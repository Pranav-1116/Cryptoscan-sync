"""§34 Live cryptographic state engine.

Per-asset live state: algorithms, certificates, libraries, protocols,
capabilities vs usage (§27), quantum status, readiness, agility, CBOM
version. Events apply deterministically; every change preserves
``previous_state`` and bumps the CBOM version.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from universal_crypto.models import CryptoEventType


class LiveCryptoState:
    """Mutable per-asset crypto state."""

    def __init__(self, asset_id: str) -> None:
        self.asset_id = asset_id
        self.algorithms: dict[str, dict[str, Any]] = {}
        self.certificates: dict[str, dict[str, Any]] = {}
        self.libraries: dict[str, dict[str, Any]] = {}
        self.protocols: dict[str, dict[str, Any]] = {}
        self.capabilities: dict[str, bool] = {}   # §27 — support
        self.usage: dict[str, bool] = {}          # §27 — exercised
        self.quantum_status: dict[str, str] = {}
        self.readiness: str = "PQC_UNKNOWN"
        self.agility: int = 50
        self.cbom_version: int = 1
        self.first_seen: datetime = datetime.now(timezone.utc)
        self.last_seen: datetime = self.first_seen
        self.last_change: str = "initial"
        self.previous_state: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "algorithms": self.algorithms,
            "certificates": self.certificates,
            "libraries": self.libraries,
            "protocols": self.protocols,
            "capabilities": self.capabilities,
            "usage": self.usage,
            "quantum_status": self.quantum_status,
            "readiness": self.readiness,
            "agility": self.agility,
            "cbom_version": self.cbom_version,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "last_change": self.last_change,
        }


class LiveCryptoStateEngine:
    """§34 state engine — applies crypto events to live state."""

    def __init__(self) -> None:
        self._states: dict[str, LiveCryptoState] = {}
        self._journal: list[dict[str, Any]] = []

    def state(self, asset_id: str) -> LiveCryptoState:
        return self._states.setdefault(asset_id, LiveCryptoState(asset_id))

    def states(self) -> list[LiveCryptoState]:
        return list(self._states.values())

    def journal(self) -> list[dict[str, Any]]:
        return list(self._journal)

    def apply_event(self, event_type: CryptoEventType, *, asset_id: str,
                    payload: dict[str, Any], observed_at: Optional[datetime] = None,
                    source: str = "live") -> dict[str, Any]:
        """Apply one event to state; returns the change summary."""
        state = self.state(asset_id)
        now = observed_at or datetime.now(timezone.utc)
        state.previous_state = state.to_dict()
        state.last_seen = now

        change = {"event_type": event_type.value, "asset_id": asset_id,
                  "changed": False, "details": []}

        if event_type in (CryptoEventType.ALGORITHM_DETECTED,
                          CryptoEventType.ALGORITHM_REMOVED):
            algorithm = str(payload.get("algorithm") or "")
            if algorithm:
                if event_type == CryptoEventType.ALGORITHM_DETECTED:
                    state.algorithms[algorithm] = {
                        "operation": payload.get("operation"),
                        "library": payload.get("library"),
                        "key_size": payload.get("key_size"),
                        "usage": bool(payload.get("usage", True)),
                    }
                    state.usage[algorithm] = bool(payload.get("usage", True))
                    change["details"].append(f"algorithm {algorithm} added")
                else:
                    state.algorithms.pop(algorithm, None)
                    change["details"].append(f"algorithm {algorithm} removed")
                change["changed"] = True

        if event_type in (CryptoEventType.CERT_NEW, CryptoEventType.CERT_RENEWED,
                          CryptoEventType.CERT_EXPIRING, CryptoEventType.CERT_REVOKED):
            cert_id = str(payload.get("certificate_id")
                          or payload.get("subject") or "cert")
            if event_type == CryptoEventType.CERT_NEW:
                state.certificates[cert_id] = {
                    "subject": payload.get("subject"),
                    "signature_algorithm": payload.get("signature_algorithm"),
                    "public_key_algorithm": payload.get("public_key_algorithm"),
                    "key_size": payload.get("key_size"),
                    "not_after": payload.get("not_after"),
                    "status": "VALID",
                }
                state.usage["certificate"] = True
                change["details"].append(f"certificate {cert_id} added")
            elif event_type == CryptoEventType.CERT_RENEWED:
                if cert_id in state.certificates:
                    state.certificates[cert_id].update({
                        "signature_algorithm": payload.get("signature_algorithm"),
                        "public_key_algorithm": payload.get("public_key_algorithm"),
                        "key_size": payload.get("key_size"),
                        "not_after": payload.get("not_after"),
                        "status": "RENEWED",
                    })
                change["details"].append(f"certificate {cert_id} renewed")
            elif event_type == CryptoEventType.CERT_EXPIRING:
                if cert_id in state.certificates:
                    state.certificates[cert_id]["status"] = "EXPIRING"
                change["details"].append(f"certificate {cert_id} expiring")
            elif event_type == CryptoEventType.CERT_REVOKED:
                if cert_id in state.certificates:
                    state.certificates[cert_id]["status"] = "REVOKED"
                change["details"].append(f"certificate {cert_id} revoked")
            change["changed"] = True

        if event_type == CryptoEventType.LIBRARY_UPGRADED:
            library = str(payload.get("library") or "")
            if library:
                state.libraries[library] = {
                    "version": payload.get("version"),
                    "pqc_support": payload.get("pqc_support", False),
                }
                change["details"].append(f"library {library} upgraded")
                change["changed"] = True

        if event_type in (CryptoEventType.TLS_POLICY_CHANGED,
                          CryptoEventType.PROTOCOL_CHANGED):
            protocol = str(payload.get("protocol") or "TLS")
            state.protocols[protocol] = {
                "min_version": payload.get("min_version"),
                "cipher_suites": payload.get("cipher_suites"),
                "pfs": payload.get("pfs"),
            }
            change["details"].append(f"{protocol} policy changed")
            change["changed"] = True

        if event_type in (CryptoEventType.KEY_ROTATED, CryptoEventType.KEY_EXPIRED):
            key_id = str(payload.get("key_id") or "key")
            state.usage.pop("key", None)
            change["details"].append(
                f"key {key_id} {'rotated' if event_type == CryptoEventType.KEY_ROTATED else 'expired'}")
            change["changed"] = True

        if event_type == CryptoEventType.CONFIG_CHANGED:
            # config re-pointed the crypto: the affected algorithm's usage
            # flag is refreshed (a config change can enable/disable a path)
            algorithm = str(payload.get("algorithm") or "")
            if algorithm and algorithm in state.algorithms:
                state.algorithms[algorithm]["usage"] = bool(
                    payload.get("usage", True))
                state.usage[algorithm] = bool(payload.get("usage", True))
                change["details"].append(
                    f"config changed for {algorithm} (usage={state.usage[algorithm]})")
            else:
                change["details"].append("config changed (no algorithm in state)")
            change["changed"] = True

        if event_type == CryptoEventType.PQC_CAPABILITY_CHANGED:
            algorithm = str(payload.get("algorithm") or "")
            supported = bool(payload.get("supported", True))
            if algorithm:
                state.capabilities[algorithm] = supported
                change["details"].append(
                    f"PQC capability {algorithm} = {supported} (support ≠ usage, §27)")
                change["changed"] = True

        if event_type == CryptoEventType.IMPLEMENTATION_CHANGED:
            implementation = str(payload.get("implementation") or "impl")
            state.libraries.setdefault(implementation, {})["implementation"] = \
                payload.get("classification")
            change["details"].append(f"implementation {implementation} changed")
            change["changed"] = True

        if event_type == CryptoEventType.UNKNOWN_CRYPTO_OPERATION:
            state.algorithms.setdefault("UNKNOWN_CRYPTO_OPERATION", {
                "location": payload.get("location"),
                "snippet": payload.get("snippet"),
            })
            change["details"].append("unknown crypto operation recorded")
            change["changed"] = True

        if change["changed"]:
            state.cbom_version += 1
            state.last_change = f"{event_type.value}:{now.isoformat()}"

        entry = {
            "event_type": event_type.value,
            "asset_id": asset_id,
            "observed_at": now.isoformat(),
            "source": source,
            "payload": payload,
            "change": change,
            "cbom_version": state.cbom_version,
        }
        self._journal.append(entry)
        return entry

    def state_at(self, asset_id: str, at: datetime) -> dict[str, Any]:
        """§16-style replay: reconstruct state at a past timestamp."""
        engine = LiveCryptoStateEngine()
        for entry in self._journal:
            observed = datetime.fromisoformat(entry["observed_at"])
            if observed > at:
                break
            if entry["asset_id"] == asset_id:
                engine.apply_event(
                    CryptoEventType(entry["event_type"]), asset_id=asset_id,
                    payload=entry["payload"],
                    observed_at=observed, source=entry["source"])
        return engine.state(asset_id).to_dict()
