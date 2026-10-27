"""Live Asset State Engine.

Every discovered asset carries a continuously-updated state:

    Current State · Previous State · First Seen · Last Seen · Last Scanned ·
    Last Deep Scan · Last Crypto Change · Scan Health · Monitoring Status

The engine snapshots each asset after every observation and classifies the
transition (crypto vs network vs both vs none) so the live loop can react
with a targeted rescan instead of a full re-discovery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

# fields that count as "crypto state" for change classification
CRYPTO_FIELDS = frozenset({
    "tls_version", "cipher_suites", "certificate_fingerprints",
    "certificate_fingerprint", "signature_algorithm", "public_key_algorithm",
    "public_key_size", "key_size", "algorithms", "crypto", "pqc_status",
    "tunnel_encryption", "ike_version", "ike_encryption", "ike_dh_group",
    "vpn_profiles", "crypto_profiles", "cipher", "tls", "weak_ciphers",
})

# fields that count as "network state"
NETWORK_FIELDS = frozenset({
    "ip_addresses", "ip", "mac", "hostname", "fqdn", "device_type", "os",
    "os_version", "model", "interfaces", "neighbors", "routes", "vlans",
    "connected_to", "topology", "segment", "network_zone", "location",
})

TRANSITION_KINDS = ("NO_CHANGE", "NETWORK_CHANGED", "CRYPTO_CHANGED",
                    "BOTH_CHANGED", "FIRST_SEEN", "REMOVED")


def _crypto_subset(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {k: snapshot[k] for k in CRYPTO_FIELDS if k in snapshot}


def _network_subset(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {k: snapshot[k] for k in NETWORK_FIELDS if k in snapshot}


def _digest(data: dict[str, Any]) -> str:
    import json
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


@dataclass
class AssetState:
    asset_id: str
    current: dict[str, Any] = field(default_factory=dict)
    previous: dict[str, Any] = field(default_factory=dict)
    first_seen: Any = None
    last_seen: Any = None
    last_scanned: Any = None
    last_deep_scan: Any = None
    last_crypto_change: Any = None
    scan_health: str = "HEALTHY"
    monitoring_status: str = "ACTIVE"

    def to_dict(self) -> dict[str, Any]:
        def iso(value: Any) -> Any:
            return value.isoformat() if hasattr(value, "isoformat") else value

        return {
            "asset_id": self.asset_id,
            "current": dict(self.current),
            "previous": dict(self.previous),
            "first_seen": iso(self.first_seen),
            "last_seen": iso(self.last_seen),
            "last_scanned": iso(self.last_scanned),
            "last_deep_scan": iso(self.last_deep_scan),
            "last_crypto_change": iso(self.last_crypto_change),
            "scan_health": self.scan_health,
            "monitoring_status": self.monitoring_status,
            "crypto_digest": _digest(_crypto_subset(self.current)),
            "network_digest": _digest(_network_subset(self.current)),
        }


@dataclass
class StateTransition:
    asset_id: str
    kind: str
    changed_fields: list[str] = field(default_factory=list)
    crypto_changed: bool = False
    network_changed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"asset_id": self.asset_id, "kind": self.kind,
                "changed_fields": list(self.changed_fields),
                "crypto_changed": self.crypto_changed,
                "network_changed": self.network_changed}


class AssetStateEngine:
    """Tracks per-asset state and classifies every observation."""

    def __init__(self, *, clock: Callable[[], Any] | None = None) -> None:
        self._states: dict[str, AssetState] = {}
        self._transitions: list[StateTransition] = []
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------- queries

    def get(self, asset_id: str) -> AssetState | None:
        return self._states.get(asset_id)

    def all(self) -> list[AssetState]:
        return list(self._states.values())

    def to_dicts(self) -> list[dict[str, Any]]:
        return [state.to_dict() for state in self.all()]

    def transitions(self) -> list[StateTransition]:
        return list(self._transitions)

    def count(self) -> int:
        return len(self._states)

    # ------------------------------------------------------------- observe

    def observe(self, asset_id: str, snapshot: dict[str, Any], *,
                deep: bool = False,
                now: Any | None = None) -> StateTransition:
        now = now if now is not None else self._clock()
        previous_state = self._states.get(asset_id)
        transition = self._classify(asset_id, previous_state.current if previous_state else {},
                                    snapshot)
        if previous_state is None:
            first_seen = now
            previous = {}
            monitoring = "ACTIVE"
        else:
            first_seen = previous_state.first_seen
            previous = dict(previous_state.current)
            monitoring = previous_state.monitoring_status

        state = AssetState(
            asset_id=asset_id,
            current=dict(snapshot),
            previous=previous,
            first_seen=first_seen,
            last_seen=now,
            last_scanned=now,
            last_deep_scan=now if deep else (previous_state.last_deep_scan if previous_state else None),
            last_crypto_change=(now if transition.crypto_changed
                                else (previous_state.last_crypto_change if previous_state else None)),
            scan_health=previous_state.scan_health if previous_state else "HEALTHY",
            monitoring_status=monitoring,
        )
        self._states[asset_id] = state
        self._transitions.append(transition)
        return transition

    def remove(self, asset_id: str, *, now: Any | None = None) -> StateTransition | None:
        if asset_id not in self._states:
            return None
        transition = StateTransition(asset_id=asset_id, kind="REMOVED")
        del self._states[asset_id]
        self._transitions.append(transition)
        return transition

    # ------------------------------------------------------------- health

    def mark_health(self, asset_id: str, health: str) -> None:
        state = self._states.get(asset_id)
        if state is not None:
            state.scan_health = health

    def mark_paused(self, asset_id: str, paused: bool = True) -> None:
        state = self._states.get(asset_id)
        if state is not None:
            state.monitoring_status = "PAUSED" if paused else "ACTIVE"

    # ------------------------------------------------------------- classify

    @staticmethod
    def _classify(asset_id: str, previous: dict[str, Any],
                  current: dict[str, Any]) -> StateTransition:
        if not previous:
            return StateTransition(asset_id=asset_id, kind="FIRST_SEEN",
                                   crypto_changed=False, network_changed=False,
                                   changed_fields=sorted(current.keys()))
        changed = [k for k in current if current.get(k) != previous.get(k)]
        crypto_changed = any(k in CRYPTO_FIELDS for k in changed)
        network_changed = any(k in NETWORK_FIELDS for k in changed)
        if not changed:
            kind = "NO_CHANGE"
        elif crypto_changed and network_changed:
            kind = "BOTH_CHANGED"
        elif crypto_changed:
            kind = "CRYPTO_CHANGED"
        else:
            kind = "NETWORK_CHANGED"
        return StateTransition(asset_id=asset_id, kind=kind,
                               changed_fields=changed,
                               crypto_changed=crypto_changed,
                               network_changed=network_changed)

    def recent(self, *, since_kind: str | None = None, limit: int = 50) -> list[StateTransition]:
        out = self._transitions
        if since_kind:
            out = [t for t in out if t.kind == since_kind]
        return out[-limit:]

    def crypto_changed_since(self, asset_id: str, since: Any) -> bool:
        state = self._states.get(asset_id)
        if state is None or state.last_crypto_change is None:
            return False
        try:
            return state.last_crypto_change >= since
        except TypeError:
            return True
