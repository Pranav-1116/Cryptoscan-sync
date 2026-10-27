"""§34 Live cryptography scanner — event bus → state → targeted analysis →
CBOM → PQC risk recalculation.

Example (certificate renewed):
    new certificate detected → signature algorithm changed →
    crypto graph updated → PQC status recalculated → risk updated.
"""

from __future__ import annotations

from typing import Any

from universal_crypto.agility import CryptoAgilityEngine
from universal_crypto.live.cbom import LiveCbomProducer
from universal_crypto.live.events import CryptoEvent
from universal_crypto.live.state import LiveCryptoState, LiveCryptoStateEngine
from universal_crypto.models import CryptoEventType, QuantumStatus
from universal_crypto.pqc_readiness import PqcReadinessEngine
from universal_crypto.registry import find as registry_find


class LiveCryptoEngine:
    """§34/§35 live crypto engine: events in, state + live CBOM + PQC risk out."""

    def __init__(self) -> None:
        self.state_engine = LiveCryptoStateEngine()
        self.cbom_producer = LiveCbomProducer()
        self.pqc = PqcReadinessEngine()
        self.agility = CryptoAgilityEngine()
        self._risks: dict[str, int] = {}

    def ingest(self, event: CryptoEvent) -> dict[str, Any]:
        """Event → state → targeted analysis → CBOM → PQC risk recalculation."""
        entry = self.state_engine.apply_event(
            event.event_type, asset_id=event.asset_id,
            payload=event.payload, observed_at=event.observed_at,
            source=event.source)
        state = self.state_engine.state(event.asset_id)

        # ── targeted crypto analysis + recalculation ─────────────────────
        if event.event_type == CryptoEventType.CERT_RENEWED:
            # certificate renewed → signature algorithm changed →
            # crypto graph updated → PQC status recalculated → risk updated
            self._recalculate_certificate(state, event.payload)
        elif event.event_type in (CryptoEventType.CERT_NEW,
                                  CryptoEventType.CERT_EXPIRING,
                                  CryptoEventType.CERT_REVOKED):
            self._recalculate_certificate(state, event.payload)
        elif event.event_type == CryptoEventType.LIBRARY_UPGRADED:
            self._recalculate_library(state, event.payload)
        elif event.event_type == CryptoEventType.PQC_CAPABILITY_CHANGED:
            self._recalculate_pqc_capability(state, event.payload)
        elif event.event_type == CryptoEventType.ALGORITHM_DETECTED:
            self._recalculate_algorithm(state, event.payload)
        elif event.event_type == CryptoEventType.ALGORITHM_REMOVED:
            self._recalculate_algorithm_removed(state, event.payload)
        elif event.event_type in (CryptoEventType.KEY_ROTATED,
                                  CryptoEventType.KEY_EXPIRED):
            self._recalculate_key(state, event.payload)
        elif event.event_type == CryptoEventType.CONFIG_CHANGED:
            self._recalculate_config(state, event.payload)
        elif event.event_type == CryptoEventType.IMPLEMENTATION_CHANGED:
            self._recalculate_implementation(state, event.payload)
        elif event.event_type in (CryptoEventType.TLS_POLICY_CHANGED,
                                  CryptoEventType.PROTOCOL_CHANGED):
            self._recalculate_protocol(state, event.payload)

        state.readiness = self._overall_readiness(state)
        state.agility = self._agility_score(state)
        risk = self._compute_risk(state)
        self._risks[event.asset_id] = risk

        # ── live CBOM (always current after the event) ───────────────────
        cbom = self.cbom_producer.produce(state)

        return {
            "event": entry,
            "risk": {"asset_id": event.asset_id, "score": risk,
                     "level": _risk_level(risk)},
            "cbom_version": state.cbom_version,
            "readiness": state.readiness,
            "agility": state.agility,
            "cbom": cbom,
        }

    def cbom(self, asset_id: str) -> dict[str, Any]:
        return self.cbom_producer.produce(self.state_engine.state(asset_id))

    def state(self, asset_id: str) -> LiveCryptoState:
        return self.state_engine.state(asset_id)

    def risk(self, asset_id: str) -> dict[str, Any]:
        score = self._risks.get(asset_id, 0)
        return {"asset_id": asset_id, "score": score, "level": _risk_level(score)}

    def risk_summary(self) -> dict[str, Any]:
        return {asset: {"score": score, "level": _risk_level(score)}
                for asset, score in self._risks.items()}

    # -- targeted recalculation (deterministic) --------------------------- #

    def _recalculate_certificate(self, state: LiveCryptoState,
                                 payload: dict[str, Any]) -> None:
        sig = str(payload.get("signature_algorithm") or "")
        if not sig:
            return
        previous = str(payload.get("previous_signature_algorithm") or "")
        if previous and previous in state.quantum_status:
            state.quantum_status.pop(previous, None)  # retired by the renewal
        status = registry_find(sig).quantum_status if registry_find(sig) else QuantumStatus.PQC_UNKNOWN
        state.quantum_status[sig] = status.value
        state.quantum_status["certificate"] = status.value

    def _recalculate_library(self, state: LiveCryptoState,
                             payload: dict[str, Any]) -> None:
        library = str(payload.get("library") or "")
        pqc_support = bool(payload.get("pqc_support", False))
        if library and pqc_support:
            for algorithm in state.algorithms:
                if registry_find(algorithm) and registry_find(algorithm).nist_lifecycle.value in (
                        "STANDARDIZED", "SELECTED_FOR_STANDARDIZATION"):
                    state.quantum_status[algorithm] = "PQC_READY"

    def _recalculate_pqc_capability(self, state: LiveCryptoState,
                                    payload: dict[str, Any]) -> None:
        algorithm = str(payload.get("algorithm") or "")
        if not algorithm:
            return
        if bool(payload.get("supported", True)):
            state.quantum_status[algorithm] = "PQC_READY"
        else:
            state.quantum_status[algorithm] = "PQC_UNKNOWN"

    def _recalculate_algorithm(self, state: LiveCryptoState,
                               payload: dict[str, Any]) -> None:
        algorithm = str(payload.get("algorithm") or "")
        if not algorithm:
            return
        entry = registry_find(algorithm)
        if entry is None:
            state.quantum_status[algorithm] = QuantumStatus.PQC_UNKNOWN.value
            return
        state.quantum_status[algorithm] = entry.quantum_status.value
        if entry.quantum_status == QuantumStatus.QUANTUM_VULNERABLE:
            readiness = self.pqc.migration_readiness(
                algorithm=algorithm, protocol=str(state.protocols.keys() or ""),
                usage=bool(payload.get("usage", True)))
            state.readiness = readiness["current_status"]

    def _recalculate_algorithm_removed(self, state: LiveCryptoState,
                                       payload: dict[str, Any]) -> None:
        """An algorithm left the asset: retire its quantum status and usage."""
        algorithm = str(payload.get("algorithm") or "")
        if not algorithm:
            return
        state.quantum_status.pop(algorithm, None)
        state.usage.pop(algorithm, None)
        state.algorithms.pop(algorithm, None)

    def _recalculate_key(self, state: LiveCryptoState,
                         payload: dict[str, Any]) -> None:
        """Key rotated/expired → the key usage slot is refreshed; an expired
        key no longer counts as exercised crypto usage."""
        algorithm = str(payload.get("algorithm") or "")
        if algorithm:
            state.usage[algorithm] = bool(payload.get("usage", False))
        state.usage.pop("key", None)

    def _recalculate_config(self, state: LiveCryptoState,
                            payload: dict[str, Any]) -> None:
        """Config change re-pointed crypto: refresh the affected algorithm's
        quantum status from the registry and its usage flag."""
        algorithm = str(payload.get("algorithm") or "")
        if not algorithm:
            return
        if algorithm not in state.algorithms:
            return
        entry = registry_find(algorithm)
        state.quantum_status[algorithm] = (
            entry.quantum_status.value if entry else QuantumStatus.PQC_UNKNOWN.value)
        state.usage[algorithm] = bool(payload.get("usage", True))

    def _recalculate_implementation(self, state: LiveCryptoState,
                                    payload: dict[str, Any]) -> None:
        """Implementation change (e.g. custom crypto replaced by a known
        library): re-classify the affected algorithms from the registry."""
        implementation = str(payload.get("implementation") or "")
        classification = str(payload.get("classification") or "")
        if not classification:
            return
        for algorithm in state.algorithms:
            entry = registry_find(algorithm)
            if entry is None:
                state.quantum_status[algorithm] = QuantumStatus.PQC_UNKNOWN.value
                continue
            state.quantum_status[algorithm] = entry.quantum_status.value
        if implementation:
            state.libraries[implementation] = {
                **state.libraries.get(implementation, {}),
                "implementation": classification,
            }

    def _recalculate_protocol(self, state: LiveCryptoState,
                              payload: dict[str, Any]) -> None:
        # TLS/SSH/IPsec are transport: their quantum posture is decided by
        # the algorithms they carry (ECDHE, cert signatures, KEMs), which
        # are observed separately — never mark the protocol itself
        # vulnerable in the asset's readiness aggregate.
        return

    # -- aggregation ------------------------------------------------------ #

    def _overall_readiness(self, state: LiveCryptoState) -> str:
        statuses = set(state.quantum_status.values())
        if not statuses:
            return "PQC_UNKNOWN"
        if "QUANTUM_VULNERABLE" in statuses:
            return "QUANTUM_VULNERABLE"
        if statuses <= {"QUANTUM_SAFE", "PQC_READY"}:
            return "PQC_READY"
        return "PQC_UNKNOWN"

    def _agility_score(self, state: LiveCryptoState) -> int:
        signals = ["configurable_provider", "configurable_tls_config"]
        if state.protocols:
            signals.append("configurable_algorithm")
        if any(l.get("pqc_support") for l in state.libraries.values()):
            signals.append("multiple_providers")
        if state.capabilities:
            signals.append("runtime_selection")
        return self.agility.score(signals)["score"]

    def _compute_risk(self, state: LiveCryptoState) -> int:
        """0–100 deterministic risk: quantum-vulnerable usage + readiness."""
        risk = 0
        vulnerable_used = [
            a for a, s in state.quantum_status.items()
            if s == "QUANTUM_VULNERABLE" and state.usage.get(a, False)]
        vulnerable_any = [
            a for a, s in state.quantum_status.items()
            if s == "QUANTUM_VULNERABLE"]
        if vulnerable_used:
            risk += 40
        elif vulnerable_any:
            risk += 20
        if state.readiness == "QUANTUM_VULNERABLE":
            risk += 30
        if state.readiness == "PQC_UNKNOWN":
            risk += 10
        expired = [c for c in state.certificates.values()
                   if c.get("status") in ("EXPIRING", "REVOKED")]
        risk += 10 * len(expired)
        if "UNKNOWN_CRYPTO_OPERATION" in state.algorithms:
            risk += 10
        return min(100, risk)


def _risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"
