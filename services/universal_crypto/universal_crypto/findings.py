"""§29 Explainable findings.

Every finding says WHAT / WHERE / HOW DETECTED / WHY CLASSIFIED / EVIDENCE /
CONFIDENCE / IMPACT / RECOMMENDATION. Example:

    Finding: RSA-2048 Signature
    Location: authentication-service
    Evidence: JCA Signature API + Bouncy Castle dependency + runtime cert
    Confidence: 98%
    Quantum Status: VULNERABLE
    Affected Assets: 43
    Recommended Action: Evaluate migration to approved PQC/hybrid signature
"""

from __future__ import annotations

import uuid
from typing import Any, Iterable, Optional

from universal_crypto.models import (
    CryptoFinding,
    CryptoObservation,
    Evidence,
    MigrationPriority,
    QuantumStatus,
)

#: deterministic recommendation catalog (algorithm family → action)
_RECOMMENDATIONS: dict[str, str] = {
    "RSA": "Evaluate migration to an approved PQC/hybrid signature or KEM "
           "architecture (ML-DSA-65 / SLH-DSA-128S / ML-KEM-768 with hybrid "
           "mode during transition).",
    "RSA-PSS": "Replace signatures with ML-DSA-65 or SLH-DSA-128S (hybrid "
               "ECDSA+ML-DSA during transition).",
    "RSA-OAEP": "Migrate key encapsulation to ML-KEM-768 (hybrid RSA-OAEP+ML-KEM "
                "during transition).",
    "ECDSA": "Evaluate ML-DSA-65 or SLH-DSA-128S for quantum-resistant signatures.",
    "ECDH": "Migrate key agreement to ML-KEM-768 or X25519+ML-KEM hybrid.",
    "Ed25519": "Evaluate ML-DSA-65 with hybrid mode during transition.",
    "DH": "Replace Diffie-Hellman with ML-KEM-768 or at minimum X25519.",
    "DSA": "Replace DSA with ECDSA now and ML-DSA-65 for the quantum horizon.",
    "X25519": "Adopt X25519+ML-KEM-768 hybrid key agreement.",
    "SHA-1": "Replace SHA-1 with SHA-256 or SHA-384; remove SHA-1 trust anchors.",
    "MD5": "Replace MD5 with SHA-256; MD5 is collision-broken.",
    "3DES": "Replace 3DES with AES-GCM (SP 800-131A disallows 3TDEA after 2023).",
    "DES": "Replace DES with AES-256-GCM.",
    "RC4": "Remove RC4 entirely (RFC 7465 prohibits it in TLS).",
    "AES-CBC": "Move to AES-GCM where policy permits; CBC is allowed only with "
               "MAC-then-encrypt mitigations.",
    "ML-KEM-768": "Already quantum-safe (FIPS 203); verify hybrid mode policy.",
    "ML-DSA-65": "Already quantum-safe (FIPS 204); verify hybrid mode policy.",
    "SLH-DSA-128S": "Already quantum-safe (FIPS 205); verify hybrid mode policy.",
    "HQC-192": "Quantum-safe; selected for NIST standardization (2025).",
}

_SEVERITY = {
    MigrationPriority.HIGH: "high",
    MigrationPriority.MEDIUM: "medium",
    MigrationPriority.LOW: "low",
}


class FindingBuilder:
    """§29 builds explainable findings from observations."""

    def __init__(self) -> None:
        pass

    def build(
        self,
        observation: CryptoObservation,
        *,
        affected_assets: int = 1,
        quantum_classification: Optional[dict[str, Any]] = None,
        extra_evidence: Optional[Iterable[Evidence]] = None,
    ) -> CryptoFinding:
        evidence = list(observation.evidence)
        if extra_evidence:
            evidence.extend(extra_evidence)
        confidence = observation.confidence
        quantum = observation.quantum_status
        priority = None
        if quantum_classification:
            quantum = QuantumStatus(quantum_classification["quantum_status"])
            priority = MigrationPriority(quantum_classification["migration_priority"])
        severity = _SEVERITY.get(priority, "info")
        impact = self._impact(observation, quantum, affected_assets)
        recommendation = _RECOMMENDATIONS.get(
            self._base_algorithm(observation.algorithm),
            "Review the algorithm against policy and the PQC roadmap.")
        how = "; ".join(f"{e.kind.value}: {e.detail}" for e in evidence[:6]) or "no evidence"
        why = (f"classified as {observation.classification.value} "
               f"(operation={observation.operation.value if observation.operation else 'n/a'}, "
               f"library={observation.library or 'n/a'})")
        return CryptoFinding(
            finding_id=uuid.uuid4().hex[:16],
            what=f"{observation.algorithm} "
                 f"{observation.operation.value if observation.operation else ''}".strip()
                 + (f" ({observation.key_size}-bit)" if observation.key_size else ""),
            where=observation.location or observation.asset_id,
            how_detected=how,
            why_classified=why,
            evidence=evidence,
            confidence=confidence,
            band=observation.band,
            impact=impact,
            recommendation=recommendation,
            classification=observation.classification,
            algorithm=observation.algorithm,
            operation=observation.operation.value if observation.operation else None,
            asset_id=observation.asset_id,
            quantum_status=quantum,
            migration_priority=priority,
            severity=severity,
            source=observation.source,
        )

    @staticmethod
    def _base_algorithm(algorithm: str) -> str:
        """'RSA-2048' -> 'RSA'; 'RSA-PSS' stays 'RSA-PSS'."""
        for suffix in ("-2048", "-3072", "-4096", "-1024", "-768", "-256",
                       "-512", "-192", "-128", "-384", "-521"):
            if algorithm.endswith(suffix) and algorithm[: -len(suffix)] in _RECOMMENDATIONS:
                return algorithm[: -len(suffix)]
        return algorithm

    def _impact(self, observation: CryptoObservation, quantum: QuantumStatus,
                affected_assets: int) -> str:
        parts = [f"{affected_assets} asset(s) affected"]
        if quantum == QuantumStatus.QUANTUM_VULNERABLE:
            parts.append("vulnerable to a cryptographically relevant quantum computer")
        if observation.usage:
            parts.append("capability is exercised at runtime")
        return "; ".join(parts)

    def build_many(
        self,
        observations: Iterable[CryptoObservation],
        *,
        quantum_classifications: Optional[dict[str, dict[str, Any]]] = None,
    ) -> list[CryptoFinding]:
        out = []
        for obs in observations:
            qc = None
            if quantum_classifications:
                qc = quantum_classifications.get(obs.algorithm)
            out.append(self.build(obs, quantum_classification=qc))
        return out
