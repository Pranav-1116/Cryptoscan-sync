"""ZELNX Live Cloud Intelligence Engine — continuous PQC readiness
monitoring (§17).

Every cryptographic change triggers a PQC evaluation:

    CRYPTO EVENT → ALGORITHM DETECTED → PQC STATUS ANALYSIS →
    DEPENDENCY ANALYSIS → COMPATIBILITY ANALYSIS → UPDATE MIGRATION PRIORITY

Example: a new RSA certificate on a public internet-facing banking
application (high criticality) gets a higher migration priority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_scanner.enterprise.live.event_schema import CloudEvent

CRYPTO_EVENT_TYPES = (
    "KEY_ROTATED", "KEY_ENABLED", "KEY_DISABLED", "KEY_ALGORITHM_CHANGED",
    "KEY_PROTECTION_LEVEL_CHANGED", "CERTIFICATE_CREATED", "CERTIFICATE_RENEWED",
    "CERTIFICATE_REPLACED", "CERTIFICATE_ALGORITHM_CHANGED", "TLS_CHANGED",
    "K8S_MTLS_CHANGED", "K8S_CRYPTO_DEPENDENCY_CHANGED",
    "SERVERLESS_DEPENDENCY_CHANGE", "SERVERLESS_KEY_REF_CHANGE",
    "SERVERLESS_CERT_REF_CHANGE", "KEY_CHANGED", "CERTIFICATE_CHANGED",
)

PQC_READY_ALGORITHMS = ("ML-KEM", "ML-DSA", "SLH-DSA", "Falcon", "SPHINCS+",
                        "X25519MLKEM768", "MLKEM768", "Kyber", "Dilithium")

VULNERABLE_ALGORITHMS = ("RSA", "ECDSA", "ED25519", "AES", "SHA-256", "SHA2",
                         "P-256", "P-384", "X25519", "CHACHA20", "HMAC")


def is_crypto_event(event_type: str) -> bool:
    return str(event_type or "") in CRYPTO_EVENT_TYPES


@dataclass
class PQCLiveEvaluation:
    """Result of a PQC evaluation triggered by one crypto event."""

    event_id: str
    resource_id: str
    event_type: str = ""
    algorithm: str = ""
    pqc_status: str = "NOT_READY"  # PQC_READY | PARTIALLY_READY | NOT_READY | UNKNOWN
    migration_priority: str = "LOW"  # LOW | MEDIUM | HIGH | CRITICAL
    public_internet_exposed: bool = False
    criticality: str = "STANDARD"
    dependencies: list[str] = field(default_factory=list)
    compatibility: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "resource_id": self.resource_id,
            "event_type": self.event_type,
            "algorithm": self.algorithm,
            "pqc_status": self.pqc_status,
            "migration_priority": self.migration_priority,
            "public_internet_exposed": self.public_internet_exposed,
            "criticality": self.criticality,
            "dependencies": list(self.dependencies),
            "compatibility": list(self.compatibility),
            "reason": self.reason,
        }


def pqc_status_for_algorithm(algorithm: str) -> str:
    algo = str(algorithm or "")
    if not algo:
        return "UNKNOWN"
    if any(name in algo.upper() for name in
           ("ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "FALCON", "SPHINCS")):
        return "PQC_READY"
    return "NOT_READY"


def pqc_priority(*, algorithm: str, internet_exposed: bool, criticality: str,
                 pqc_status: str) -> str:
    """Migration priority: RSA + public internet + banking = HIGH/CRITICAL."""
    if pqc_status == "PQC_READY":
        return "LOW"
    vulnerable = any(name in str(algorithm).upper() for name in
                     ("RSA", "ECDSA", "ED25519", "DSA", "DH", "ECIES"))
    score = 0
    if vulnerable:
        score += 1
    if internet_exposed:
        score += 2
    if criticality in ("HIGH", "CRITICAL"):
        score += 2
    elif criticality == "MEDIUM":
        score += 1
    if score >= 4:
        return "CRITICAL"
    if score == 3:
        return "HIGH"
    if score == 2:
        return "MEDIUM"
    return "LOW"


class ContinuousPQCReadinessMonitor:
    """Evaluate PQC readiness for every crypto event.

    ``detect_algorithm(resource_id)`` and ``dependencies(resource_id)``
    are injectable; defaults come from ``provider_metadata``.
    """

    def __init__(self, *, detect_algorithm=None, find_dependencies=None) -> None:
        self._detect = detect_algorithm or (lambda event: None)
        self._deps = find_dependencies or (lambda resource_id: [])
        self._evaluations: list[PQCLiveEvaluation] = []

    def watch(self, event: CloudEvent, *, internet_exposed: bool | None = None,
              criticality: str = "") -> PQCLiveEvaluation | None:
        if not is_crypto_event(event.event_type):
            return None
        algorithm = str(self._detect(event) or
                        event.provider_metadata.get("algorithm") or "") or "UNKNOWN"
        exposed = (internet_exposed if internet_exposed is not None
                   else bool(event.provider_metadata.get("public_internet_exposed")))
        criticality = criticality or str(event.provider_metadata.get("criticality") or "STANDARD")
        status = pqc_status_for_algorithm(algorithm)
        priority = pqc_priority(algorithm=algorithm, internet_exposed=exposed,
                                criticality=criticality, pqc_status=status)
        evaluation = PQCLiveEvaluation(
            event_id=event.event_id,
            resource_id=event.resource_id,
            event_type=event.event_type,
            algorithm=algorithm,
            pqc_status=status,
            migration_priority=priority,
            public_internet_exposed=exposed,
            criticality=criticality,
            dependencies=[str(d) for d in (self._deps(event.resource_id) or [])],
            compatibility=self._compatibility(status, algorithm),
            reason=f"{algorithm} → {status}, internet_exposed={exposed}, "
                   f"criticality={criticality} → {priority}",
        )
        self._evaluations.append(evaluation)
        return evaluation

    def evaluations(self) -> list[PQCLiveEvaluation]:
        return list(self._evaluations)

    def latest(self) -> PQCLiveEvaluation | None:
        return self._evaluations[-1] if self._evaluations else None

    def summary(self) -> dict[str, Any]:
        return {
            "evaluations": len(self._evaluations),
            "by_status": {
                status: sum(1 for e in self._evaluations if e.pqc_status == status)
                for status in ("PQC_READY", "PARTIALLY_READY", "NOT_READY", "UNKNOWN")
            },
            "by_priority": {
                priority: sum(1 for e in self._evaluations
                              if e.migration_priority == priority)
                for priority in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            },
        }

    @staticmethod
    def _compatibility(status: str, algorithm: str) -> list[str]:
        if status == "PQC_READY":
            return ["post-quantum-compatible"]
        algo = str(algorithm).upper()
        checks = []
        if any(name in algo for name in ("RSA", "ECDSA", "ED25519")):
            checks.append("needs-pqc-signature-migration")
        if "AES" in algo or "CHACHA" in algo:
            checks.append("symmetric-safe-with-hybrid")
        if "SHA-256" in algo or "SHA2" in algo:
            checks.append("hash-ok")
        return checks or ["unknown-compatibility"]
