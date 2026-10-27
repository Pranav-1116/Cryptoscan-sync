"""§17/§18 Crypto classification + quantum vulnerability classification.

§17: every finding carries exactly one of
ALGORITHM / PRIMITIVE / PROTOCOL / IMPLEMENTATION / KEY / CERTIFICATE /
CRYPTO_LIBRARY / CRYPTO_PROVIDER / HARDWARE_CAPABILITY / CONFIGURATION.

§18: quantum classification is not "RSA = BAD". An RSA-2048 asset gets:
classical status (accepted/policy-dependent), quantum status (vulnerable to
a cryptographically relevant quantum computer, NIST IR 8547), usage,
dependency count and migration priority.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from universal_crypto.models import (
    Classification,
    CryptoObservation,
    MigrationPriority,
    QuantumStatus,
)
from universal_crypto.registry import quantum_status as _registry_quantum


class CryptoClassifier:
    """§17 classification rules (deterministic catalog)."""

    def classify_observation(self, obs: CryptoObservation) -> Classification:
        """Classify by evidence shape — never by name alone."""
        kinds = obs.evidence_kinds()
        if obs.protocol:
            return Classification.PROTOCOL
        if obs.library and any(k.value in ("LIBRARY", "DEPENDENCY", "BINARY")
                               for k in kinds):
            return Classification.CRYPTO_LIBRARY
        if obs.provider:
            return Classification.CRYPTO_PROVIDER
        if obs.capability and not obs.usage:
            return Classification.HARDWARE_CAPABILITY
        if obs.operation in ("key_generation", "key_exchange", "key_storage"):
            return Classification.KEY
        if any(k.value == "CERTIFICATE" for k in kinds):
            return Classification.CERTIFICATE
        if any(k.value == "CONFIG" for k in kinds):
            return Classification.CONFIGURATION
        if obs.operation is not None:
            return Classification.PRIMITIVE
        return Classification.ALGORITHM

    def classify_algorithm(self, algorithm: str) -> Classification:
        return Classification.ALGORITHM

    def classify_entity(self, *, kind: str) -> Classification:
        return {
            "algorithm": Classification.ALGORITHM,
            "primitive": Classification.PRIMITIVE,
            "protocol": Classification.PROTOCOL,
            "implementation": Classification.IMPLEMENTATION,
            "key": Classification.KEY,
            "certificate": Classification.CERTIFICATE,
            "crypto_library": Classification.CRYPTO_LIBRARY,
            "crypto_provider": Classification.CRYPTO_PROVIDER,
            "hardware_capability": Classification.HARDWARE_CAPABILITY,
            "configuration": Classification.CONFIGURATION,
        }.get(kind, Classification.ALGORITHM)


class QuantumVulnerabilityClassifier:
    """§18 quantum classification of a crypto asset."""

    #: migration priority by (quantum status, usage, dependency count)
    _PRIORITY = {
        (QuantumStatus.QUANTUM_VULNERABLE, True): MigrationPriority.HIGH,
        (QuantumStatus.QUANTUM_VULNERABLE, False): MigrationPriority.MEDIUM,
    }

    def classify(
        self,
        *,
        algorithm: str,
        usage: bool = True,
        dependency_count: int = 0,
        key_size: Optional[int] = None,
        policy_allows: bool = True,
    ) -> dict[str, Any]:
        """§18 structured classification — never a blanket 'RSA = BAD'."""
        quantum = _registry_quantum(algorithm)
        # note: PQC_UNKNOWN is deliberately preserved — an algorithm not in
        # the registry is never labeled safe or vulnerable (§24 honesty rule)
        classical_status = "accepted" if policy_allows else "restricted_by_policy"
        priority = self._PRIORITY.get((quantum, usage), MigrationPriority.LOW)
        if priority == MigrationPriority.MEDIUM and dependency_count >= 50:
            priority = MigrationPriority.HIGH
        return {
            "algorithm": algorithm,
            "classical_status": classical_status,
            "quantum_status": quantum.value,
            "usage": usage,
            "dependency_count": dependency_count,
            "migration_priority": priority.value,
            "rationale": self._rationale(algorithm, quantum, key_size),
        }

    def _rationale(self, algorithm: str, quantum: QuantumStatus,
                   key_size: Optional[int]) -> str:
        if quantum == QuantumStatus.QUANTUM_VULNERABLE:
            return (f"{algorithm} is in the public-key families NIST IR 8547 "
                    "identifies as threatened by future cryptographically "
                    "relevant quantum computers")
        if quantum == QuantumStatus.QUANTUM_SAFE:
            return f"{algorithm} is quantum-safe (Grover only halves security)"
        if quantum == QuantumStatus.PQC_UNKNOWN:
            return (f"{algorithm} is not in the registry — cannot classify; "
                    "never labeled safe or vulnerable without evidence")
        return ""

    def classify_many(
        self,
        observations: Iterable[CryptoObservation],
    ) -> list[dict[str, Any]]:
        return [self.classify(algorithm=obs.algorithm, usage=obs.usage)
                for obs in observations]
