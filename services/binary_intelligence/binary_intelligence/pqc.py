"""PQC intelligence from compiled binaries (§9).

Three things, reported separately: quantum-vulnerable indicators, PQC
implementation indicators, and migration blockers. The scanner never
classifies every classical algorithm as an immediate vulnerability, and
the presence of a PQC implementation never proves the application uses
it. Migration readiness is 'Not established' unless evidence establishes
it — never optimistic, never invented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from binary_intelligence.evidence import CryptoFinding

_QUANTUM_VULNERABLE_FAMILIES = {"RSA", "DH", "ECDH", "ECDSA", "EdDSA",
                                "Ed25519", "X25519", "DSA"}
_PQC_FAMILIES = {"ML-KEM", "ML-DSA", "SLH-DSA"}


@dataclass
class PQCAssessment:
    quantum_vulnerable_indicators: str = "Not detected"
    quantum_vulnerable_algorithms: List[str] = field(default_factory=list)
    pqc_implementation_indicators: str = "Not detected"
    pqc_algorithms: List[str] = field(default_factory=list)
    migration_blockers: List[str] = field(default_factory=list)
    library_identified: str = "Not identified"
    static_linking: str = "Not established — evidence-dependent"
    source_availability: str = "Requires confirmation"
    vendor_replacement_dependency: str = "Requires confirmation"
    migration_readiness: str = "Not established"
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "quantum_vulnerable_algorithm_indicators":
                self.quantum_vulnerable_indicators,
            "quantum_vulnerable_algorithms": sorted(self.quantum_vulnerable_algorithms),
            "pqc_implementation_indicators": self.pqc_implementation_indicators,
            "pqc_algorithms": sorted(self.pqc_algorithms),
            "migration_blockers": self.migration_blockers,
            "cryptographic_library": self.library_identified,
            "static_linking": self.static_linking,
            "source_availability": self.source_availability,
            "vendor_replacement_dependency": self.vendor_replacement_dependency,
            "migration_readiness": self.migration_readiness,
            "limitations": self.limitations,
            "note": "presence is not usage — a PQC implementation may be "
                    "unused library functionality, and a classical "
                    "algorithm is not automatically an immediate "
                    "vulnerability (§9)",
        }


def assess_pqc(findings: List[CryptoFinding], *,
               libraries: Optional[List[str]] = None,
               stripped: bool = False,
               proprietary_suspected: bool = False,
               static_linking_suspected: bool = False
               ) -> PQCAssessment:
    assessment = PQCAssessment()
    libraries = libraries or []
    assessment.library_identified = ", ".join(sorted(set(libraries))) \
        if libraries else "Not identified"

    for finding in findings:
        family = finding.algorithm
        if family in _QUANTUM_VULNERABLE_FAMILIES or finding.quantum_vulnerable:
            assessment.quantum_vulnerable_indicators = "Detected"
            if family:
                assessment.quantum_vulnerable_algorithms.append(family)
        if family in _PQC_FAMILIES or finding.pqc_family:
            assessment.pqc_implementation_indicators = "Detected"
            if family:
                assessment.pqc_algorithms.append(family)

    # de-duplicate while preserving honesty
    assessment.quantum_vulnerable_algorithms = sorted(
        set(assessment.quantum_vulnerable_algorithms))
    assessment.pqc_algorithms = sorted(set(assessment.pqc_algorithms))

    if static_linking_suspected:
        assessment.static_linking = "Suspected — evidence-dependent"
        assessment.migration_blockers.append(
            "static-linked cryptographic dependencies — replacement "
            "requires rebuilding or vendor action")
    if stripped:
        assessment.migration_blockers.append(
            "symbols stripped — detection confidence is reduced and "
            "migration scoping is incomplete")
    if proprietary_suspected:
        assessment.migration_blockers.append(
            "proprietary binary component without source availability")
        assessment.source_availability = "Unavailable"
    if any("vendor" in lib.lower() or "hsm" in lib.lower() for lib in libraries):
        assessment.migration_blockers.append(
            "vendor-specific cryptographic interface — replacement "
            "library requires confirmation")
        assessment.vendor_replacement_dependency = "Requires confirmation"
    if not assessment.pqc_algorithms:
        assessment.migration_blockers.append(
            "no PQC implementation indicators detected within the "
            "analyzed scope — migration path is unproven either way")

    assessment.migration_readiness = "Not established"
    assessment.limitations.append(
        "static analysis establishes indicators, not runtime behavior; "
        "migration readiness requires source, vendor and runtime evidence "
        "this scan cannot provide (§9)")
    return assessment
