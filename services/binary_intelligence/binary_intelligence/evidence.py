"""Evidence, confidence and coverage (§7) — the part that makes this
bank-grade.

Evidence classifications (observed / strongly_supported / indicated /
inferred / unknown / not_detected) are DISTINCT from any numerical
confidence. Finding confidence and analysis coverage are two separate
measurements: high confidence in one finding never implies the artifact
was fully analyzed, and 'no cryptography found' is NEVER reported as
'cryptography absent' without a defensible basis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum


class EvidenceClass(str, Enum):
    OBSERVED = "observed"
    STRONGLY_SUPPORTED = "strongly_supported"
    INDICATED = "indicated"
    INFERRED = "inferred"
    UNKNOWN = "unknown"
    NOT_DETECTED = "not_detected"


#: §5: capability versus actual usage. The names carry the claim.
class UsageStatus(str, Enum):
    CAPABILITY_ONLY = "capability_only"          # library/feature present
    STATICALLY_REFERENCED = "statically_referenced"   # symbol imported/used
    STATICALLY_SUPPORTED = "statically_supported"     # multiple static indicators
    RUNTIME_CONFIRMED = "runtime_confirmed"           # dynamic analysis only
    CONFIGURATION_ONLY = "configuration_only"         # config permits it
    UNRESOLVED = "unresolved"


@dataclass
class EvidenceItem:
    evidence_type: str          # "function_reference" | "string_indicator"
                                # | "dependency" | "header_field" |
                                # "certificate" | "constant_match"
    location: str               # "ELF dynsym", "PE import table", offset...
    description: str
    excerpt: str = ""           # bounded excerpt, never key material

    def as_dict(self) -> Dict[str, Any]:
        return {
            "type": self.evidence_type,
            "location": self.location,
            "description": self.description,
            "excerpt": self.excerpt,
        }


@dataclass
class CryptoFinding:
    finding_id: str
    artifact_id: str
    artifact_sha256: str
    subject: str
    finding_type: str           # "cryptographic_algorithm" | "cryptographic_library" | ...
    algorithm: str = ""
    variant: str = ""           # "" = variant not established
    operation: str = ""
    mode_or_padding: str = ""
    key_size_bits: Optional[int] = None   # None = unknown, NEVER guessed
    library: str = ""
    detection_method: str = ""
    evidence: List[EvidenceItem] = field(default_factory=list)
    evidence_class: EvidenceClass = EvidenceClass.INDICATED
    usage_status: UsageStatus = UsageStatus.CAPABILITY_ONLY
    runtime_confirmed: bool = False
    quantum_vulnerable: bool = False
    pqc_family: bool = False
    limitations: List[str] = field(default_factory=list)
    scanner_version: str = ""
    signature_database_version: str = ""
    observed_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "subject": self.subject,
            "finding_type": self.finding_type,
            "algorithm": self.algorithm,
            "variant": self.variant,
            "operation": self.operation,
            "mode_or_padding": self.mode_or_padding,
            "key_size_bits": self.key_size_bits,   # unknown stays null
            "library": self.library,
            "detection_method": self.detection_method,
            "evidence": [e.as_dict() for e in self.evidence],
            "confidence": self.evidence_class.value,
            "usage_status": self.usage_status.value,
            "runtime_confirmed": self.runtime_confirmed,
            "quantum_vulnerable": self.quantum_vulnerable,
            "pqc_family": self.pqc_family,
            "limitations": self.limitations,
            "scanner_version": self.scanner_version,
            "signature_database_version": self.signature_database_version,
            "observed_at": self.observed_at,
        }


@dataclass
class CoverageReport:
    """Analysis coverage — never confused with finding confidence (§7).
    'No cryptography found' is not 'cryptography absent'."""
    total_bytes: int
    bytes_inspected: int
    sections_total: int
    sections_inspected: int
    executable_sections: int
    symbols_found: int
    symbols_stripped: bool
    unresolved_dependencies: List[str] = field(default_factory=list)
    unsupported_regions: List[str] = field(default_factory=list)
    extraction_failures: List[str] = field(default_factory=list)
    deep_analysis_completed: bool = False
    packed_or_encrypted_suspected: bool = False
    analysis_timeouts: int = 0

    def as_dict(self) -> Dict[str, Any]:
        fraction = (self.bytes_inspected / self.total_bytes
                    if self.total_bytes else 0.0)
        return {
            "total_bytes": self.total_bytes,
            "bytes_inspected": self.bytes_inspected,
            "coverage_fraction": round(fraction, 4),
            "sections_total": self.sections_total,
            "sections_inspected": self.sections_inspected,
            "executable_sections": self.executable_sections,
            "symbols_found": self.symbols_found,
            "symbols_stripped": self.symbols_stripped,
            "unresolved_dependencies": self.unresolved_dependencies,
            "unsupported_regions": self.unsupported_regions,
            "extraction_failures": self.extraction_failures,
            "deep_analysis_completed": self.deep_analysis_completed,
            "packed_or_encrypted_suspected": self.packed_or_encrypted_suspected,
            "analysis_timeouts": self.analysis_timeouts,
            "note": (
                "analysis coverage is not finding confidence: a fully "
                "covered artifact can still hold undetected cryptography, "
                "and no finding is never proof of absence"),
        }
