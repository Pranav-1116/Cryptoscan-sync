"""Normalized OS intelligence evidence (docs/os-kernel-intelligence/
01_PRODUCT_SPEC.md §10).

Every finding carries: observation source, collection time, scope,
evidence reference and confidence classification (§1). The decisive
field is `runtime_usage_confirmed` — a registered kernel capability is
NOT proof that any application used it (§2.2). Evidence classes reuse
the platform taxonomy (binary-intelligence §5): observed,
strongly_supported, indicated, inferred, unknown, not_detected — a
classification is never a numeric score, and confidence is never
coverage.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List

COLLECTOR_NAME = "cryptoscan-os-intelligence"
COLLECTOR_VERSION = "os-intelligence/1.0.0"

EVIDENCE_CLASSES = ("observed", "strongly_supported", "indicated",
                    "inferred", "unknown", "not_detected")

OBSERVATION_TYPES = ("registered_capability", "configuration_state",
                     "loaded_module", "interface_inventory",
                     "device_presence", "metadata_extraction",
                     "unavailable", "permission_denied")


@dataclass
class OSFinding:
    """One normalized finding (§10 example record shape)."""
    finding_type: str
    subject: str                      # host id
    algorithm: str = ""
    implementation: str = ""
    evidence_source: str = ""
    observation_type: str = "registered_capability"
    runtime_usage_confirmed: bool = False
    evidence_class: str = "observed"
    details: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "host_id": self.subject,
            "algorithm": self.algorithm,
            "implementation": self.implementation,
            "evidence_source": self.evidence_source,
            "observation_type": self.observation_type,
            # the decisive field (§10): a registered capability is not
            # runtime usage — this engine never confirms usage
            "runtime_usage_confirmed": self.runtime_usage_confirmed,
            "evidence_class": self.evidence_class,
            "collector_version": COLLECTOR_VERSION,
            "details": self.details,
            "limitations": self.limitations,
            "note": "an inventory of registered capabilities and "
                    "configuration states — runtime usage is never "
                    "confirmed by static OS collection (§2.2)",
        }


@dataclass
class CoverageReport:
    """Collection completeness (§2.1): unavailable information is
    RECORDED, never treated as disabled."""
    sources_attempted: List[str] = field(default_factory=list)
    sources_collected: List[str] = field(default_factory=list)
    sources_unavailable: List[Dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sources_attempted": self.sources_attempted,
            "sources_collected": self.sources_collected,
            "sources_unavailable": self.sources_unavailable,
            "note": "coverage is collection completeness — an "
                    "unavailable source is recorded as unavailable and "
                    "NEVER treated as 'disabled' or 'absent' (§2.1); "
                    "coverage is not finding confidence",
        }


def evidence_digest(payload: str) -> str:
    """Hash the captured metadata artifact (§10 evidence integrity)."""
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()
