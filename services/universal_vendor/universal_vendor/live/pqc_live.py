"""Live PQC Vendor Monitoring (24/7 spec §15).

Every vendor change triggers: crypto detection → algorithm classification →
PQC status → vendor capability check → dependency analysis → migration
impact. Capability states: PQC_SUPPORTED | HYBRID_SUPPORTED |
PARTIALLY_SUPPORTED | ROADMAP_DECLARED | NOT_SUPPORTED | UNKNOWN —
maintained in a versioned capability database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from universal_vendor.models import PqcCapability
from universal_vendor.pqc_readiness import PqcReadinessDatabase

_VENDOR_IMPACT_WEIGHTS = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


@dataclass
class MigrationImpact:
    asset_id: str
    vendor: str
    product: str
    pqc_capability: str
    lifecycle_priority: str = "LOW"
    dependency_count: int = 0
    impact: str = "LOW"

    def to_dict(self) -> dict[str, Any]:
        return {"asset_id": self.asset_id, "vendor": self.vendor,
                "product": self.product,
                "pqc_capability": self.pqc_capability,
                "lifecycle_priority": self.lifecycle_priority,
                "dependency_count": self.dependency_count,
                "impact": self.impact}


class LivePqcMonitor:
    """Per-asset live PQC tracking with migration impact."""

    def __init__(self, pqc_db: Optional[PqcReadinessDatabase] = None,
                 lifecycle_db=None) -> None:
        self.pqc_db = pqc_db or PqcReadinessDatabase()
        self.lifecycle = lifecycle_db
        self._assessments: dict[str, MigrationImpact] = {}
        self._change_log: list[dict[str, Any]] = []

    def assess(self, *, asset_id: str, vendor: str, product: str,
               version: Optional[str] = None,
               algorithms: Optional[list[str]] = None,
               dependency_count: int = 0) -> MigrationImpact:
        """Evaluate PQC capability + migration impact for an asset."""
        verdict = self.pqc_db.verdict(vendor, product, version)
        capability = verdict.get("pqc_capability", PqcCapability.UNKNOWN.value)

        lifecycle_priority = "LOW"
        if self.lifecycle is not None:
            result = self.lifecycle.migration_priority(
                vendor, product, version, pqc_required=capability in (
                    PqcCapability.NOT_SUPPORTED.value,
                    PqcCapability.UNKNOWN.value,
                ))
            lifecycle_priority = result.get("migration_priority", "LOW")

        # impact = capability shortfall + lifecycle + dependency fan-out
        shortfall = {
            PqcCapability.PQC_SUPPORTED.value: 0,
            PqcCapability.HYBRID_SUPPORTED.value: 1,
            PqcCapability.PARTIALLY_SUPPORTED.value: 2,
            PqcCapability.ROADMAP_DECLARED.value: 2,
            PqcCapability.NOT_SUPPORTED.value: 3,
            PqcCapability.UNKNOWN.value: 2,
        }.get(capability, 2)
        lifecycle_weight = _VENDOR_IMPACT_WEIGHTS.get(lifecycle_priority, 0)
        dep_weight = min(dependency_count, 10) // 5
        score = shortfall + lifecycle_weight + dep_weight
        impact = "HIGH" if score >= 5 else ("MEDIUM" if score >= 3 else "LOW")

        assessment = MigrationImpact(
            asset_id=asset_id, vendor=vendor, product=product,
            pqc_capability=capability,
            lifecycle_priority=lifecycle_priority,
            dependency_count=dependency_count, impact=impact,
        )
        previous = self._assessments.get(asset_id)
        self._assessments[asset_id] = assessment
        if previous and previous.pqc_capability != capability:
            self._change_log.append({
                "asset_id": asset_id,
                "previous_capability": previous.pqc_capability,
                "capability": capability,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        return assessment

    def assessments(self) -> list[MigrationImpact]:
        return list(self._assessments.values())

    def capability_changes(self) -> list[dict[str, Any]]:
        return list(self._change_log)
