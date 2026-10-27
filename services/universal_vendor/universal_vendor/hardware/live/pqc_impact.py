"""Live hardware PQC monitoring (§18).

Hardware changes automatically trigger PQC reassessment:

    Hardware Change → Crypto Capability → PQC Capability →
    Affected Software → Affected Applications → Migration Impact

Example: legacy HSM + no required PQC capability + 100 dependent
applications → HIGH migration dependency.

All thresholds and verdicts are deterministic catalog rules — the engine
never infers a PQC capability from a product name (that stays the
evidence-backed PqcReadinessDatabase's job).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from datetime import datetime, timezone
from typing import Any, Optional

# deterministic thresholds for migration-impact classification
_HIGH_APP_THRESHOLD = 10
_MEDIUM_APP_THRESHOLD = 3


class HardwarePqcImpactEngine:
    """Assesses PQC migration impact when hardware crypto changes (§18)."""

    def __init__(
        self,
        *,
        pqc_db: Optional[Any] = None,
        correlation: Optional[Any] = None,
    ) -> None:
        self._pqc_db = pqc_db  # PqcReadinessDatabase (evidence-backed verdicts)
        self._correlation = correlation  # HardwareCorrelationEngine (graph)
        self._assessments: list[dict[str, Any]] = []

    def _verdict(self, manufacturer: str, model: str,
                 version: Optional[str]) -> dict[str, Any]:
        if self._pqc_db is not None:
            try:
                return self._pqc_db.verdict(manufacturer, model, version)
            except Exception as _handler_exc:
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass
        return {"pqc_capability": "UNKNOWN", "hybrid_capability": False,
                "reason": "no pqc database supplied"}

    def affected_applications(self, asset_id: str) -> list[str]:
        """Software/applications depending on this hardware (from the
        hardware→software correlation graph, §11)."""
        if self._correlation is None:
            return []
        apps: list[str] = []
        try:
            for node in self._correlation.graph.nodes():
                nid = node.get("id") or node.get("asset_id")
                if not nid or nid == asset_id:
                    continue
                if self._correlation.graph.paths(asset_id, nid, max_depth=6):
                    apps.append(nid)
        except Exception:
            return []
        return apps

    def assess(
        self,
        *,
        asset_id: str,
        manufacturer: str,
        model: str,
        version: Optional[str] = None,
        affected_applications: Optional[list[str]] = None,
        hardware_change_type: str = "HARDWARE_CHANGE",
        declared_capability: Optional[str] = None,
    ) -> dict[str, Any]:
        """One deterministic PQC impact assessment for a hardware change.

        ``declared_capability`` is evidence from the change event itself
        (e.g. the HSM's own metadata); the evidence-backed DB verdict is the
        fallback when the event declares nothing.
        """
        verdict = self._verdict(manufacturer, model, version)
        db_capability = str(verdict.get("pqc_capability", "UNKNOWN")).upper()
        declared = str(declared_capability or "").upper()
        pqc_capability = declared or db_capability
        apps = list(affected_applications
                    if affected_applications is not None
                    else self.affected_applications(asset_id))
        app_count = len(apps)

        # migration dependency (spec example: legacy HSM + no PQC + 100 apps).
        # Canonical capability values (universal_vendor.models.PqcCapability):
        # PQC_SUPPORTED / HYBRID_SUPPORTED / PARTIALLY_SUPPORTED /
        # ROADMAP_DECLARED / NOT_SUPPORTED / UNKNOWN.
        if pqc_capability == "HYBRID_SUPPORTED" and verdict.get("hybrid_capability"):
            impact = "NONE"
        elif pqc_capability in ("PQC_SUPPORTED", "HYBRID_SUPPORTED"):
            impact = "LOW"
        elif pqc_capability in ("ROADMAP_DECLARED", "PARTIALLY_SUPPORTED", "PARTIAL"):
            impact = "MEDIUM" if app_count >= _MEDIUM_APP_THRESHOLD else "LOW"
        else:  # UNKNOWN / NOT_SUPPORTED
            if app_count >= _HIGH_APP_THRESHOLD:
                impact = "HIGH"
            elif app_count >= _MEDIUM_APP_THRESHOLD:
                impact = "MEDIUM"
            else:
                impact = "LOW" if app_count else "NONE"

        assessment = {
            "asset_id": asset_id,
            "hardware_change_type": hardware_change_type,
            "pqc_capability": pqc_capability,
            "hybrid_capability": bool(verdict.get("hybrid_capability", False)),
            "pqc_reason": verdict.get("reason", ""),
            "affected_application_count": app_count,
            "affected_applications": apps,
            "migration_impact": impact,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }
        self._assessments.append(assessment)
        return assessment

    def assessments(self) -> list[dict[str, Any]]:
        return list(self._assessments)

    def latest(self, asset_id: str) -> Optional[dict[str, Any]]:
        for assessment in reversed(self._assessments):
            if assessment["asset_id"] == asset_id:
                return assessment
        return None
