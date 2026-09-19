"""Remediation SLA tracking endpoints (deterministic, no AI/ML).

Fixed deadline-per-severity policy with critical-asset window compression;
classifies findings ON_TRACK / AT_RISK / BREACHED / RESOLVED and reports breach
rate. Runs over posted findings or the LIVE stored evidence findings.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sla", tags=["sla"])


class SlaEvaluateBody(BaseModel):
    findings: list[dict] = Field(default_factory=list, max_length=100_000)
    use_live: bool = False
    sla_days: dict[str, int] | None = None


def _live_findings(db: Session) -> list[dict]:
    try:
        from db.repositories.evidence_repository import EvidenceRepository

        rows = EvidenceRepository(db).list_all(limit=100_000)
    except Exception:  # noqa: BLE001
        logger.debug("sla live evidence lookup failed", exc_info=True)
        return []
    out = []
    for r in rows:
        out.append({
            "id": str(getattr(r, "id", "")),
            "severity": getattr(r, "severity", None) or getattr(r, "confidence", None),
            "detected_at": getattr(r, "created_at", None) or getattr(r, "first_seen", None),
            "resolved_at": getattr(r, "resolved_at", None) or getattr(r, "fixed_at", None),
            "asset_criticality": getattr(r, "asset_criticality", None),
        })
    return out


@router.get("/policy")
def sla_policy(user: str = Depends(get_current_user)):
    from sla.tracker import CRITICAL_ASSET_TIERS, DEFAULT_SLA_DAYS, WARN_FRACTION

    return {
        "sla_days": DEFAULT_SLA_DAYS,
        "critical_asset_tiers": sorted(CRITICAL_ASSET_TIERS),
        "critical_asset_window": "halved",
        "at_risk_warning_fraction": WARN_FRACTION,
        "states": ["ON_TRACK", "AT_RISK", "BREACHED", "RESOLVED"],
    }


@router.post("/evaluate")
def evaluate(body: SlaEvaluateBody, db: Session = Depends(get_db_session),
             user: str = Depends(require_roles("admin", "superadmin", "security_analyst",
                                               "ciso", "auditor", "remediation"))):
    from sla.tracker import evaluate_findings

    findings = body.findings
    if body.use_live or not findings:
        findings = _live_findings(db)
    report = evaluate_findings(findings, sla_days=body.sla_days)
    out = report.as_dict()
    out["source"] = "live_evidence" if (body.use_live or not body.findings) else "posted"
    out["evaluated_by"] = user

    # surface breaches on the event bus (deterministic alerting)
    if report.breached:
        try:
            from api.events.bus import get_event_bus

            get_event_bus().publish(
                "sla.breaches_present",
                {"breached": report.breached, "at_risk": report.at_risk,
                 "breach_rate": out["breach_rate"]},
                source="sla",
            )
        except Exception:  # noqa: BLE001
            logger.debug("sla event publish skipped", exc_info=True)
    return out
