"""Deterministic automation operations (no AI/ML): certificate watch sweep,
sector policy activation, and blast-radius analysis.

* POST /automation/cert-watch          assess live certificates, emit alerts
* GET  /automation/sectors             list activatable regulated sectors
* POST /automation/sectors/{sector}/activate   derive policy config + seed rules
* POST /automation/blast-radius        dependency BFS -> impact layers
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/automation", tags=["automation"])

_ADMINS = ("admin", "superadmin", "ciso", "security_analyst")


def _publish(event_type: str, payload: dict) -> None:
    try:
        from api.events.bus import get_event_bus

        get_event_bus().publish(event_type, payload, source="automation")
    except Exception:  # noqa: BLE001
        logger.debug("automation publish skipped", exc_info=True)


# ----------------------------------------------------------------- cert watch
@router.post("/cert-watch")
def cert_watch(db: Session = Depends(get_db_session),
               user: str = Depends(require_roles(*_ADMINS))):
    """Sweep live certificates and emit thresholded expiry/strength alerts.

    Each alert is published as ``certificate.expiring`` (consumed by the
    automation bridge -> certificate playbook). Returns the watch report.
    """
    from db.models.certificate import Certificate
    from automation.watchers.cert_expiry import watch_certificates

    rows = db.execute(select(Certificate).limit(100_000)).scalars().all()
    certs = [{
        "id": r.id,
        "fingerprint_sha256": r.fingerprint_sha256,
        "not_after": r.not_after.isoformat() if r.not_after else None,
        "public_key_algorithm": r.public_key_algorithm,
        "public_key_size": r.public_key_size,
        "is_self_signed": r.is_self_signed,
        "subject": r.subject,
    } for r in rows]

    report = watch_certificates(certs)
    for alert in report.alerts:
        _publish("certificate.expiring", {
            "cert_id": alert["cert_id"],
            "days_remaining": alert["days_remaining"],
            "severity": alert["severity"],
            "state": alert["state"],
            "reasons": alert["reasons"],
        })
    out = report.as_dict()
    out["swept_by"] = user
    out["source"] = "live_certificates"
    return out


# ----------------------------------------------------------------- sectors
@router.get("/sectors")
def list_sectors(user: str = Depends(get_current_user)):
    from automation.sector_activation import available_sectors

    return {"sectors": available_sectors(), "total_count": len(available_sectors())}


class ActivateSectorResult(BaseModel):
    seeded_rule_ids: list[str] = Field(default_factory=list)


@router.post("/sectors/{sector}/activate", status_code=201)
def activate_sector_endpoint(
    sector: str,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_ADMINS)),
):
    """Derive the deterministic sector policy configuration and seed its
    safe (recommend-tier) automation rules. Change actions remain approval-gated."""
    from automation.sector_activation import activate_sector
    from automation.rules_engine import AutomationRule, RulesError
    from db.models.automation import AutomationRuleRow

    try:
        act = activate_sector(sector)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    seeded: list[str] = []
    for rdict in act.seed_rules:
        try:
            AutomationRule.from_dict({**rdict, "enabled": True})  # validate
        except RulesError as exc:
            logger.warning("sector_rule_invalid %s: %s", rdict.get("rule_id"), exc)
            continue
        row = db.execute(
            select(AutomationRuleRow).where(AutomationRuleRow.rule_id == rdict["rule_id"])
        ).scalars().first()
        if row is None:
            row = AutomationRuleRow(rule_id=rdict["rule_id"], created_by=user)
            db.add(row)
        row.name = rdict.get("name") or rdict["rule_id"]
        row.when = rdict["when"]
        row.conditions = rdict.get("if") or []
        row.actions = rdict.get("then") or []
        row.severity = str(rdict.get("severity") or "MEDIUM").upper()
        row.enabled = True
        seeded.append(rdict["rule_id"])
    db.commit()
    _publish("automation.sector_activated", {"sector": act.sector, "by": user,
                                             "rules": len(seeded)})
    return {**act.as_dict(), "activated_by": user, "seeded_rule_ids": seeded}


# ----------------------------------------------------------------- blast radius
class BlastBody(BaseModel):
    origin: str
    edges: list[list[str]] = Field(default_factory=list,
                                   description="directed [source, target] dependency edges")
    nodes: dict[str, dict] | None = None
    max_hops: int = Field(default=12, ge=1, le=24)


@router.post("/blast-radius")
def blast_radius(body: BlastBody, user: str = Depends(get_current_user)):
    """Deterministic downstream impact (certificates/apps/APIs/business services)."""
    from automation.blast_radius import analyze_blast_radius

    edges = [(str(a), str(b)) for a, b in body.edges if a and b]
    result = analyze_blast_radius(body.origin, edges, nodes=body.nodes or {},
                                  max_hops=body.max_hops)
    out = result.as_dict()
    out["evaluated_by"] = user
    # large blast radius on a critical change is worth an alert (deterministic)
    biz = out["impact_layers"].get("business_service", 0)
    if biz >= 1 or result.reachable >= 10:
        _publish("alert.raised", {
            "event_kind": "blast_radius", "asset_id": body.origin,
            "severity": result.highest_criticality,
            "business_services": result.business_services,
            "reachable_nodes": result.reachable})
    return out
