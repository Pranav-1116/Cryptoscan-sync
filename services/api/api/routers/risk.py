"""Unified Risk Engine.

Normalizes Technical + Crypto + PQC + Exposure + Business Criticality +
Dependency Impact + Evidence Confidence + Threat into one deterministic score
per asset and across the estate (enterprise-blueprint item #3).

This endpoint is the single risk contract the CMDB and executive views consume.
It reuses the authoritative unified inventory (``collect_inventory``) so the
scores are computed over the SAME persisted, deduplicated rows shown on the
CMDB — no separate, divergent dataset.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from api.routers.inventory import collect_inventory
from universal_platform.risk import UNIFIED_FACTORS, from_asset

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/unified")
def unified_inventory_risk(
    asset_type: str | None = None,
    risk: str | None = None,
    limit: int = Query(500, ge=1, le=1000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Unified risk for every asset in the authoritative inventory + estate rollup.

    Filters mirror the CMDB (asset_type / risk level) so the views stay in sync.
    """
    rows = collect_inventory(db, limit=limit)
    if asset_type:
        rows = [r for r in rows if r["asset_type"].lower() == asset_type.lower()]
    if risk:
        rows = [r for r in rows if r["risk"] and r["risk"].lower() == risk.lower()]

    scored: list[dict[str, Any]] = []
    for r in rows:
        score = from_asset(r)
        scored.append({
            "id": r["id"],
            "name": r.get("name"),
            "asset_type": r["asset_type"],
            "score": score["score"],
            "level": score["level"],
            "factors": score["factors"],
            "missing": score["missing"],
        })
    estate = _estate_rollup(scored)
    return {
        "assets": scored,
        "count": len(scored),
        "estate": estate,
        "factors": list(UNIFIED_FACTORS.keys()),
        "source": "unified_risk_engine",
    }


def _estate_rollup(scored: list[dict[str, Any]]) -> dict[str, Any]:
    if not scored:
        return {"score": 0.0, "level": "LOW", "count": 0, "by_level": {}}
    mean = round(sum(s["score"] for s in scored) / len(scored), 1)
    return {
        "score": mean,
        "level": _level_for(mean),
        "count": len(scored),
        "by_level": {lv: sum(1 for s in scored if s["level"] == lv)
                     for lv in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
    }


def _level_for(score: float) -> str:
    for name, floor in (("CRITICAL", 80), ("HIGH", 60), ("MEDIUM", 40), ("LOW", 0)):
        if score >= floor:
            return name
    return "LOW"
