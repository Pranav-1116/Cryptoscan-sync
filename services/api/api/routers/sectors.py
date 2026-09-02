"""Sector Layer endpoints — one universal engine, sector-specific context.

The scanner is identical across sectors; these endpoints serve the decision
layer that changes per sector: which assets matter, which policy packs and
compliance frameworks apply, how business criticality is weighted, what
evidence is required, and which scan modes are recommended.

All sector logic is deterministic data/pure functions (no AI) and read-only —
nothing here scans or mutates the estate.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from api.dependencies import get_current_user

router = APIRouter(prefix="/sectors", tags=["sectors"])


@router.get("")
def list_sectors(user: str = Depends(get_current_user)):
    from sector_profiles import list_sectors as _list

    return {"sectors": [p.to_dict() for p in _list()], "count": len(_list())}


@router.get("/scan-modes")
def list_scan_modes(ot_safe_only: bool = False, user: str = Depends(get_current_user)):
    from sector_profiles import SCAN_MODES, is_ot_safe

    modes = []
    for mode in SCAN_MODES.values():
        if ot_safe_only and not is_ot_safe(mode.id):
            continue
        modes.append(
            {
                "id": mode.id,
                "name": mode.name,
                "description": mode.description,
                "active_probing": mode.active_probing,
                "depth": mode.depth,
                "mutating": mode.mutating,
                "ot_safe": is_ot_safe(mode.id),
                "default_interval_s": mode.default_interval_s,
            }
        )
    return {"modes": modes}


@router.get("/{sector_id}")
def get_sector(sector_id: str, user: str = Depends(get_current_user)):
    from sector_profiles import SECTOR_PROFILES, get_profile, normalize_sector

    canonical = normalize_sector(sector_id)
    # unknown sector normalizes to generic — surface that honestly (404)
    if sector_id.strip().lower().replace("-", "_") != canonical and canonical == "generic" \
            and sector_id.strip().lower() not in {"generic", ""}:
        # accept aliases but report a genuinely unknown token distinctly
        from sector_profiles.catalog import SECTOR_ALIASES

        token = sector_id.strip().lower().replace("-", "_")
        loose = token.replace("&", "_").split("_")[0]
        if token not in SECTOR_ALIASES and loose not in SECTOR_ALIASES and token not in SECTOR_PROFILES:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unknown sector '{sector_id}'. Use GET /sectors for the catalog.",
            )
    profile = get_profile(canonical)
    from sector_profiles import recommend_modes

    body = profile.to_dict()
    body["recommended_modes"] = recommend_modes(profile.id)
    body["recommended_modes_ot"] = recommend_modes(profile.id, ot_environment=True)
    return body


class AssetSignals(BaseModel):
    asset_id: str | None = None
    asset_type: str = ""
    customer_facing: bool = False
    internet_exposed: bool = False
    handles_pii: bool = False
    production: bool = True
    payment_path: bool = False
    safety_critical: bool = False
    crypto_strength: bool = False
    downstream_count: int = Field(0, ge=0)
    environment: str | None = None


class CriticalityRequest(BaseModel):
    sector: str = "generic"
    assets: list[AssetSignals] = Field(default_factory=list)


@router.post("/criticality")
def score_criticality(body: CriticalityRequest, user: str = Depends(get_current_user)):
    """Score business criticality for assets within a sector context.

    Same assets score differently across sectors (a payment HSM is mission-
    critical in banking, lower in a generic estate). Pure deterministic output.
    """
    from sector_profiles import (
        get_profile,
        normalize_sector,
        risk_weight,
        score_criticality,
    )

    sector = normalize_sector(body.sector)
    profile = get_profile(sector)
    results = []
    for asset in body.assets:
        signals = asset.model_dump(exclude={"asset_id", "asset_type"})
        signals["environment"] = asset.environment or ("production" if asset.production else "dev")
        tier = score_criticality(profile, asset.asset_type, **signals)
        results.append(
            {
                "asset_id": asset.asset_id,
                "asset_type": asset.asset_type,
                "criticality": tier,
                "risk_weight": risk_weight(tier),
            }
        )
    return {"sector": profile.id, "sector_name": profile.name, "assets": results}


class ContextRequest(BaseModel):
    sector: str = "generic"
    assets: list[AssetSignals] = Field(default_factory=list)
    ot_environment: bool = False


@router.post("/context")
def sector_context(body: ContextRequest, user: str = Depends(get_current_user)):
    """Full sector context bundle used to seed scans/reports: policy packs,
    compliance mappings, recommended scan modes (OT-aware), required evidence,
    integrations, environment separation, and per-asset criticality."""
    from sector_profiles import (
        normalize_sector,
        recommend_modes,
        resolve_sector_context,
    )

    sector = normalize_sector(body.sector)
    asset_dicts = [a.model_dump() for a in body.assets]
    ctx = resolve_sector_context(sector, asset_dicts)
    if body.ot_environment:
        ctx["recommended_modes"] = recommend_modes(sector, ot_environment=True)
        ctx["ot_environment"] = True
        ctx["active_probing_permitted"] = False
    else:
        ctx["ot_environment"] = False
        ctx["active_probing_permitted"] = True
    return ctx
