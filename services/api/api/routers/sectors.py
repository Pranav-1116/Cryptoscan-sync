"""Sector Layer endpoints — one universal engine, sector-specific context.

The scanner is identical across sectors; these endpoints serve the decision
layer that changes per sector: which assets matter, which policy packs and
compliance frameworks apply, how business criticality is weighted, what
evidence is required, and which scan modes are recommended.

All sector logic is deterministic data/pure functions (no AI) and read-only —
nothing here scans or mutates the estate.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from db.repositories.settings_repository import SECTOR_SETTING_KEY, SettingsRepository
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

router = APIRouter(prefix="/sectors", tags=["sectors"])


# ------------------------------------------------------------- org sector setting


def _active_sector(db: Session) -> str:
    try:
        stored = SettingsRepository(db).get(SECTOR_SETTING_KEY)
        if isinstance(stored, dict):
            return stored.get("sector") or "generic"
        if isinstance(stored, str):
            return stored
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
    return "generic"


@router.get("/organization/active")
def get_active_sector(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The sector profile currently applied to the organization, plus its
    resolved context (policy packs, frameworks, modes)."""
    from sector_profiles import get_profile, normalize_sector, recommend_modes

    sector = normalize_sector(_active_sector(db))
    profile = get_profile(sector)
    body = profile.to_dict()
    body["recommended_modes"] = recommend_modes(sector)
    return {"sector": sector, "profile": body}


class SetSectorRequest(BaseModel):
    sector: str = Field(..., min_length=1)


@router.put("/organization/active")
def set_active_sector(
    body: SetSectorRequest,
    request: Request,
    admin: str = Depends(require_roles("admin", "superadmin", "ciso")),
    db: Session = Depends(get_db_session),
):
    """Persist the organization's sector profile (admin/ciso).

    The universal scanner is unchanged; this selects which policy packs,
    compliance frameworks, criticality model and scan modes apply estate-wide.
    """
    from sector_profiles import SECTOR_PROFILES, get_profile, normalize_sector

    raw = body.sector.strip()
    sector = normalize_sector(raw)
    # reject a genuinely unknown token (normalize falls back to generic)
    if sector == "generic" and raw.lower().replace("-", "_") not in {"generic", ""}:
        from sector_profiles.catalog import SECTOR_ALIASES

        token = raw.lower().replace("-", "_")
        loose = token.replace("&", "_").split("_")[0]
        if token not in SECTOR_ALIASES and loose not in SECTOR_ALIASES and token not in SECTOR_PROFILES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown sector '{raw}'. Use GET /sectors for the catalog.",
            )
    repo = SettingsRepository(db)
    repo.set(SECTOR_SETTING_KEY, {"sector": sector}, updated_by=admin)
    repo_session = db
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(repo_session).audit(
            admin, "sector.set", target_type="organization", target_id="sector_profile",
            detail={"sector": sector}, ip=request.client.host if request.client else None,
        )
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
    db.commit()
    try:
        from api.events.bus import get_event_bus

        get_event_bus().publish("sector.changed", {"sector": sector, "by": admin}, source="sectors")
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
    profile = get_profile(sector)
    return {"sector": sector, "name": profile.name, "policy_packs": list(profile.policy_packs),
            "compliance_frameworks": list(profile.compliance_frameworks)}


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


class QuantumRiskRequest(BaseModel):
    sector: str | None = None


@router.get("/quantum-risk")
def sector_quantum_risk(
    sector: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Quantum (HNDL/PQC) risk for live assets weighted by the sector context.

    The active sector (or override) drives the per-asset criticality weight,
    so a payment HSM in banking is scored higher than the same asset in a
    generic estate. Read-only over the current crypto inventory.
    """
    from db.repositories.system_repository import SystemRepository
    from quantum.risk import analyze_quantum_risk
    from sector_profiles import normalize_sector

    effective = normalize_sector(sector or _active_sector(db))
    repo = SystemRepository(db)
    systems, _ = repo.list_systems(page=1, page_size=500)
    system_rows = []
    findings = []
    for system in systems:
        sdict = system.to_dict()
        system_rows.append(sdict)
        for asset in repo.assets_for(system.id):
            row = asset.to_dict()
            row["system_id"] = system.id
            findings.append(row)
    result = analyze_quantum_risk(findings, systems=system_rows, sector=effective)
    result["active_sector"] = effective
    return result


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


class ComplianceMapRequest(BaseModel):
    sector: str | None = None  # default: organization's active sector
    findings: list[dict] = Field(default_factory=list)


@router.post("/compliance-map")
def compliance_map(
    body: ComplianceMapRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Map policy findings onto the sector's compliance frameworks.

    Uses the supplied sector or, when omitted, the organization's active
    sector. Compliance status still comes from the deterministic policy
    engine; this only attributes failing findings to sector framework controls.
    """
    from sector_profiles import map_findings_to_frameworks, normalize_sector

    sector = normalize_sector(body.sector or _active_sector(db))
    return map_findings_to_frameworks(sector, body.findings)


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
