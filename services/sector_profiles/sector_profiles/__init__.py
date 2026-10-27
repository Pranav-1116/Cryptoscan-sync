"""Sector Profiles — the ZELNX Sector Layer.

One universal scanning engine; sectors differ only in context and decision:
which assets matter, which policy packs and compliance frameworks apply, how
criticality is weighted, what evidence is required, and which scan modes fit.

    from sector_profiles import get_profile, score_criticality, recommend_modes

Deterministic data + pure functions only — policy is never decided by AI.
"""

from __future__ import annotations

from sector_profiles.catalog import (
    CRITICALITY_TIERS,
    SECTOR_ALIASES,
    SECTOR_PROFILES,
    SectorProfile,
    get_profile,
    list_sectors,
    normalize_sector,
)
from sector_profiles.compliance import map_findings_to_frameworks
from sector_profiles.criticality import risk_weight, score_criticality
from sector_profiles.scan_modes import (
    OT_SAFE_MODES,
    SCAN_MODES,
    ScanMode,
    is_ot_safe,
    list_modes,
    recommend_modes,
)


def resolve_sector_context(sector: str | None, assets: list[dict] | None = None) -> dict:
    """Full context bundle the engine/reports use for one deployment.

    Given a sector id and an optional list of asset dicts (each with at least
    ``asset_type`` and optional signals), returns the profile plus per-asset
    criticality. Deterministic and side-effect free.
    """
    profile = get_profile(sector)
    assets = assets or []
    scored = []
    for asset in assets:
        asset_type = str(asset.get("asset_type") or asset.get("type") or "")
        tier = score_criticality(profile, asset_type, **{k: v for k, v in asset.items() if k not in {"asset_type", "type"}})
        scored.append(
            {
                "asset_id": asset.get("asset_id") or asset.get("id"),
                "asset_type": asset_type,
                "criticality": tier,
                "risk_weight": risk_weight(tier),
            }
        )
    return {
        "sector": profile.id,
        "sector_name": profile.name,
        "description": profile.description,
        "policy_packs": list(profile.policy_packs),
        "compliance_frameworks": list(profile.compliance_frameworks),
        "recommended_modes": recommend_modes(profile.id),
        "required_evidence": list(profile.required_evidence),
        "integrations": list(profile.integrations),
        "environment_separation": list(profile.environment_separation),
        "critical_asset_classes": list(profile.critical_asset_classes),
        "scanning_notes": list(profile.scanning_notes),
        "assets": scored,
    }


__all__ = [
    "CRITICALITY_TIERS",
    "OT_SAFE_MODES",
    "SCAN_MODES",
    "SECTOR_ALIASES",
    "SECTOR_PROFILES",
    "ScanMode",
    "SectorProfile",
    "get_profile",
    "is_ot_safe",
    "list_modes",
    "list_sectors",
    "map_findings_to_frameworks",
    "normalize_sector",
    "recommend_modes",
    "resolve_sector_context",
    "risk_weight",
    "score_criticality",
]
