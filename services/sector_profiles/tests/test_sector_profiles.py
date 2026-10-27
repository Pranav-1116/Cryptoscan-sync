"""Sector Profile layer: catalog, normalization, criticality, scan modes."""

from __future__ import annotations

from sector_profiles import (
    SECTOR_PROFILES,
    get_profile,
    list_sectors,
    normalize_sector,
    recommend_modes,
    resolve_sector_context,
    risk_weight,
    score_criticality,
)
from sector_profiles.scan_modes import SCAN_MODES, is_ot_safe

# --------------------------------------------------------------- catalog

def test_catalog_covers_all_zelnx_sectors():
    ids = {p.id for p in list_sectors()}
    expected = {
        "banking", "healthcare", "energy", "telecom", "government",
        "manufacturing", "automotive", "pharmaceutical", "retail",
        "cloud_saas", "generic",
    }
    assert expected <= ids
    # generic exists as the safe default
    assert normalize_sector(None) == "generic"
    assert normalize_sector("totally-unknown") == "generic"


def test_each_profile_has_required_fields_and_known_packs():
    valid_packs = {"nist", "fips", "cnsa", "hipaa", "pci_dss", "baseline"}
    for profile in SECTOR_PROFILES.values():
        assert profile.name and profile.description
        assert profile.policy_packs, f"{profile.id} declares no policy packs"
        assert profile.compliance_frameworks, f"{profile.id} declares no frameworks"
        assert profile.recommended_modes, f"{profile.id} declares no modes"
        assert set(profile.recommended_modes) <= set(SCAN_MODES)
        assert set(profile.policy_packs) <= valid_packs, profile.policy_packs
        # every asset-criticality value is a real tier
        from sector_profiles.catalog import CRITICALITY_TIERS
        assert set(profile.asset_criticality.values()) <= set(CRITICALITY_TIERS)


def test_normalize_sector_aliases():
    assert normalize_sector("bank") == "banking"
    assert normalize_sector("HIPAA-health") == "healthcare" or normalize_sector("health") == "healthcare"
    assert normalize_sector("Banking & Financial Services") == "banking"
    assert normalize_sector("TELCO") == "telecom"
    assert normalize_sector("Manufacturing") == "manufacturing"
    assert normalize_sector("saas") == "cloud_saas"


# ----------------------------------------------------------- criticality

def test_payment_hsm_is_mission_critical_in_banking():
    bank = get_profile("banking")
    assert score_criticality(bank, "payment_hsm", payment_path=True, production=True) == "MISSION_CRITICAL"


def test_same_asset_scores_lower_in_generic_sector():
    bank = get_profile("banking")
    generic = get_profile("generic")
    hsm_bank = score_criticality(bank, "payment_hsm", payment_path=True)
    hsm_generic = score_criticality(generic, "unknown_widget")
    assert hsm_bank == "MISSION_CRITICAL"
    assert hsm_generic in {"MEDIUM", "LOW"}


def test_non_production_is_downgraded():
    bank = get_profile("banking")
    prod = score_criticality(bank, "api_gateway", production=True, environment="production")
    dev = score_criticality(bank, "api_gateway", production=False, environment="dev")
    assert prod != "VERY_LOW"
    assert dev in {"VERY_LOW", "LOW"}


def test_safety_critical_ot_asset_elevated_in_energy():
    energy = get_profile("energy")
    tier = score_criticality(energy, "scada_controller", safety_critical=True, production=True)
    assert tier == "MISSION_CRITICAL"


def test_risk_weight_monotonic_with_tier():
    assert risk_weight("MISSION_CRITICAL") > risk_weight("VERY_HIGH") > risk_weight("MEDIUM") > risk_weight("LOW")
    assert risk_weight("NOPE") == 1.0


def test_criticality_is_deterministic():
    bank = get_profile("banking")
    a = score_criticality(bank, "core_banking", production=True, handles_pii=True)
    b = score_criticality(bank, "core_banking", production=True, handles_pii=True)
    assert a == b


# ------------------------------------------------------------- scan modes

def test_passive_mode_is_not_active_probing():
    assert SCAN_MODES["passive"].active_probing is False
    assert is_ot_safe("passive") and is_ot_safe("discovery")
    assert not is_ot_safe("deep")


def test_ot_environment_puts_passive_first():
    modes = recommend_modes("energy", ot_environment=True)
    assert modes[0]["id"] == "passive"
    # energy's normal recommendation also already includes passive
    normal = [m["id"] for m in recommend_modes("energy")]
    assert "passive" in normal


# -------------------------------------------------------------- context

def test_resolve_sector_context_bundle():
    ctx = resolve_sector_context("healthcare", [
        {"asset_type": "ehr", "handles_pii": True, "production": True},
        {"asset_type": "dev_workstation", "environment": "dev"},
    ])
    assert ctx["sector"] == "healthcare"
    assert "HIPAA" in ctx["compliance_frameworks"]
    ehr = next(a for a in ctx["assets"] if a["asset_type"] == "ehr")
    assert ehr["criticality"] == "MISSION_CRITICAL"
    assert ctx["policy_packs"] and ctx["recommended_modes"]
