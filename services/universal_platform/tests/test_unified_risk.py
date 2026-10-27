"""§29b Unified risk tests — Technical + Crypto + PQC + Exposure + Business
Criticality + Dependency Impact + Evidence Confidence + Threat → one score."""

from __future__ import annotations

from universal_platform.risk import (
    CALCULATION_VERSION,
    UNIFIED_FACTORS,
    from_asset,
    unified_level,
    unified_risk,
    unified_weights,
)


def test_unified_risk_missing_factors_are_zero():
    r = unified_risk()
    assert r["score"] == 0.0
    assert r["level"] == "LOW"
    assert r["missing"] == list(UNIFIED_FACTORS.keys())


def test_unified_risk_all_max_is_critical():
    r = unified_risk({k: 4 for k in UNIFIED_FACTORS})
    assert r["score"] == 100.0
    assert r["level"] == "CRITICAL"
    assert r["missing"] == []


def test_unified_risk_levels_and_weighted_scale():
    r = unified_risk({"technical": 4, "crypto": 0, "pqc": 0, "exposure": 4,
                      "business_criticality": 4, "dependency_impact": 4,
                      "evidence_confidence": 4, "threat": 4})
    # technical .18 + exposure .12 + business .14 + dependency .10 + conf .06 + threat .08
    assert abs(r["score"] - (18 + 12 + 14 + 10 + 6 + 8)) < 2.0
    assert unified_level(r["score"]) in ("HIGH", "MEDIUM")


def test_unified_risk_caps_level_at_four():
    assert unified_risk({"technical": 99})["score"] == 18.0  # capped at 4 * .18


def test_from_asset_maps_inventory_row_deterministically():
    asset = {
        "name": "payment-gateway",
        "asset_type": "Application",
        "environment": "prod",
        "criticality": "TIER-1",
        "pqc": "vulnerable",
        "algorithm": "RSA",
        "confidence": "HIGH",
        "relationships": {"uses": ["a", "b"], "supports": ["c"]},
    }
    r = from_asset(asset)
    assert r["level"] in ("HIGH", "CRITICAL")
    assert r["factors"]["exposure"]["level"] == 4   # prod
    assert r["factors"]["business_criticality"]["level"] == 4  # TIER-1
    assert r["factors"]["pqc"]["level"] == 4        # vulnerable
    assert r["factors"]["dependency_impact"]["level"] == 3  # 3 relationship hops
    assert r["factors"]["evidence_confidence"]["level"] == 4  # HIGH
    assert r["factors"]["threat"]["level"] == 0     # no threat source -> honest 0


def test_from_asset_unknown_is_zero_not_fabricated():
    r = from_asset({"name": "x", "asset_type": "Crypto"})
    assert r["score"] == 0.0
    assert r["level"] == "LOW"


# --------------------------------------------------------------------------- #
# Report 64 P0 — configurable weights + calculation versioning
# --------------------------------------------------------------------------- #


def test_calculation_version_stamped():
    r = unified_risk({"pqc": 4})
    assert r["calculation_version"] == CALCULATION_VERSION
    assert r["weights_source"] == "default"


def test_default_weights_sum_to_one_and_cover_all_factors():
    weights, source = unified_weights()
    assert source == "default"
    assert set(weights) == set(UNIFIED_FACTORS)
    assert abs(sum(weights.values()) - 1.0) < 1e-6


def test_env_weights_reweight_and_renormalize(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_RISK_WEIGHTS", '{"pqc": 0.50}')
    weights, source = unified_weights()
    assert source == "env:CRYPTOSCAN_RISK_WEIGHTS"
    assert weights["pqc"] == 0.50
    assert abs(sum(weights.values()) - 1.0) < 1e-6
    # default pqc weight is 0.16, so the score for pqc=4 must now be higher
    r = unified_risk({"pqc": 4})
    assert r["factors"]["pqc"]["weight"] == 0.50
    assert r["score"] == 50.0


def test_env_weights_invalid_falls_back_wholly(monkeypatch):
    for bad in ('{"no_such_factor": 1.0}', "not json", '["list"]', '{"pqc": -1}', "{}", '{"pqc": "x"}'):
        monkeypatch.setenv("CRYPTOSCAN_RISK_WEIGHTS", bad)
        weights, source = unified_weights()
        assert source == "default", bad
        assert weights["pqc"] == UNIFIED_FACTORS["pqc"][1]


def test_explicit_weights_argument_overrides(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_RISK_WEIGHTS", '{"pqc": 0.90}')
    r = unified_risk({"pqc": 4}, weights={"pqc": 1.0})
    assert r["weights_source"] == "caller"
    assert r["score"] == 100.0

