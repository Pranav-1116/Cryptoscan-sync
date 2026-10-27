"""Sector context weights quantum (HNDL/PQC) risk deterministically."""

from __future__ import annotations

from quantum.risk import analyze_quantum_risk, score_asset

_FINDING = {"algorithm": "RSA", "key_size": 1024, "purpose": "SIGNING"}


def test_sector_weight_param_changes_score():
    base = score_asset(dict(_FINDING), system={})
    weighted = score_asset(dict(_FINDING), system={}, sector_criticality_weight=1.5)
    low = score_asset(dict(_FINDING), system={}, sector_criticality_weight=0.7)
    assert weighted["quantum_risk_score"] >= base["quantum_risk_score"]
    assert low["quantum_risk_score"] <= base["quantum_risk_score"]


def test_weight_is_clamped():
    assert score_asset(dict(_FINDING), system={}, sector_criticality_weight=99)["quantum_risk_score"] <= 100
    assert score_asset(dict(_FINDING), system={}, sector_criticality_weight=0.1)["quantum_risk_score"] >= 0


def test_analyze_uses_sector_and_marks_weighted():
    systems = [{
        "id": "s1", "name": "payment_hsm", "criticality": "MISSION_CRITICAL",
        "extra": {"environment": "production", "payment_path": True},
    }]
    finding = dict(_FINDING, system_id="s1", asset_type="payment_hsm")
    result = analyze_quantum_risk([finding], systems=systems, sector="banking")
    assert result["sector"] == "banking"
    assert result["sector_weighted"] is True
    # mission-critical payment HSM in banking is forced to top risk
    assert result["assets"][0]["risk_category"] in {"CRITICAL", "HIGH"}


def test_analyze_without_sector_still_works():
    result = analyze_quantum_risk([dict(_FINDING)])
    assert result["sector_weighted"] is False
    assert result["assets"][0]["quantum_risk_score"] >= 0
