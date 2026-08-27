"""Agility upgrades: factor details/signals, structured recs, PQC exposure,
readiness blockers/checklist/effort, roadmap sequencing, portfolio trend."""

from __future__ import annotations

from agility.readiness import assess_readiness
from agility.roadmap import build_roadmap, portfolio_trend, wave_for
from agility.system_score import (
    calculate_agility_score,
    classify_quantum,
    collect_signals,
    pqc_exposure,
)


def _modern_system():
    evidence = [
        {
            "algorithm": "AES",
            "file_path": "config/crypto.yaml",
            "finding_data": {"metadata": {"library": "aws_kms", "confidence_reason": "config-driven"}},
        }
    ]
    system = {
        "environment": "KUBERNETES",
        "extra": {
            "kms": True, "configmap": True, "hot_reload": True,
            "crypto_tests": True, "parameterized_crypto_tests": True,
            "has_crypto_docs": True, "has_crypto_inventory_docs": True,
            "has_dr_plan": True, "key_management": "AWS_KMS",
        },
    }
    return evidence, system


def _legacy_system():
    evidence = [
        {
            "algorithm": "DES",
            "file_path": "src/PaymentService.java",
            "is_hardcoded_key": True,
            "finding_data": {"metadata": {"confidence_reason": "literal-api"}},
        }
        for _ in range(6)
    ]
    system = {"extra": {"no_tests": True, "static_binary": True, "secrets_in_git": True}}
    return evidence, system


# --------------------------------------------------------------------------- #
# factor details + structured recommendations
# --------------------------------------------------------------------------- #

def test_factor_details_cover_all_six_factors_with_statuses():
    result = calculate_agility_score(*_modern_system())
    details = result["factor_details"]
    assert [d["key"] for d in details] == [f"factor{i}" for i in range(1, 7)]
    assert [d["name"] for d in details][0] == "Algorithm Configurability"
    by_key = {d["key"]: d for d in details}
    assert by_key["factor1"]["maximum"] == 30 and by_key["factor5"]["maximum"] == 35
    assert by_key["factor1"]["score"] == result["factor_scores"]["factor1"]
    assert 0.0 <= by_key["factor1"]["utilization"] <= 1.0
    assert by_key["factor1"]["status"] == "OK"  # modern system: 30/30
    legacy = calculate_agility_score(*_legacy_system())
    legacy_by_key = {d["key"]: d for d in legacy["factor_details"]}
    assert legacy_by_key["factor2"]["status"] == "CRITICAL"  # negative score


def test_factor_status_bands():
    empty = calculate_agility_score([], None)
    by_key = {d["key"]: d for d in empty["factor_details"]}
    # empty evidence: factor1 short-circuits to 20/30 = 0.667 -> OK band
    assert by_key["factor1"]["status"] == "OK"
    # factor6 = 0/35 (no docs at all) -> CRITICAL band without going negative
    assert by_key["factor6"]["status"] == "CRITICAL"
    # evidence present but no KMS hints: factor2 = 10/30 -> AT_RISK band
    hinted = calculate_agility_score([{"algorithm": "AES", "file_path": "src/a.py"}], None)
    by_key = {d["key"]: d for d in hinted["factor_details"]}
    assert by_key["factor2"]["status"] == "AT_RISK"


def test_recommendations_carry_numeric_impact_and_estimate_is_numeric():
    legacy = calculate_agility_score(*_legacy_system())
    recs = legacy["recommendations"]
    assert recs and all("impact_points" in r and "factor_key" in r for r in recs)
    expected = min(100, legacy["agility_score"] + sum(r["impact_points"] for r in recs))
    assert legacy["estimated_final_score"] == expected
    assert legacy["calculation_version"] == "agility-v1.1"


def test_legacy_recommendation_factors_are_referenced():
    legacy = calculate_agility_score(*_legacy_system())
    keys = {r["factor_key"] for r in legacy["recommendations"]}
    assert "factor1" in keys and "factor2" in keys  # hardcoded algorithms + keys


# --------------------------------------------------------------------------- #
# factor signals (audit trail)
# --------------------------------------------------------------------------- #

def test_signals_on_modern_fixture():
    evidence, system = _modern_system()
    signals = collect_signals(evidence, system)
    assert signals["total_sites"] == 1
    assert signals["config_file_hits"] == 1
    assert signals["hardcoded_key_sites"] == 0
    assert signals["distinct_algorithms"] == ["AES"]
    assert signals["kms_hint"] == "aws_kms"
    assert signals["hot_reload"] is True
    assert "has_crypto_docs" in signals["doc_flags"] and "has_dr_plan" in signals["doc_flags"]
    assert signals["secrets_in_git"] is False


def test_signals_on_legacy_fixture():
    evidence, system = _legacy_system()
    signals = collect_signals(evidence, system)
    assert signals["hardcoded_key_sites"] == 6
    assert signals["hardcoded_reason_sites"] == 6
    assert signals["max_algorithm_reuse"] == 6  # 6x DES = scattered
    assert signals["secrets_in_git"] is True
    assert signals["test_hits"] == 0


def test_signals_survive_none_system():
    signals = collect_signals([{"algorithm": "RSA", "file_path": "src/a.py"}], None)
    assert signals["doc_flags"] == [] and signals["kms_hint"] is None


# --------------------------------------------------------------------------- #
# PQC exposure indicators (never feed the score)
# --------------------------------------------------------------------------- #

def test_classify_quantum():
    assert classify_quantum("RSA-2048") == "QUANTUM_VULNERABLE"
    assert classify_quantum("ECDSA-P256") == "QUANTUM_VULNERABLE"
    assert classify_quantum("X25519") == "QUANTUM_VULNERABLE"
    assert classify_quantum("AES-256-GCM") == "QUANTUM_RESISTANT"
    assert classify_quantum("HMAC-SHA256") == "QUANTUM_RESISTANT"
    assert classify_quantum("scrypt") == "UNKNOWN"
    assert classify_quantum("") == "UNKNOWN"


def test_pqc_exposure_counts_and_honest_unknown():
    evidence = [
        {"algorithm": "RSA-2048"},
        {"algorithm": "RSA-4096"},
        {"algorithm": "AES-256-GCM"},
        {"algorithm": "ChaCha20-Poly1305"},
        {"algorithm": "scrypt"},
    ]
    exposure = pqc_exposure(evidence)
    assert exposure["quantum_vulnerable_sites"] == 2
    assert exposure["quantum_vulnerable_algorithms"] == ["RSA-2048", "RSA-4096"]
    assert "AES-256-GCM" in exposure["quantum_resistant_algorithms"]
    assert exposure["unknown_algorithms"] == ["scrypt"]
    assert exposure["hybrid_support"] is None  # no signal -> unknown, not False
    assert exposure["hybrid_signals"] is None


def test_pqc_hybrid_detected_from_library():
    evidence = [
        {"algorithm": "RSA-2048", "finding_data": {"metadata": {"library": "oqs-mlkem"}}},
    ]
    exposure = pqc_exposure(evidence)
    assert exposure["hybrid_support"] is True
    assert "mlkem" in exposure["hybrid_signals"]


def test_pqc_exposure_does_not_change_agility_score():
    plain = calculate_agility_score([{"algorithm": "AES", "file_path": "config/crypto.yaml"}], None)
    pqc = calculate_agility_score(
        [
            {"algorithm": "RSA-2048", "file_path": "config/crypto.yaml"},
            {"algorithm": "AES", "file_path": "config/crypto.yaml"},
        ],
        None,
    )
    # scores may differ because sites differ; the pqc block itself carries no weight
    assert plain["pqc_exposure"]["quantum_vulnerable_sites"] == 0
    assert pqc["pqc_exposure"]["quantum_vulnerable_sites"] == 1
    assert set(plain["factor_scores"]) == set(pqc["factor_scores"])


# --------------------------------------------------------------------------- #
# readiness: blockers, checklist, effort bands
# --------------------------------------------------------------------------- #

def test_readiness_blockers():
    blocked = assess_readiness(
        agility_score=10, dependency_count=20, has_crypto_tests=False, team_capacity="LOW", change_freeze=True
    )
    codes = {b["code"] for b in blocked["blockers"]}
    assert codes == {"AGILITY_TOO_LOW", "NO_CRYPTO_TEST_SAFETY_NET", "DEPENDENCY_SPRAWL", "FROZEN_CHANGE_WINDOW"}
    assert blocked["prep_checklist"]


def test_readiness_ready_now_has_no_blockers_or_checklist():
    ready = assess_readiness(agility_score=95, dependency_count=0, has_crypto_tests=True, team_capacity="HIGH")
    assert ready["readiness_category"] == "READY_NOW"
    assert ready["blockers"] == []
    assert ready["prep_checklist"] == []
    assert ready["estimated_effort_weeks"] == {"min": 0, "max": 1, "estimate": True}


def test_readiness_effort_bands():
    prep = assess_readiness(agility_score=70, dependency_count=2, has_crypto_tests=True)
    assert prep["readiness_category"] == "READY_WITH_PREP"
    assert prep["estimated_effort_weeks"]["min"] == 2 and prep["estimated_effort_weeks"]["max"] == 4
    not_ready = assess_readiness(agility_score=45, dependency_count=8)
    assert not_ready["readiness_category"] == "NOT_READY"
    assert not_ready["estimated_effort_weeks"]["min"] == 8


def test_readiness_checklist_mentions_crypto_tests_when_missing():
    result = assess_readiness(agility_score=55, has_crypto_tests=False)
    assert any("crypto test suite" in item for item in result["prep_checklist"])


# --------------------------------------------------------------------------- #
# roadmap: deterministic wave sequencing
# --------------------------------------------------------------------------- #

def _entry(system_id, name, agility, readiness, category, deps=0):
    return {
        "system_id": system_id, "system": name, "agility_score": agility,
        "readiness_score": readiness, "readiness_category": category, "dependency_count": deps,
    }


def test_roadmap_groups_and_orders_within_waves():
    roadmap = build_roadmap(
        [
            _entry("a", "alpha", 30, 30, "BLOCKED", deps=20),
            _entry("b", "bravo", 90, 90, "READY_NOW"),
            _entry("c", "charlie", 92, 88, "READY_NOW"),
            _entry("d", "delta", 20, 15, "BLOCKED", deps=3),
            _entry("e", "echo", 50, 55, "NOT_READY"),
        ]
    )
    assert roadmap["total_systems"] == 5
    assert roadmap["wave_order"] == [1, 2, 3]
    wave1 = roadmap["waves"]["1"]
    assert [row["system_id"] for row in wave1] == ["b", "c"]  # readiness 90 > 88
    assert wave1[0]["position"] == 1
    wave3 = roadmap["waves"]["3"]
    assert [row["system_id"] for row in wave3] == ["a", "d"]  # readiness 30 > 15
    assert "20 dependencies" in wave3[0]["rationale"]
    assert "sequencing" in roadmap


def test_roadmap_is_deterministic_with_ties():
    entries = [
        _entry("x", "same", 50, 60, "NOT_READY"),
        _entry("y", "same", 50, 60, "NOT_READY"),
        _entry("z", "same", 50, 60, "NOT_READY"),
    ]
    first = build_roadmap(entries)
    second = build_roadmap(reversed(entries))
    ids_first = [r["system_id"] for r in first["waves"]["2"]]
    ids_second = [r["system_id"] for r in second["waves"]["2"]]
    assert ids_first == ids_second  # tie broken by system_id, order-independent input


def test_wave_for_defaults_to_three():
    assert wave_for("READY_NOW") == 1
    assert wave_for("NOT_READY") == 2
    assert wave_for("BLOCKED") == 3
    assert wave_for(None) == 3
    assert wave_for("SOMETHING_NEW") == 3


# --------------------------------------------------------------------------- #
# portfolio trend
# --------------------------------------------------------------------------- #

def test_portfolio_trend_buckets():
    trend = portfolio_trend(
        [
            {"system_id": "a", "agility_score": 60, "previous_agility_score": 40},
            {"system_id": "b", "agility_score": 30, "previous_agility_score": 45},
            {"system_id": "c", "agility_score": 50, "previous_agility_score": 50},
            {"system_id": "d", "agility_score": 70, "previous_agility_score": None},
            {"system_id": "e", "agility_score": None, "previous_agility_score": 10},
        ]
    )
    assert trend["improving"] == 1
    assert trend["declining"] == 1
    assert trend["flat"] == 1
    assert trend["no_history"] == 2
    assert trend["deltas"] == {"a": 20, "b": -15, "c": 0}


def test_portfolio_trend_empty():
    assert portfolio_trend([]) == {"improving": 0, "declining": 0, "flat": 0, "no_history": 0, "deltas": {}}
