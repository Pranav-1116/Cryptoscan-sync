"""Agility trajectory analysis, what-if simulation, and CLI."""

from __future__ import annotations

import json

from agility.__main__ import main as cli_main
from agility.simulation import available_actions, simulate_improvements
from agility.trajectory import analyze_history
from agility.system_score import calculate_agility_score


def _legacy_evidence():
    return [
        {
            "algorithm": "DES",
            "file_path": "src/PaymentService.java",
            "is_hardcoded_key": True,
            "finding_data": {"metadata": {"confidence_reason": "literal-api"}},
        }
        for _ in range(6)
    ]


def _legacy_system():
    return {"extra": {"no_tests": True, "static_binary": True, "secrets_in_git": True}}


# --------------------------------------------------------------------------- #
# trajectory
# --------------------------------------------------------------------------- #

def _row(score, *, factors=None, readiness=None):
    return {
        "calculated_at": f"2026-01-0{score % 9 + 1}T00:00:00",
        "agility_score": score,
        "category": "GOOD",
        "readiness_score": readiness,
        "factor_scores": factors,
    }


def test_trajectory_improving():
    result = analyze_history([_row(20), _row(35), _row(55)])
    assert result["trajectory"] == "IMPROVING"
    assert result["score_deltas"] == [15, 20]
    assert result["net_change"] == 35
    assert result["first_score"] == 20 and result["latest_score"] == 55
    assert result["best_score"] == 55 and result["worst_score"] == 20


def test_trajectory_declining_and_volatile_and_stable():
    assert analyze_history([_row(60), _row(50), _row(40)])["trajectory"] == "DECLINING"
    assert analyze_history([_row(30), _row(60), _row(20)])["trajectory"] == "VOLATILE"
    assert analyze_history([_row(45), _row(45)])["trajectory"] == "STABLE"


def test_trajectory_insufficient_data():
    result = analyze_history([_row(40)])
    assert result["trajectory"] == "INSUFFICIENT_DATA"
    assert result["score_deltas"] == [] and result["net_change"] is None
    assert analyze_history([])["trajectory"] == "INSUFFICIENT_DATA"


def test_trajectory_factor_deltas():
    rows = [
        _row(30, factors={"factor1": 5, "factor2": -20, "factor5": 0}),
        _row(50, factors={"factor1": 15, "factor2": -20, "factor5": 35}),
    ]
    result = analyze_history(rows)
    assert result["factor_deltas"] == {"factor1": 10, "factor2": 0, "factor5": 35}
    assert result["factors_improved"] == ["factor1", "factor5"]
    assert result["factors_regressed"] == []


def test_trajectory_factor_deltas_none_when_missing():
    rows = [_row(30), _row(50, factors={"factor1": 10})]  # first row has no factors
    assert analyze_history(rows)["factor_deltas"] is None
    rows = [_row(30, factors=None), _row(50)]  # explicit None, non-dict
    assert analyze_history(rows)["factor_deltas"] is None


# --------------------------------------------------------------------------- #
# simulation
# --------------------------------------------------------------------------- #

def test_simulation_uses_real_engine_and_reports_unsupported():
    sim = simulate_improvements(_legacy_evidence(), _legacy_system(), ["move_to_kms", "bogus_action"])
    assert sim["projection"] is True
    assert sim["actions_applied"] == ["move_to_kms"]
    assert sim["unsupported_actions"] == ["bogus_action"]  # never silently dropped
    assert len(sim["assumptions"]) == 1
    # KMS alone lifts factor2 by +20 (base 10 -> 30) but hardcoded keys still drag it
    assert sim["factor_deltas"]["factor2"] == 20
    assert sim["score_delta"] == sim["projected"]["agility_score"] - sim["current"]["agility_score"]


def test_simulation_full_remediation_rescues_legacy_system():
    sim = simulate_improvements(
        _legacy_evidence(),
        _legacy_system(),
        ["remove_hardcoded_keys", "move_to_kms", "centralize_wrapper", "externalize_config", "add_crypto_tests", "document_procedures", "enable_hot_reload"],
    )
    assert sim["unsupported_actions"] == []
    assert sim["projected"]["agility_score"] > sim["current"]["agility_score"]
    assert sim["projected"]["category"] in {"GOOD", "EXCELLENT", "MODERATE"}
    assert sim["factor_deltas"]["factor5"] == 45  # -10 -> 35
    assert all("assumes" in note for note in sim["assumptions"])


def test_simulation_kms_alone_is_not_enough_for_legacy():
    sim = simulate_improvements(_legacy_evidence(), _legacy_system(), ["move_to_kms", "add_crypto_tests"])
    # honest: keys still hardcoded + secrets in git keep the normalized score at 0
    assert sim["projected"]["agility_score"] == 0
    assert sim["factor_deltas"]["factor2"] > 0  # even though the factor improved


def test_simulation_does_not_mutate_inputs():
    evidence = _legacy_evidence()
    system = _legacy_system()
    simulate_improvements(evidence, system, ["remove_hardcoded_keys", "centralize_wrapper"])
    assert all(row["is_hardcoded_key"] for row in evidence)
    assert all("PaymentService" in row["file_path"] for row in evidence)
    assert system["extra"]["secrets_in_git"] is True


def test_simulation_is_deterministic():
    first = simulate_improvements(_legacy_evidence(), _legacy_system(), ["move_to_kms"])
    second = simulate_improvements(_legacy_evidence(), _legacy_system(), ["move_to_kms"])
    assert first == second


def test_available_actions_complete():
    assert set(available_actions()) == {
        "move_to_kms", "remove_hardcoded_keys", "centralize_wrapper",
        "externalize_config", "add_crypto_tests", "document_procedures", "enable_hot_reload",
    }


# --------------------------------------------------------------------------- #
# CLI (DB-free)
# --------------------------------------------------------------------------- #

def test_cli_scores_file(tmp_path, capsys):
    payload = {
        "evidence": [
            {"algorithm": "AES", "file_path": "config/crypto.yaml",
             "finding_data": {"metadata": {"library": "aws_kms", "confidence_reason": "config-driven"}}}
        ],
        "system": {"environment": "KUBERNETES", "extra": {"kms": True, "crypto_tests": True}},
    }
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(payload))
    assert cli_main([str(path)]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["agility_score"] >= 0
    assert result["factor_details"] and "pqc_exposure" in result
    assert "agility=" in captured.err and "version=agility-v1.1" in captured.err


def test_cli_accepts_bare_evidence_list_and_simulates(tmp_path, capsys):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(_legacy_evidence()))
    out = tmp_path / "result.json"
    assert cli_main([str(path), "-o", str(out), "--simulate", "move_to_kms,add_crypto_tests,nonsense"]) == 0
    result = json.loads(out.read_text())
    sim = result["simulation"]
    assert sim["actions_applied"] == ["move_to_kms", "add_crypto_tests"]
    assert sim["unsupported_actions"] == ["nonsense"]
    err = capsys.readouterr().err
    assert "projected=" in err and "delta=" in err
    assert "nonsense" in err  # unsupported actions surfaced on stderr


def test_cli_simulation_matches_library(tmp_path, capsys):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"evidence": _legacy_evidence(), "system": _legacy_system()}))
    cli_main([str(path), "--simulate", "remove_hardcoded_keys,move_to_kms"])
    result = json.loads(capsys.readouterr().out)
    direct = simulate_improvements(_legacy_evidence(), _legacy_system(), ["remove_hardcoded_keys", "move_to_kms"])
    assert result["simulation"]["projected"] == direct["projected"]
    # and the engine itself is untouched by CLI use
    assert calculate_agility_score(_legacy_evidence(), _legacy_system())["agility_score"] == 0
