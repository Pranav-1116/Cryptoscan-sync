"""Quantum planning: Mosca inequality, migration workstreams and waves, CLI."""

from __future__ import annotations

import json
from datetime import date

from quantum.__main__ import main as cli_main
from quantum.plan import _family, build_migration_plan, mosca
from quantum.risk import analyze_quantum_risk


# --------------------------------------------------------------------------- #
# Mosca's inequality: x + y > z
# --------------------------------------------------------------------------- #

def test_mosca_already_late():
    result = mosca(retention_years=10, migration_years=1, today=date(2026, 8, 28))
    assert result["computable"] is True
    assert result["verdict"] == "ALREADY_LATE"  # x=10 >= z=4 no matter how fast you migrate
    assert result["z_years_to_crqc"] == 4
    assert result["slack_years"] == round(4 - 10 - 1, 2)


def test_mosca_at_risk_and_safe_margin():
    at_risk = mosca(retention_years=2, migration_years=5, today=date(2026, 1, 1))
    assert at_risk["verdict"] == "AT_RISK"  # 2 + 5 > 4
    assert at_risk["slack_years"] == -3.0
    safe = mosca(retention_years=1, migration_years=1, today=date(2026, 1, 1))
    assert safe["verdict"] == "SAFE_MARGIN"  # 1 + 1 < 4
    assert safe["slack_years"] == 2.0


def test_mosca_unknown_margin_without_migration_estimate():
    result = mosca(retention_years=2, migration_years=None, today=date(2026, 1, 1))
    assert result["verdict"] == "UNKNOWN_MARGIN"  # x fits, y not provided — honest
    assert result["y_migration_years"] is None
    assert "?" in result["inequality"]


def test_mosca_not_computable_without_retention():
    result = mosca(retention_years=None)
    assert result["computable"] is False
    assert "no retention data" in result["reason"]
    assert result["z_years_to_crqc"] >= 0


def test_mosca_custom_threat_year():
    result = mosca(retention_years=2, migration_years=1, threat_year=2035, today=date(2026, 1, 1))
    assert result["z_years_to_crqc"] == 9
    assert result["verdict"] == "SAFE_MARGIN"


def test_mosca_boundary_is_at_risk_not_late():
    # x == z exactly: shelf-life ends exactly at CRQC -> already late (data outlives nothing)
    assert mosca(retention_years=4, migration_years=0, today=date(2026, 1, 1))["verdict"] == "ALREADY_LATE"
    # x + y == z exactly: no slack left -> at risk
    assert mosca(retention_years=3, migration_years=1, today=date(2026, 1, 1))["verdict"] == "AT_RISK"


# --------------------------------------------------------------------------- #
# family mapping
# --------------------------------------------------------------------------- #

def test_family_grouping():
    assert _family("RSA-2048") == "RSA"
    assert _family("rsa") == "RSA"
    assert _family("ECDSA-P256") == "ECC"
    assert _family("X25519") == "ECC"
    assert _family("Diffie-Hellman") == "DH"
    assert _family("ML-KEM-768") == "PQC"
    assert _family("AES-128") == "AES"
    assert _family("SHA-256") == "SHA"
    assert _family("3DES") == "LEGACY"
    assert _family("scrypt") == "OTHER"


# --------------------------------------------------------------------------- #
# migration plan
# --------------------------------------------------------------------------- #

def _findings():
    return [
        {"algorithm": "RSA-2048", "key_size": 2048, "purpose": "KEY_EXCHANGE", "file_path": "src/a.py", "line_number": 1, "system_id": "pay"},
        {"algorithm": "ECDSA-P256", "purpose": "SIGNATURE", "file_path": "src/b.py", "line_number": 2, "system_id": "pay"},
        {"algorithm": "AES-128", "purpose": "ENCRYPTION", "file_path": "src/c.py", "line_number": 3, "system_id": "db"},
        {"algorithm": "ML-KEM-768", "file_path": "src/d.py", "line_number": 4, "system_id": "pay"},
        {"algorithm": "AES-256-GCM", "file_path": "src/e.py", "line_number": 5, "system_id": "db"},
    ]


def _systems():
    return [
        {"id": "pay", "criticality": "TIER-1", "extra": {"data_retention_years": 10}},
        {"id": "db", "extra": {"data_retention_years": 2}},
    ]


def test_plan_inventory_counts():
    plan = build_migration_plan(_findings(), systems=_systems(), today=date(2026, 8, 28))
    inv = plan["inventory"]
    assert inv["total_sites"] == 5
    assert inv["vulnerable_sites"] == 3  # RSA + ECDSA + AES-128
    assert inv["pqc_ready_sites"] == 0
    assert inv["pqc_candidate_sites"] == 1
    assert inv["by_family"] == {"AES": 2, "ECC": 1, "PQC": 1, "RSA": 1}
    assert inv["by_threat_type"]["SHOR_VULNERABLE"] == 2
    assert inv["by_threat_type"]["GROVER_WEAKENED"] == 1
    assert inv["by_threat_type"]["PQC_RESISTANT"] == 1


def test_plan_workstreams_grouped_by_replacement_target():
    plan = build_migration_plan(_findings(), systems=_systems(), today=date(2026, 8, 28))
    streams = plan["workstreams"]
    targets = [stream["target"] for stream in streams]
    assert "ML-KEM-768" in targets and "ML-DSA-65" in targets and "AES-256" in targets
    assert streams[0]["priority"] == "P1"  # highest max_score first
    kem = next(stream for stream in streams if stream["target"] == "ML-KEM-768")
    assert kem["sites"][0]["algorithm"] == "RSA-2048"
    assert kem["systems"] == ["pay"]
    assert kem["priority"] in {"P1", "P2"}
    dsa = next(stream for stream in streams if stream["target"] == "ML-DSA-65")
    assert dsa["sites"][0]["algorithm"] == "ECDSA-P256"
    # sorted: P1 before P2 before P3
    priorities = [stream["priority"] for stream in streams]
    assert priorities == sorted(priorities)


def test_plan_waves_hndl_first():
    plan = build_migration_plan(_findings(), systems=_systems(), today=date(2026, 8, 28))
    waves = plan["waves"]
    # RSA key exchange is harvestable -> wave1; ECDSA signature still requires
    # authenticity migration -> wave2; AES-128 sizing remains wave3.
    assert waves["1"]["site_count"] == 1
    assert {site["algorithm"] for site in waves["1"]["sites"]} == {"RSA-2048"}
    assert waves["2"]["site_count"] == 1
    assert waves["2"]["sites"][0]["algorithm"] == "ECDSA-P256"
    assert waves["3"]["site_count"] == 1
    assert waves["3"]["sites"][0]["algorithm"] == "AES-128"
    assert "harvest" in waves["1"]["focus"]


def test_plan_mosca_uses_longest_retention():
    plan = build_migration_plan(
        _findings(), systems=_systems(), migration_years=2, today=date(2026, 8, 28)
    )
    assert plan["mosca"]["computable"] is True
    assert plan["mosca"]["x_shelf_life_years"] == 10  # the longest retention governs
    assert plan["mosca"]["verdict"] == "ALREADY_LATE"


def test_plan_mosca_honest_without_retention_data():
    plan = build_migration_plan(_findings(), systems=None, today=date(2026, 8, 28))
    assert plan["mosca"]["computable"] is False
    assert "no retention data" in plan["mosca"]["reason"]


def test_plan_summary_and_version():
    plan = build_migration_plan(_findings(), systems=_systems(), today=date(2026, 8, 28))
    assert "3 of 5 sites are migration-review candidates" in plan["summary"]
    assert plan["calculation_version"].endswith("+plan")
    # risk report stays intact underneath
    report = analyze_quantum_risk(_findings(), systems=_systems(), today=date(2026, 8, 28))
    assert report["vulnerable_count"] == plan["inventory"]["vulnerable_sites"]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_cli_plan_with_mosca(tmp_path, capsys):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps({"findings": _findings(), "systems": _systems()}))
    assert (
        cli_main(
            [str(path), "--plan", "--migration-years", "2", "--retention-years", "10", "-o", str(tmp_path / "out.json")]
        )
        == 0
    )
    result = json.loads((tmp_path / "out.json").read_text())
    assert result["inventory"]["vulnerable_sites"] == 3
    assert result["waves"]["1"]["site_count"] == 1
    captured = capsys.readouterr()
    assert "vulnerable=3/5" in captured.err
    assert "mosca: ALREADY_LATE" in captured.err


def test_cli_risk_report_by_default(tmp_path, capsys):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(_findings()))
    assert cli_main([str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert "overall_hndl_risk" in result and "assets" in result


def test_summary_does_not_label_classically_weak_migration_sites_as_all_shor():
    result = build_migration_plan([{"id": "legacy", "algorithm": "3DES"}])
    assert result["inventory"]["by_threat_type"] == {"CLASSICALLY_BROKEN": 1}
    assert "migration-review" in result["summary"]


def test_mosca_human_explanation_is_also_an_assumption_not_a_forecast():
    from datetime import date
    from quantum.plan import mosca
    result = mosca(retention_years=12, migration_years=None, today=date(2026, 10, 24), threat_year=2030)
    assert "assumption" in result["explanation"].lower()
    assert "estimated CRQC arrival" not in result["explanation"]
