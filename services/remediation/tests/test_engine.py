"""Remediation engine: rule matching (exact + family prefix), priorities, backlog."""

from __future__ import annotations

import json

from remediation.__main__ import main as cli_main
from remediation.backlog import build_backlog
from remediation.engine import suggest_remediations


def _finding(algorithm, status="FAIL", **extra):
    return {"algorithm": algorithm, "compliance_status": status, "file_path": "a.java", "line_number": 4, **extra}


# --------------------------------------------------------------------------- #
# original contract stays intact
# --------------------------------------------------------------------------- #

def test_des_gets_aes_suggestion():
    report = suggest_remediations(
        [{"algorithm": "DES", "compliance_status": "FAIL", "file_path": "a.java", "line_number": 4}]
    )
    assert report["count"] == 1
    assert report["suggestions"][0]["replace_with"] == "AES-256-GCM"
    assert "policy engine" in report["disclaimer"]
    assert report["suggestions"][0]["label"] == "DETERMINISTIC SUGGESTION - NOT COMPLIANCE DETERMINATION"


# --------------------------------------------------------------------------- #
# family-prefix matching (the old exact table silently missed these)
# --------------------------------------------------------------------------- #

def test_versioned_algorithm_names_match_their_family_rule():
    report = suggest_remediations(
        [
            _finding("RSA-2048"),
            _finding("ECDSA-P256"),
            _finding("AES-128"),
            _finding("TLSv1.0"),
            _finding("SHA1"),
        ]
    )
    by_rule = {row["rule"]: row for row in report["suggestions"]}
    assert by_rule["plan-rsa-pqc"]["replace_with"] == "ML-KEM-768 / ML-DSA-65"
    assert by_rule["plan-rsa-pqc"]["effort"] == "high"
    assert by_rule["plan-ecc-pqc"]["replace_with"] == "ML-KEM-768 / ML-DSA-65"
    assert by_rule["resize-aes128"]["replace_with"] == "AES-256"
    assert by_rule["replace-tls10"]["replace_with"] == "TLS 1.3"
    assert by_rule["replace-sha1"]["replace_with"] == "SHA-256"


def test_ecb_mode_rule_fires_for_any_ecb_cipher():
    report = suggest_remediations([_finding("AES", mode="ECB")])
    row = report["suggestions"][0]
    assert row["rule"] == "fix-ecb-mode"
    assert row["category"] == "WEAK_MODE"
    assert row["priority"] == "P1"
    assert row["replace_with"] == "AES-256-GCM"


def test_pqc_algorithms_are_not_suggested_against():
    report = suggest_remediations([_finding("ML-KEM-768", status="PASS"), _finding("ML-DSA-65", status="PASS")])
    assert report["count"] == 0  # healthy algorithm, no status flag


def test_policy_flag_on_unknown_algorithm_falls_back_to_manual_review():
    report = suggest_remediations([_finding("scrypt")])
    assert report["count"] == 1
    row = report["suggestions"][0]
    assert row["rule"] == "manual-review"
    assert row["replace_with"] == "review"
    assert row["priority"] == "P3"


def test_policy_flag_on_pqc_algorithm_is_manual_review_not_pqc_plan():
    # the policy engine knows something the rule table does not — never override it
    report = suggest_remediations([_finding("ML-KEM-768")])
    assert report["suggestions"][0]["rule"] == "manual-review"


def test_healthy_unknown_finding_is_skipped():
    report = suggest_remediations([_finding("AES-256-GCM", status="PASS")])
    assert report["count"] == 0


def test_known_weak_algorithm_suggested_even_without_flag():
    report = suggest_remediations([_finding("RC4", status="PASS")])
    assert report["count"] == 1
    assert report["suggestions"][0]["rule"] == "replace-rc4"


# --------------------------------------------------------------------------- #
# ordering + rollups
# --------------------------------------------------------------------------- #

def test_suggestions_sorted_by_priority_then_location():
    report = suggest_remediations(
        [
            _finding("RSA", file_path="a.py", line_number=1),
            _finding("DES", file_path="z.py", line_number=9),
            _finding("RC4", file_path="b.py", line_number=2),
            _finding("SHA-1", file_path="a.py", line_number=1),
        ]
    )
    assert [row["rule"] for row in report["suggestions"]] == [
        "replace-rc4",  # P0, b.py
        "replace-des",  # P0, z.py
        "replace-sha1",  # P1
        "plan-rsa-pqc",  # P2
    ]
    assert report["by_priority"] == {"P0": 2, "P1": 1, "P2": 1, "P3": 0}
    assert report["rule_counts"] == {"replace-des": 1, "replace-rc4": 1, "replace-sha1": 1, "plan-rsa-pqc": 1}


def test_result_carries_backlog():
    report = suggest_remediations([_finding("DES"), _finding("DES", file_path="b.java")])
    assert report["backlog"]["total_sites"] == 2
    assert report["backlog"]["items"][0]["rule"] == "replace-des"


# --------------------------------------------------------------------------- #
# backlog module
# --------------------------------------------------------------------------- #

def test_backlog_groups_sites_per_rule_with_waves():
    suggestions = [
        {"rule": "replace-des", "category": "CLASSICALLY_BROKEN", "priority": "P0",
         "replace_with": "AES-256-GCM", "guidance": "g", "effort": "low",
         "evidence_id": "e1", "algorithm": "DES", "file_path": "a.py", "line_number": 1},
        {"rule": "replace-des", "category": "CLASSICALLY_BROKEN", "priority": "P0",
         "replace_with": "AES-256-GCM", "guidance": "g", "effort": "low",
         "evidence_id": "e2", "algorithm": "3DES", "file_path": "b.py", "line_number": 2},
        {"rule": "plan-rsa-pqc", "category": "PQC_TRANSITION", "priority": "P2",
         "replace_with": "ML-KEM-768 / ML-DSA-65", "guidance": "g", "effort": "high",
         "evidence_id": "e3", "algorithm": "RSA-2048", "file_path": "c.py", "line_number": 3},
    ]
    backlog = build_backlog(suggestions)
    assert backlog["total_rules"] == 2
    assert backlog["total_sites"] == 3
    assert [item["rule"] for item in backlog["items"]] == ["replace-des", "plan-rsa-pqc"]
    des = backlog["items"][0]
    assert des["site_count"] == 2 and len(des["sites"]) == 2
    assert des["wave"] == 1
    assert backlog["items"][1]["wave"] == 3
    assert backlog["waves"]["1"] == {"focus": "classically broken crypto — stop the bleed", "rule_count": 1, "site_count": 2}
    assert backlog["waves"]["3"]["site_count"] == 1


def test_backlog_orders_by_priority_then_site_count():
    suggestions = []
    for i in range(3):
        suggestions.append({"rule": "plan-rsa-pqc", "priority": "P2", "site": i, "evidence_id": f"r{i}"})
    for i in range(2):
        suggestions.append({"rule": "replace-tls10", "priority": "P1", "evidence_id": f"t{i}"})
    suggestions.append({"rule": "replace-sha1", "priority": "P1", "evidence_id": "s0"})
    backlog = build_backlog(suggestions)
    assert [item["rule"] for item in backlog["items"]] == ["replace-tls10", "replace-sha1", "plan-rsa-pqc"]


def test_backlog_empty_and_site_cap():
    empty = build_backlog([])
    assert empty["total_rules"] == 0 and empty["total_sites"] == 0
    assert empty["items"] == []
    many = [{"rule": "replace-des", "priority": "P0", "evidence_id": f"e{i}"} for i in range(250)]
    backlog = build_backlog(many)
    assert backlog["items"][0]["site_count"] == 250  # exact count
    assert len(backlog["items"][0]["sites"]) == 200  # capped listing
    assert "capped" in backlog["note"]


def test_backlog_is_deterministic():
    rows = [
        {"rule": "replace-rc4", "priority": "P0", "evidence_id": "a"},
        {"rule": "replace-des", "priority": "P0", "evidence_id": "b"},
    ]
    assert build_backlog(rows) == build_backlog(list(reversed(rows)))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_cli_emits_suggestions_and_backlog(tmp_path, capsys):
    path = tmp_path / "findings.json"
    path.write_text(
        '[{"algorithm": "DES", "compliance_status": "FAIL", "file_path": "a.java", "line_number": 4}]'
    )
    assert cli_main([str(path)]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["count"] == 1
    assert result["backlog"]["total_sites"] == 1
    assert "suggestions=1 p0=1" in captured.err
    assert "wave1_sites=1" in captured.err

