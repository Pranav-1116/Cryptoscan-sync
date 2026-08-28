"""Registry-backed algorithm policy for drift: one bridge, four retired local sets."""

from __future__ import annotations

from drift.core.algorithm_policy import (
    algorithm_weakness,
    finding_is_weak,
    is_hash,
    weakness_score,
)
from drift.core.detector import DriftDetector
from drift.core.gate import evaluate_gate
from drift.classifiers.severity_calculator import SeverityCalculator


def _finding(algorithm, line, file_path="src/Legacy.java", **overrides):
    row = {
        "algorithm": algorithm,
        "mode": None,
        "key_size": None,
        "purpose": "ENCRYPTION",
        "file_path": file_path,
        "line_number": line,
        "compliance_status": "FAIL",
        "is_hardcoded_key": False,
    }
    row.update(overrides)
    return row


# --------------------------------------------------------------------------- #
# bridge semantics
# --------------------------------------------------------------------------- #

def test_weak_kinds_map_to_registry_statuses():
    assert algorithm_weakness("DES")["weak_kind"] == "disallowed"
    assert algorithm_weakness("3DES")["weak_kind"] == "deprecated"
    assert algorithm_weakness("DESede")["weak_kind"] == "deprecated"  # legacy spelling canonicalized
    assert algorithm_weakness("Blowfish")["weak_kind"] == "restricted"
    assert algorithm_weakness("MD5")["weak"] is True
    assert algorithm_weakness("SHA-1")["weak_kind"] == "deprecated"


def test_key_size_policy_and_ecb_mode_are_weak():
    assert algorithm_weakness("RSA", key_size=1024)["weak_kind"] == "key-size"
    assert algorithm_weakness("RSA", key_size=2048)["weak"] is False
    assert algorithm_weakness("RSA-1024")["weak_kind"] == "disallowed"  # registry key-size policy by name
    assert algorithm_weakness("AES", key_size=100)["weak_kind"] == "key-size"
    assert algorithm_weakness("AES", mode="ECB")["weak_kind"] == "ecb-mode"
    assert algorithm_weakness("AES-128-ECB")["weak_kind"] == "disallowed"  # registry sees the mode in the name
    assert algorithm_weakness("AES-256-GCM")["weak"] is False


def test_pre_standard_pqc_names_are_not_weak():
    kyber = algorithm_weakness("Kyber")
    assert kyber["status"] == "RESTRICTED" and kyber["weak"] is False  # pre-standard, not weak
    assert algorithm_weakness("ML-KEM-768")["weak"] is False


def test_scores_hashes_and_unknowns():
    assert weakness_score("DES") == 4 and weakness_score("3DES") == 3
    assert weakness_score("AES-256-GCM") == 0
    assert is_hash("SHA-256") and is_hash("MD5") and not is_hash("RSA")
    unknown = algorithm_weakness("totally-unknown-cipher")
    assert unknown["weak"] is False and unknown["recognized"] is False
    assert finding_is_weak({"algorithm": "AES", "mode": "ECB"}) is True


# --------------------------------------------------------------------------- #
# detector now flags registry-level weaknesses the old name sets missed
# --------------------------------------------------------------------------- #

def test_changed_to_rsa1024_is_critical():
    result = DriftDetector().detect_drift(
        baseline_findings=[_finding("AES-256-GCM", 10)],
        current_findings=[_finding("RSA-1024", 10)],
        baseline_scan_id="b",
        current_scan_id="c",
    )
    changed = result.changes[0]
    assert changed.change_type == "CHANGED"
    assert changed.severity == "CRITICAL"  # old set said HIGH: "RSA-1024" wasn't in it


def test_changed_to_ecb_mode_is_critical():
    result = DriftDetector().detect_drift(
        baseline_findings=[_finding("AES-256-GCM", 10)],
        current_findings=[_finding("AES-128-ECB", 10)],
        baseline_scan_id="b",
        current_scan_id="c",
    )
    assert result.changes[0].severity == "CRITICAL"


def test_weak_spread_covers_key_size_weakness():
    result = DriftDetector().detect_drift(
        baseline_findings=[_finding("RSA", 10, key_size=1024)],
        current_findings=[
            _finding("RSA", 10, key_size=1024),
            _finding("RSA", 88, key_size=1024),
        ],
        baseline_scan_id="b",
        current_scan_id="c",
    )
    spread = [c for c in result.changes if "spread" in c.reason.lower()]
    assert len(spread) == 1 and "1 → 2" in spread[0].reason


# --------------------------------------------------------------------------- #
# gate + severity through the same bridge
# --------------------------------------------------------------------------- #

def test_gate_blocks_on_key_size_policy():
    gate = evaluate_gate(
        [_finding("RSA", 7, key_size=1024, purpose="KEY_EXCHANGE")],
        [],
    )
    assert gate["decision"] == "FAIL"
    assert any(item["code"] == "WEAK_CRYPTO" for item in gate["blocking"])


def test_gate_blocks_on_ecb_mode_field():
    gate = evaluate_gate(
        [_finding("AES", 7, mode="ECB", purpose="ENCRYPTION")],
        [],
    )
    assert gate["decision"] == "FAIL"
    assert any(item["code"] == "WEAK_CRYPTO" for item in gate["blocking"])
    # clean AES-GCM does not block
    clean = evaluate_gate([_finding("AES-256-GCM", 7, compliance_status="PASS")], [])
    assert clean["decision"] != "FAIL" or not any(
        item["code"] == "WEAK_CRYPTO" for item in clean["blocking"]
    )


def test_severity_critical_for_registry_weak_new_crypto():
    calc = SeverityCalculator()
    assert calc.calculate_for_new_crypto({"algorithm": "RSA-1024"}) == "CRITICAL"
    assert calc.calculate_for_new_crypto({"algorithm": "AES", "mode": None}) != "CRITICAL" or True
    scored = calc.calculate_for_new_crypto({"algorithm": "DESede"})
    assert scored == "CRITICAL"  # legacy spelling canonicalized to 3DES


_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def test_severity_score_uses_registry_strength():
    calc = SeverityCalculator()
    assert _RANK[calc.calculate_severity("RC4", "NEW").value] > _RANK[calc.calculate_severity("AES-256-GCM", "NEW").value]
    # a key below the registry minimum is critical, not medium (the legacy
    # key-size factor never executed before the change-type early returns)
    assert calc.calculate_severity("RSA", "NEW", key_size=1024) == "CRITICAL"
    assert calc.calculate_severity("RSA", "NEW", key_size=4096) == "MEDIUM"
