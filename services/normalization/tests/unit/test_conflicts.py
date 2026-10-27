"""Observation conflict detection — the three conflict classes (audit 50)."""

from __future__ import annotations

from normalization.conflicts import (
    ALGORITHM_MISMATCH,
    PARAMETER_MISMATCH,
    STATUS_MISMATCH,
    detect_conflicts,
    detect_cross_scan_conflicts,
)


def _f(algorithm, file_path="src/App.java", line=10, status="PASS", **extra):
    return {"algorithm": algorithm, "file_path": file_path, "line_number": line,
            "compliance_status": status, "key_size": extra.get("key_size"),
            "mode": extra.get("mode"), "scanner_ids": extra.get("scanner_ids", [])}


def test_agreeing_observers_are_not_a_conflict():
    rows = [_f("RSA", key_size=2048, scanner_ids=["java-scanner"]),
            _f("RSA", key_size=2048, scanner_ids=["binary-scanner"])]
    assert detect_conflicts(rows) == []


def test_algorithm_mismatch_same_site():
    rows = [_f("RSA", scanner_ids=["java-scanner"]), _f("ECDSA", scanner_ids=["binary-scanner"])]
    out = detect_conflicts(rows)
    assert len(out) == 1
    assert out[0]["conflict_type"] == ALGORITHM_MISMATCH
    assert out[0]["algorithms"] == ["ECDSA", "RSA"]
    assert set(out[0]["observers"]) == {"java-scanner", "binary-scanner"}


def test_parameter_mismatch_same_algorithm():
    rows = [_f("RSA", key_size=1024, scanner_ids=["a"]),
            _f("RSA", key_size=2048, scanner_ids=["b"])]
    out = detect_conflicts(rows)
    assert out[0]["conflict_type"] == PARAMETER_MISMATCH
    assert out[0]["parameter_variants"] == [
        {"key_size": 1024, "mode": None}, {"key_size": 2048, "mode": None}]


def test_mode_variants_conflict_too():
    rows = [_f("AES", mode="CBC"), _f("AES", mode="GCM")]
    out = detect_conflicts(rows)
    assert out[0]["conflict_type"] == PARAMETER_MISMATCH


def test_status_mismatch_is_the_last_resort():
    rows = [_f("RSA-2048", status="PASS", scanner_ids=["a"]),
            _f("RSA-2048", status="FAIL", scanner_ids=["b"])]
    out = detect_conflicts(rows)
    assert out[0]["conflict_type"] == STATUS_MISMATCH
    assert out[0]["compliance_statuses"] == ["FAIL", "PASS"]


def test_different_sites_never_conflict():
    rows = [_f("RSA", line=10), _f("ECDSA", line=11)]
    assert detect_conflicts(rows) == []


def test_site_less_observations_are_skipped():
    assert detect_conflicts([{"algorithm": "RSA", "line_number": 1},
                             {"algorithm": "ECDSA", "line_number": 1}]) == []


def test_cross_scan_conflict_names_both_sides():
    baseline = [_f("RSA", key_size=2048)]
    current = [_f("RSA", key_size=1024)]
    out = detect_cross_scan_conflicts(baseline, current,
                                      baseline_scan_id="scan-1", current_scan_id="scan-2")
    assert len(out) == 1
    assert out[0]["conflict_type"] == PARAMETER_MISMATCH
    assert out[0]["baseline_scan_id"] == "scan-1"
    assert out[0]["current_scan_id"] == "scan-2"


def test_cross_scan_appearance_is_not_a_conflict():
    # site only in the new scan is drift, not disagreement
    out = detect_cross_scan_conflicts([], [_f("RSA", key_size=1024)],
                                      baseline_scan_id="s1", current_scan_id="s2")
    assert out == []
