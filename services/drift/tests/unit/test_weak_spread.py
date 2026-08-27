"""Weak-algorithm spread detection (new occurrences of an existing weak algo)."""

from drift.core.detector import DriftDetector


def _finding(algorithm, line, file_path="src/Legacy.java", **overrides):
    row = {
        "algorithm": algorithm,
        "mode": None,
        "key_size": None,
        "purpose": "HASH",
        "file_path": file_path,
        "line_number": line,
        "compliance_status": "FAIL",
        "is_hardcoded_key": False,
    }
    row.update(overrides)
    return row


def test_second_weak_occurrence_flags_spread():
    result = DriftDetector().detect_drift(
        baseline_findings=[_finding("MD5", 10)],
        current_findings=[_finding("MD5", 10), _finding("MD5", 88)],
        baseline_scan_id="b",
        current_scan_id="c",
    )
    spread = [c for c in result.changes if "spread" in c.reason.lower()]
    assert len(spread) == 1
    assert spread[0].change_type == "NEW"
    assert spread[0].severity == "HIGH"
    assert "MD5" in spread[0].reason
    assert "1 → 2" in spread[0].reason


def test_identical_inventory_has_no_spread_event():
    result = DriftDetector().detect_drift(
        baseline_findings=[_finding("MD5", 10), _finding("DES", 20)],
        current_findings=[_finding("MD5", 10), _finding("DES", 20)],
        baseline_scan_id="b",
        current_scan_id="c",
    )
    assert result.total_changes == 0


def test_strong_algorithm_growth_is_not_flagged():
    result = DriftDetector().detect_drift(
        baseline_findings=[_finding("AES", 10, purpose="ENCRYPTION")],
        current_findings=[
            _finding("AES", 10, purpose="ENCRYPTION"),
            _finding("AES", 42, purpose="ENCRYPTION"),
        ],
        baseline_scan_id="b",
        current_scan_id="c",
    )
    spread = [c for c in result.changes if "spread" in c.reason.lower()]
    assert spread == []


def test_shrinking_weak_usage_is_not_flagged():
    result = DriftDetector().detect_drift(
        baseline_findings=[_finding("MD5", 10), _finding("MD5", 88)],
        current_findings=[_finding("MD5", 10)],
        baseline_scan_id="b",
        current_scan_id="c",
    )
    spread = [c for c in result.changes if "spread" in c.reason.lower()]
    assert spread == []
    # The removed occurrence still surfaces (as REMOVED or MOVED), never as spread.
    assert result.total_changes == 1
    assert result.changes[0].change_type in {"REMOVED", "MOVED"}
