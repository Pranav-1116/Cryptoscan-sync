from drift.core.detector import DriftDetector


def test_new_weak_algo_is_critical(detector: DriftDetector):
    result = detector.detect_drift(
        baseline_findings=[],
        current_findings=[{"algorithm": "DES", "file_path": "A.java", "line_number": 1, "purpose": "ENCRYPTION"}],
        baseline_scan_id="b",
        current_scan_id="c",
    )
    assert result.total_changes == 1
    assert result.changes[0].severity == "CRITICAL"
    assert result.changes[0].change_type == "NEW"
