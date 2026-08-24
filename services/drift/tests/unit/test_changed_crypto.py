from drift.core.detector import DriftDetector


def test_changed_algorithm_at_same_location():
    detector = DriftDetector()
    result = detector.detect_drift(
        baseline_findings=[
            {
                "algorithm": "AES",
                "mode": "GCM",
                "key_size": 256,
                "purpose": "ENCRYPTION",
                "file_path": "src/Pay.java",
                "line_number": 40,
            }
        ],
        current_findings=[
            {
                "algorithm": "DES",
                "mode": "ECB",
                "key_size": 56,
                "purpose": "ENCRYPTION",
                "file_path": "src/Pay.java",
                "line_number": 40,
            }
        ],
        baseline_scan_id="b",
        current_scan_id="c",
    )
    types = {change.change_type for change in result.changes}
    assert "CHANGED" in types
    assert "NEW" not in types
    assert "REMOVED" not in types
    assert result.changes[0].severity == "CRITICAL"


def test_same_location_key_upgrade():
    detector = DriftDetector()
    result = detector.detect_drift(
        baseline_findings=[
            {
                "algorithm": "RSA",
                "mode": None,
                "key_size": 1024,
                "purpose": "KEY_GENERATION",
                "file_path": "src/Keys.java",
                "line_number": 8,
            }
        ],
        current_findings=[
            {
                "algorithm": "RSA",
                "mode": None,
                "key_size": 2048,
                "purpose": "KEY_GENERATION",
                "file_path": "src/Keys.java",
                "line_number": 8,
            }
        ],
        baseline_scan_id="b",
        current_scan_id="c",
    )
    assert any(change.change_type == "UPGRADED" for change in result.changes)
