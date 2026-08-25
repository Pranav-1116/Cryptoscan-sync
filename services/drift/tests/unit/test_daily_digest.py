from drift.alerts.daily_digest import build_digest


def test_digest_summarizes_open_events():
    digest = build_digest(
        [
            {
                "severity": "HIGH",
                "drift_type": "NEW",
                "resolution_status": "OPEN",
                "drift_details": {"algorithm": "DES"},
            },
            {
                "severity": "INFO",
                "drift_type": "REMOVED",
                "resolution_status": "RESOLVED",
                "drift_details": {"algorithm": "MD5"},
            },
        ]
    )
    assert digest["total"] == 2
    assert digest["open"] == 1
    assert digest["by_severity"]["HIGH"] == 1
    assert "DES" in digest["text"]
    assert digest["subject"].startswith("[HIGH]")
