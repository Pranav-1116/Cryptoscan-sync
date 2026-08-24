def test_hardcoded_key_fails_baseline_004(engine):
    result = engine.evaluate(
        {"algorithm": "AES", "mode": "GCM", "key_size": 256, "is_hardcoded_key": True}
    )
    assert result.overall_status == "FAIL"
    assert "BASELINE-004" in result.failed_rule_ids()
