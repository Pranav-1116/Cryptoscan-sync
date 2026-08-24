def test_aes_ecb_fails_baseline_003(engine):
    result = engine.evaluate({"algorithm": "AES", "mode": "ECB", "is_hardcoded_key": False})
    assert result.overall_status == "FAIL"
    assert "BASELINE-003" in result.failed_rule_ids()
