def test_rsa_1024_fails_baseline_002(engine):
    result = engine.evaluate({"algorithm": "RSA", "key_size": 1024, "is_hardcoded_key": False})
    assert result.overall_status == "FAIL"
    assert "BASELINE-002" in result.failed_rule_ids()
