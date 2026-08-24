def test_des_fails_baseline_001(engine):
    result = engine.evaluate({"algorithm": "DES", "is_hardcoded_key": False})
    assert result.overall_status == "FAIL"
    assert "BASELINE-001" in result.failed_rule_ids()
