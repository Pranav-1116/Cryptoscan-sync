def test_aes_256_gcm_passes_all(engine):
    result = engine.evaluate(
        {
            "algorithm": "AES",
            "mode": "GCM",
            "key_size": 256,
            "is_hardcoded_key": False,
        }
    )
    assert result.overall_status == "PASS"
    assert result.rules_failed == 0
