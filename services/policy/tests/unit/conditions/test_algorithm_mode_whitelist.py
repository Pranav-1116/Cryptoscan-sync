from policy.conditions.algorithm_mode_whitelist import AlgorithmModeWhitelistCondition


def test_ecb_forbidden():
    outcome = AlgorithmModeWhitelistCondition().evaluate(
        {"algorithm": "AES", "mode": "ECB"},
        {"algorithm": "AES", "approved_modes": ["GCM"], "forbidden_modes": ["ECB"]},
    )
    assert outcome.result == "FAIL"


def test_gcm_approved():
    outcome = AlgorithmModeWhitelistCondition().evaluate(
        {"algorithm": "AES", "mode": "GCM"},
        {"algorithm": "AES", "approved_modes": ["GCM", "CTR"], "forbidden_modes": ["ECB"]},
    )
    assert outcome.result == "PASS"
