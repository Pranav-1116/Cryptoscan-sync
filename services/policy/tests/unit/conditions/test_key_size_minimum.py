from policy.conditions.key_size_minimum import KeySizeMinimumCondition


def test_small_rsa_fails():
    outcome = KeySizeMinimumCondition().evaluate(
        {"algorithm": "RSA", "key_size": 1024},
        {"algorithm": "RSA", "minimum_key_size": 2048},
    )
    assert outcome.result == "FAIL"


def test_large_rsa_passes():
    outcome = KeySizeMinimumCondition().evaluate(
        {"algorithm": "RSA", "key_size": 4096},
        {"algorithm": "RSA", "minimum_key_size": 2048},
    )
    assert outcome.result == "PASS"


def test_other_algorithm_not_applicable():
    outcome = KeySizeMinimumCondition().evaluate(
        {"algorithm": "AES", "key_size": 128},
        {"algorithm": "RSA", "minimum_key_size": 2048},
    )
    assert outcome.result == "NOT_APPLICABLE"
