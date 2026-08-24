from policy.conditions.algorithm_in_list import AlgorithmInListCondition


def test_forbidden_algorithm_fails():
    outcome = AlgorithmInListCondition().evaluate(
        {"algorithm": "MD5"}, {"algorithm_list": ["DES", "MD5"]}
    )
    assert outcome.result == "FAIL"


def test_approved_algorithm_passes():
    outcome = AlgorithmInListCondition().evaluate(
        {"algorithm": "AES"}, {"algorithm_list": ["DES", "MD5"]}
    )
    assert outcome.result == "PASS"
