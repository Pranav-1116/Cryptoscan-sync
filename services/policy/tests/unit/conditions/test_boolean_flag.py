from policy.conditions.boolean_flag import BooleanFlagCondition


def test_hardcoded_key_fails():
    outcome = BooleanFlagCondition().evaluate(
        {"is_hardcoded_key": True},
        {"field": "is_hardcoded_key", "forbidden_value": True},
    )
    assert outcome.result == "FAIL"


def test_generated_key_passes():
    outcome = BooleanFlagCondition().evaluate(
        {"is_hardcoded_key": False},
        {"field": "is_hardcoded_key", "forbidden_value": True},
    )
    assert outcome.result == "PASS"
