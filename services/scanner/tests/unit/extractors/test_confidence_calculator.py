from scanner.extractors.confidence_calculator import calculate_confidence


def test_literal_is_high():
    result = calculate_confidence(is_string_literal=True, is_from_local_variable=False, is_hardcoded=False)
    assert result.level.value == "HIGH"


def test_variable_is_medium():
    result = calculate_confidence(is_string_literal=False, is_from_local_variable=True, is_hardcoded=False)
    assert result.level.value == "MEDIUM"
