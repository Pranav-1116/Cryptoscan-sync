def test_unknown_algorithm_needs_review(engine):
    result = engine.normalize("FOOBAR-999")
    assert result.needs_human_review is True
    assert result.normalization_confidence == "LOW"
