from normalization.matchers.pattern_matcher import PatternMatcher


def test_aes_gcm_pattern():
    matched = PatternMatcher().match("AES/GCM/NoPadding")
    assert matched is not None
    assert matched.algorithm == "AES"
    assert matched.mode == "GCM"
