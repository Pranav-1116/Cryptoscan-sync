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


# Regression (SNB-profile e2e, 2026-09): the normaliser writes the *display* name "TLS 1.0" into
# normalized_crypto.algorithm and "TLS1.0" into standard_name. BASELINE-005 lists "TLS1.0", so every
# TLS 1.0 / 1.1 / SSLv3 endpoint PASSed policy purely because of a space. Matching is now spelling-insensitive
# across display name, standard name, the evidence column and the scanner's own finding_data name.
def test_display_name_with_space_still_matches_rule_list():
    evidence = {
        "algorithm": "TLS 1.0",
        "normalized_crypto": {"algorithm": "TLS 1.0", "standard_name": "TLS1.0"},
    }
    outcome = AlgorithmInListCondition().evaluate(evidence, {"algorithm_list": ["SSLv3", "TLS1.0", "TLS1.1"]})
    assert outcome.result == "FAIL"


def test_scanner_spelling_in_finding_data_matches():
    evidence = {"algorithm": "Triple DES", "normalized_crypto": {}, "finding_data": {"crypto": {"algorithm": "DESede"}}}
    outcome = AlgorithmInListCondition().evaluate(evidence, {"algorithm_list": ["3DES", "DES"]})
    assert outcome.result == "FAIL"


def test_spelling_insensitive_does_not_over_match():
    evidence = {"algorithm": "TLS 1.2", "normalized_crypto": {"algorithm": "TLS 1.2", "standard_name": "TLS1.2"}}
    assert AlgorithmInListCondition().evaluate(evidence, {"algorithm_list": ["TLS1.0", "TLS1.1"]}).result == "PASS"
    assert AlgorithmInListCondition().evaluate({"algorithm": "SHA-256"}, {"algorithm_list": ["SHA-1", "SHA1"]}).result == "PASS"
