"""
Unit tests for ExactMatcher.
Tests exact pattern lookup, case insensitivity, and miss handling.
"""

from __future__ import annotations

import pytest

from normalization.matchers.exact_matcher import ExactMatcher
from normalization.models.normalization_rule import NormalizationRule
from normalization.rules.rule_registry import RuleRegistry


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture()
def registry_with_rules() -> RuleRegistry:
    """Registry pre-loaded with representative rules."""
    registry = RuleRegistry()

    rules = [
        NormalizationRule(
            rule_id="NORM-AES-GCM-256",
            version="1.0",
            description="AES-256-GCM",
            raw_patterns=["AES/GCM/NoPadding", "AES-256-GCM"],
            normalized_output={
                "algorithm": "AES",
                "algorithm_family": "symmetric",
                "standard_name": "AES-256-GCM",
                "mode": "GCM",
                "padding": "NoPadding",
                "key_size": 256,
                "nist_designation": "APPROVED",
                "quantum_vulnerable": False,
            },
        ),
        NormalizationRule(
            rule_id="NORM-DES",
            version="1.0",
            description="DES",
            raw_patterns=["DES", "DES/ECB/PKCS5Padding"],
            normalized_output={
                "algorithm": "DES",
                "algorithm_family": "symmetric",
                "standard_name": "DES",
                "mode": "ECB",
                "padding": "PKCS5Padding",
                "key_size": 56,
                "nist_designation": "DISALLOWED",
                "quantum_vulnerable": True,
            },
        ),
        NormalizationRule(
            rule_id="NORM-SHA256",
            version="1.0",
            description="SHA-256",
            raw_patterns=["SHA-256", "SHA256"],
            normalized_output={
                "algorithm": "SHA2",
                "algorithm_family": "hash",
                "standard_name": "SHA-256",
                "output_bits": 256,
                "nist_designation": "APPROVED",
                "quantum_vulnerable": False,
            },
        ),
    ]

    for rule in rules:
        registry.register(rule)

    return registry


@pytest.fixture()
def matcher(registry_with_rules: RuleRegistry) -> ExactMatcher:
    return ExactMatcher(registry_with_rules)


# ── Tests: Successful Matches ─────────────────────────────────────────

class TestExactMatcherHits:
    def test_exact_match_aes_gcm(self, matcher: ExactMatcher) -> None:
        rule = matcher.match("AES/GCM/NoPadding")
        assert rule is not None
        assert rule.rule_id == "NORM-AES-GCM-256"

    def test_exact_match_aes_gcm_alias(self, matcher: ExactMatcher) -> None:
        rule = matcher.match("AES-256-GCM")
        assert rule is not None
        assert rule.rule_id == "NORM-AES-GCM-256"

    def test_exact_match_des(self, matcher: ExactMatcher) -> None:
        rule = matcher.match("DES")
        assert rule is not None
        assert rule.rule_id == "NORM-DES"
        assert rule.normalized_output["nist_designation"] == "DISALLOWED"

    def test_exact_match_des_ecb(self, matcher: ExactMatcher) -> None:
        rule = matcher.match("DES/ECB/PKCS5Padding")
        assert rule is not None
        assert rule.rule_id == "NORM-DES"

    def test_exact_match_sha256_hyphen(self, matcher: ExactMatcher) -> None:
        rule = matcher.match("SHA-256")
        assert rule is not None
        assert rule.rule_id == "NORM-SHA256"

    def test_exact_match_sha256_nohyphen(self, matcher: ExactMatcher) -> None:
        rule = matcher.match("SHA256")
        assert rule is not None
        assert rule.rule_id == "NORM-SHA256"


# ── Tests: Case Insensitivity ─────────────────────────────────────────

class TestExactMatcherCaseInsensitive:
    def test_lowercase_input(self, matcher: ExactMatcher) -> None:
        rule = matcher.match("des")
        assert rule is not None
        assert rule.rule_id == "NORM-DES"

    def test_mixed_case_input(self, matcher: ExactMatcher) -> None:
        rule = matcher.match("Des")
        assert rule is not None
        assert rule.rule_id == "NORM-DES"

    def test_all_caps_aes(self, matcher: ExactMatcher) -> None:
        rule = matcher.match("AES/GCM/NOPADDING")
        assert rule is not None
        assert rule.rule_id == "NORM-AES-GCM-256"


# ── Tests: Misses ─────────────────────────────────────────────────────

class TestExactMatcherMisses:
    def test_unknown_algorithm_returns_none(self, matcher: ExactMatcher) -> None:
        result = matcher.match("CustomCrypto")
        assert result is None

    def test_empty_string_returns_none(self, matcher: ExactMatcher) -> None:
        result = matcher.match("")
        assert result is None

    def test_partial_match_returns_none(self, matcher: ExactMatcher) -> None:
        # "AES" is not registered, only "AES/GCM/NoPadding"
        result = matcher.match("AES")
        assert result is None

    def test_whitespace_only_returns_none(self, matcher: ExactMatcher) -> None:
        result = matcher.match("   ")
        assert result is None


# ── Tests: Edge Cases ─────────────────────────────────────────────────

class TestExactMatcherEdgeCases:
    def test_leading_trailing_whitespace_stripped(self, matcher: ExactMatcher) -> None:
        rule = matcher.match("  DES  ")
        assert rule is not None
        assert rule.rule_id == "NORM-DES"

    def test_returns_correct_rule_object(self, matcher: ExactMatcher) -> None:
        rule = matcher.match("SHA-256")
        assert rule is not None
        assert rule.normalized_output["algorithm"] == "SHA2"
        assert rule.normalized_output["output_bits"] == 256

    def test_empty_registry(self) -> None:
        empty_registry = RuleRegistry()
        matcher = ExactMatcher(empty_registry)
        result = matcher.match("AES")
        assert result is None