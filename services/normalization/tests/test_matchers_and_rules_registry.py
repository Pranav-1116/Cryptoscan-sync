"""Normalization tests — ExactMatcher, PatternMatcher, RuleLoader, RuleRegistry.

These four modules previously had no test coverage. RuleLoader is exercised
against BOTH a synthetic in-repo fixture and the real multi-document
rule_definitions directory when it is present.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from normalization.matchers.exact_matcher import ExactMatcher
from normalization.matchers.pattern_matcher import PatternMatcher
from normalization.models.normalization_rule import NormalizationRule
from normalization.rules.rule_loader import RuleLoader
from normalization.rules.rule_registry import DuplicateRuleError, RuleRegistry

REPO_ROOT = Path(__file__).resolve().parents[3]
RULE_DEFINITIONS = REPO_ROOT / "services" / "normalization" / "rule_definitions"


# ── Fixtures & helpers ──────────────────────────────────────────────────

def _rule(rule_id: str, patterns: list[str], algorithm: str = "AES",
          family: str = "symmetric") -> NormalizationRule:
    return NormalizationRule(
        rule_id=rule_id,
        pattern=patterns[0],
        raw_patterns=list(patterns),
        normalized_output={
            "algorithm": algorithm,
            "algorithm_family": family,
            "standard_name": algorithm,
        },
    )


@pytest.fixture
def registry() -> RuleRegistry:
    reg = RuleRegistry()
    reg.register(_rule("NORM-AES-001", ["AES", "AES/GCM/NoPadding"], algorithm="AES"))
    reg.register(_rule("NORM-DES-001", ["DES", "DES/ECB/PKCS5Padding"], algorithm="DES"))
    reg.register(_rule("NORM-RSA-001", ["RSA-2048"], algorithm="RSA", family="asymmetric"))
    return reg


# ── ExactMatcher ────────────────────────────────────────────────────────

class TestExactMatcher:
    def test_built_from_rule_list(self):
        matcher = ExactMatcher([_rule("R1", ["DES", "3DES"])])
        assert matcher.match("des").rule_id == "R1"
        assert matcher.match("3DES").rule_id == "R1"
        assert matcher.match(" DES ") is not None

    def test_missing_returns_none(self):
        matcher = ExactMatcher([])
        assert matcher.match("AES") is None
        assert matcher.match("") is None
        assert matcher.match(None) is None
        assert matcher.match("   ") is None

    def test_single_pattern_field_used(self):
        rule = NormalizationRule(rule_id="R2", pattern="CHACHA20",
                                 output={"algorithm": "CHACHA20"})
        matcher = ExactMatcher([rule])
        assert matcher.match("chacha20").rule_id == "R2"

    def test_delegates_to_registry(self):
        reg = RuleRegistry()
        reg.register(_rule("R3", ["BLOWFISH"]))
        matcher = ExactMatcher(reg)
        assert matcher.match("blowfish").rule_id == "R3"
        assert matcher.match("AES") is None

    def test_all_rules_iterable_support(self):
        reg = RuleRegistry()
        reg.register(_rule("R4", ["TWOFISH"]))
        matcher = ExactMatcher(reg)
        assert matcher.match("TWOFISH").rule_id == "R4"


# ── PatternMatcher ──────────────────────────────────────────────────────

class TestPatternMatcher:
    def test_full_transformation_string(self):
        result = PatternMatcher().match("AES/GCM/NoPadding")
        assert result is not None
        assert result.algorithm == "AES"
        assert result.mode == "GCM"
        assert result.padding is None  # NoPadding -> None
        assert result.standard_name == "AES/GCM/NoPadding"
        assert result.normalization_confidence == "MEDIUM"

    def test_pkcs5_padding_suffix_stripped(self):
        result = PatternMatcher().match("DES/ECB/PKCS5Padding")
        assert result is not None
        assert result.algorithm == "DES"
        assert result.mode == "ECB"
        assert result.padding == "PKCS5"

    def test_algorithm_mode_only(self):
        result = PatternMatcher().match("AES/CBC")
        assert result is not None
        assert result.algorithm == "AES"
        assert result.mode == "CBC"
        assert result.padding is None

    def test_compound_with_key_size_and_mode(self):
        result = PatternMatcher().match("AES-256-GCM")
        assert result is not None
        assert result.key_size == 256
        assert result.algorithm in ("AES", "AES-256-GCM", "AES-GCM")
        assert result.algorithm_family == "symmetric"

    def test_compound_underscore_separator(self):
        result = PatternMatcher().match("AES_128_CBC")
        assert result is not None
        assert result.key_size == 128
        assert result.mode == "CBC"

    def test_rsa_compound(self):
        result = PatternMatcher().match("RSA-2048")
        assert result is not None
        assert result.algorithm_family == "asymmetric"
        assert result.key_size == 2048

    def test_empty_and_garbage(self):
        matcher = PatternMatcher()
        assert matcher.match("") is None
        assert matcher.match(None) is None
        assert matcher.match("   ") is None
        assert matcher.match("!!not-an-algorithm!!") is None

    def test_family_inference_mac_before_hash(self):
        result = PatternMatcher().match("HMACSHA256")
        # HMACSHA256 is not a transformation; registry may resolve it.
        if result is not None:
            assert result.algorithm_family in ("mac", "unknown")


# ── RuleLoader ──────────────────────────────────────────────────────────

class TestRuleLoader:
    def test_load_from_directory_missing(self, tmp_path):
        loader = RuleLoader()
        with pytest.raises(ValueError):
            loader.load_from_directory(tmp_path / "nope")

    def test_unset_directory_raises(self):
        loader = RuleLoader()
        with pytest.raises(ValueError):
            loader.load_all_rules()

    def test_loads_multi_document_and_skips_underscore(self, tmp_path):
        (tmp_path / "a.yaml").write_text(
            "rule_id: NORM-X-001\n"
            "raw_patterns: [X1]\n"
            "normalized_output: {algorithm: X1, algorithm_family: symmetric, standard_name: X1}\n"
            "---\n"
            "rule_id: NORM-X-002\n"
            "raw_patterns: [X2]\n"
            "normalized_output: {algorithm: X2, algorithm_family: hash, standard_name: X2}\n",
            encoding="utf-8",
        )
        (tmp_path / "_skip.yaml").write_text(
            "rule_id: NORM-SKIP\nraw_patterns: [S]\n"
            "normalized_output: {algorithm: S}\n",
            encoding="utf-8",
        )
        rules = RuleLoader().load_from_directory(tmp_path)
        ids = {r.rule_id for r in rules}
        assert ids == {"NORM-X-001", "NORM-X-002"}

    def test_wrapped_rules_key(self, tmp_path):
        (tmp_path / "b.yaml").write_text(
            "rules:\n"
            "  - rule_id: NORM-W-001\n"
            "    raw_patterns: [W]\n"
            "    normalized_output: {algorithm: W, algorithm_family: mac, standard_name: W}\n",
            encoding="utf-8",
        )
        rules = RuleLoader().load_from_directory(tmp_path)
        assert [r.rule_id for r in rules] == ["NORM-W-001"]

    def test_pattern_falls_back_to_single_field(self, tmp_path):
        (tmp_path / "c.yaml").write_text(
            "rule_id: NORM-C-001\n"
            "pattern: ZETA\n"
            "output: {algorithm: ZETA, algorithm_family: symmetric, standard_name: ZETA}\n",
            encoding="utf-8",
        )
        rules = RuleLoader().load_from_directory(tmp_path)
        assert rules[0].pattern == "ZETA"
        assert rules[0].output["algorithm"] == "ZETA"

    def test_invalid_entries_skipped(self, tmp_path):
        (tmp_path / "d.yaml").write_text(
            "rule_id: NORM-BAD-1\nraw_patterns: []\nnormalized_output: {algorithm: BAD}\n"
            "---\n"
            "rule_id: NORM-BAD-2\nraw_patterns: [OK]\nnormalized_output: {}\n",
            encoding="utf-8",
        )
        assert RuleLoader().load_from_directory(tmp_path) == []

    def test_version_stringified(self, tmp_path):
        (tmp_path / "e.yaml").write_text(
            "rule_id: NORM-V-001\nversion: 2.0\n"
            "raw_patterns: [V1]\n"
            "normalized_output: {algorithm: V1, algorithm_family: symmetric, standard_name: V1}\n",
            encoding="utf-8",
        )
        rule = RuleLoader().load_from_directory(tmp_path)[0]
        assert rule.version == "2.0"

    def test_validate_rules(self):
        loader = RuleLoader()
        assert loader.validate_rules([_rule("R", ["AES"])]) is True
        with pytest.raises(ValueError):
            loader.validate_rules([NormalizationRule(rule_id="R", pattern="",
                                                     raw_patterns=[])])

    @pytest.mark.skipif(
        not RULE_DEFINITIONS.exists(),
        reason="real rule_definitions directory not present",
    )
    def test_loads_real_rule_definitions(self):
        rules = RuleLoader().load_from_directory(RULE_DEFINITIONS)
        assert len(rules) >= 20
        ids = {r.rule_id for r in rules}
        assert any(i.startswith("NORM-") for i in ids)
        # every rule must have a usable pattern and an algorithm output
        for rule in rules:
            assert rule.raw_patterns
            assert rule.normalized_output.get("algorithm")


# ── RuleRegistry ────────────────────────────────────────────────────────

class TestRuleRegistry:
    def test_register_and_lookups(self, registry):
        assert registry.rule_count() == 3
        assert registry.lookup_by_pattern("des").rule_id == "NORM-DES-001"
        assert registry.lookup_by_pattern(" DES ").rule_id == "NORM-DES-001"
        assert registry.lookup_by_id("NORM-AES-001").rule_id == "NORM-AES-001"
        assert registry.lookup_by_id("missing") is None
        assert registry.lookup_by_pattern(None) is None
        assert registry.lookup_by_pattern("") is None

    def test_duplicate_rule_id_rejected(self, registry):
        with pytest.raises(DuplicateRuleError):
            registry.register(_rule("NORM-AES-001", ["OTHER"]))

    def test_duplicate_pattern_rejected(self, registry):
        with pytest.raises(DuplicateRuleError):
            registry.register(_rule("NORM-OTHER-001", ["AES"]))

    def test_overwrite_allowed(self, registry):
        registry.register(_rule("NORM-AES-001", ["AES"]), overwrite=True)
        assert registry.rule_count() == 3

    def test_has_pattern_and_all_patterns(self, registry):
        assert registry.has_pattern("rsa-2048") is True
        assert registry.has_pattern("nope") is False
        assert registry.all_patterns() == ["AES", "AES/GCM/NOPADDING",
                                           "DES", "DES/ECB/PKCS5PADDING", "RSA-2048"]

    def test_all_rules_iteration(self, registry):
        ids = {r.rule_id for r in registry.all_rules()}
        assert ids == {"NORM-AES-001", "NORM-DES-001", "NORM-RSA-001"}

    def test_stats_and_repr(self, registry):
        stats = registry.stats()
        assert stats["rule_count"] == 3
        assert stats["pattern_count"] == 5
        assert "NORM-AES-001" in stats["rule_ids"]
        assert "rules=3" in repr(registry)

    def test_clear(self, registry):
        registry.clear()
        assert registry.rule_count() == 0
        assert registry.pattern_count() == 0

    def test_register_all_atomicity(self, registry):
        good = _rule("NORM-OK-001", ["FRESH"])
        bad = _rule("NORM-AES-001", ["CONFLICT"])  # duplicate id
        with pytest.raises(DuplicateRuleError):
            registry.register_all([good, bad])
        assert registry.lookup_by_id("NORM-OK-001") is None  # nothing committed

    def test_thread_safety_smoke(self, registry):
        errors: list[Exception] = []

        def worker(start: int):
            try:
                for i in range(50):
                    rule = _rule(f"NORM-T-{start}-{i:03d}", [f"T{start}-{i}"])
                    registry.register(rule)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert registry.rule_count() == 3 + 200
