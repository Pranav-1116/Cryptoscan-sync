"""Normalization tests — FallbackHandler + rule validator (untested modules)."""

from __future__ import annotations

from pathlib import Path

import pytest

from normalization.matchers.fallback_handler import FallbackHandler
from normalization.rules.rule_validator import RuleValidationError, RuleValidator


class TestFallbackHandler:
    def test_unknown_algorithm_flagged(self):
        result = FallbackHandler().handle("AES-UNKNOWN-MODE", context={"mode": "XTS"})
        assert result.algorithm == "UNKNOWN"
        assert result.algorithm_family == "unknown"
        assert result.standard_name == "AES-UNKNOWN-MODE"
        assert result.mode == "XTS"

    def test_context_merging(self):
        result = FallbackHandler().handle(
            "MYSTERY", context={"mode": "CBC"},
            purpose="ENCRYPTION", key_size=256)
        assert result.purpose == "ENCRYPTION"
        assert result.key_size == 256
        assert result.mode == "CBC"

    def test_version_and_timestamp_annotations(self):
        result = FallbackHandler().handle(
            "X", context={}, normalization_version="2.0",
            timestamp="2026-01-01T00:00:00Z")
        assert result.normalization_version == "2.0"
        assert result.normalization_timestamp == "2026-01-01T00:00:00Z"

    def test_no_context_ok(self):
        result = FallbackHandler().handle("WEIRD")
        assert result.algorithm == "UNKNOWN"
        assert result.mode is None


class TestRuleValidator:
    def _good_rule(self) -> dict:
        return {
            "rule_id": "ALG-AES",
            "version": "1.0",
            "raw_patterns": ["AES-256-GCM", "aes-256-gcm"],
            "normalized_output": {
                "algorithm": "AES-256-GCM",
                "algorithm_family": "aead",
                "standard_name": "AES-256-GCM",
            },
        }

    def test_valid_file_passes(self, tmp_path):
        path = tmp_path / "aes.yaml"
        path.write_text("rule_id: ALG-AES\nversion: '1.0'\nraw_patterns:\n  - AES-256-GCM\n"
                        "normalized_output:\n  algorithm: AES-256-GCM\n"
                        "  algorithm_family: aead\n  standard_name: AES-256-GCM\n",
                        encoding="utf-8")
        rules = RuleValidator().validate_file(path)
        assert len(rules) == 1
        rule = rules[0]
        assert rule.rule_id == "ALG-AES"
        assert rule.normalized_output["algorithm"] == "AES-256-GCM"
        # dataclass constructor mirrors raw_patterns → pattern
        assert rule.pattern == "AES-256-GCM"

    def test_multi_document_file_returns_each_rule(self, tmp_path):
        path = tmp_path / "multi.yaml"
        path.write_text(
            "rule_id: ALG-AES\nversion: '1.0'\nraw_patterns:\n  - AES-256-GCM\n"
            "normalized_output:\n  algorithm: AES-256-GCM\n  algorithm_family: aead\n"
            "  standard_name: AES-256-GCM\n"
            "---\n"
            "rule_id: ALG-MD5\nversion: '1.0'\nraw_patterns:\n  - MD5\n"
            "normalized_output:\n  algorithm: MD5\n  algorithm_family: hash\n"
            "  standard_name: MD5\n",
            encoding="utf-8")
        rules = RuleValidator().validate_file(path)
        assert [r.rule_id for r in rules] == ["ALG-AES", "ALG-MD5"]

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(RuleValidationError, match="does not exist"):
            RuleValidator().validate_file(tmp_path / "nope.yaml")

    def test_bad_extension_raises(self, tmp_path):
        path = tmp_path / "rule.txt"
        path.write_text("{}", encoding="utf-8")
        with pytest.raises(RuleValidationError, match="extension"):
            RuleValidator().validate_file(path)

    def test_missing_required_keys_raises(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("rule_id: X\nversion: '1'\n", encoding="utf-8")
        with pytest.raises(RuleValidationError, match="raw_patterns"):
            RuleValidator().validate_file(path)

    def test_empty_raw_patterns_raises(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text(
            "rule_id: X\nversion: '1'\nraw_patterns: []\nnormalized_output:\n"
            "  algorithm: A\n  algorithm_family: f\n  standard_name: A\n",
            encoding="utf-8")
        with pytest.raises(RuleValidationError):
            RuleValidator().validate_file(path)

    def test_missing_output_keys_raises(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text(
            "rule_id: X\nversion: '1'\nraw_patterns:\n  - A\nnormalized_output:\n"
            "  algorithm: A\n", encoding="utf-8")
        with pytest.raises(RuleValidationError, match="algorithm_family"):
            RuleValidator().validate_file(path)

    def test_invalid_yaml_raises(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("rule_id: [unclosed", encoding="utf-8")
        with pytest.raises(RuleValidationError, match="YAML parse error"):
            RuleValidator().validate_file(path)

    def test_validate_directory_collects_errors(self, tmp_path):
        (tmp_path / "good.yaml").write_text(
            "rule_id: ALG-AES\nversion: '1.0'\nraw_patterns:\n  - AES-256-GCM\n"
            "normalized_output:\n  algorithm: AES-256-GCM\n  algorithm_family: aead\n"
            "  standard_name: AES-256-GCM\n", encoding="utf-8")
        (tmp_path / "bad.yaml").write_text("rule_id: [broken", encoding="utf-8")
        with pytest.raises(RuleValidationError, match="failed validation"):
            RuleValidator().validate_directory(tmp_path)

    def test_validate_directory_skips_underscore(self, tmp_path):
        (tmp_path / "_schema.yaml").write_text("rule_id: X\nversion: '1'\n", encoding="utf-8")
        assert RuleValidator().validate_directory(tmp_path) == []

    def test_real_rule_definitions_validate(self):
        rules_dir = Path(__file__).resolve().parents[1] / "rule_definitions"
        if not rules_dir.exists():
            pytest.skip("normalization rule_definitions not present")
        rules = RuleValidator().validate_directory(rules_dir)
        assert len(rules) >= 5
        ids = {r.rule_id for r in rules}
        assert "NORM-MD5" in ids
        assert any(rid.startswith("NORM-RSA") for rid in ids)
