"""Policy rules infrastructure tests — loader, registry, validator."""

from __future__ import annotations

from pathlib import Path

import pytest

from policy.models.policy_rule import (
    Condition,
    PolicyRule,
    PolicyRuleSet,
    RuleType,
    Severity,
)
from policy.rules.rule_loader import RuleLoader
from policy.rules.rule_registry import RuleRegistry
from policy.rules.rule_validator import RuleValidator


_DEFAULT_PARAMS: dict = {"algorithm_list": ["MD5"]}


def _rule(rule_id: str = "TEST-001", *, enabled: bool = True,
          condition_type: str = "ALGORITHM_IN_LIST",
          parameters: dict | None = None, severity: str = "HIGH") -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        rule_name=f"Rule {rule_id}",
        version="1.0",
        effective_date="2024-01-01",
        severity=Severity(severity),
        standard_reference="test",
        description="A test rule",
        condition=Condition(
            type=condition_type,
            parameters=_DEFAULT_PARAMS if parameters is None else parameters,
        ),
        evaluation={"result_template": "FAIL"},
        remediation="fix it",
        enabled=enabled,
    )


class TestRuleLoader:
    def test_loads_yaml_rules_from_dir(self, tmp_path):
        (tmp_path / "TEST-001.yaml").write_text(
            "rule_id: TEST-001\nrule_name: Forbidden MD5\nversion: 1.0\n"
            "effective_date: 2024-01-01\nseverity: CRITICAL\n"
            "standard_reference: internal\ndescription: no md5\n"
            "condition:\n  type: ALGORITHM_IN_LIST\n  parameters:\n"
            "    algorithm_list: [MD5]\nevaluation:\n  result_template: FAIL\n"
            "remediation: use sha256\nenabled: true\n", encoding="utf-8")
        rules = RuleLoader(tmp_path).load_all_rules()
        assert len(rules) == 1
        assert rules[0].rule_id == "TEST-001"
        assert rules[0].severity == Severity.CRITICAL
        assert rules[0].enabled is True

    def test_skips_underscore_files_and_dirs(self, tmp_path):
        (tmp_path / "_private.yaml").write_text("rule_id: X", encoding="utf-8")
        (tmp_path / "_schema").mkdir()
        (tmp_path / "_schema" / "template.yaml").write_text("rule_id: T", encoding="utf-8")
        (tmp_path / "VALID-001.yaml").write_text(
            "rule_id: VALID-001\nrule_name: ok\nversion: 1.0\nseverity: LOW\n"
            "description: ok\ncondition:\n  type: ALGORITHM_IN_LIST\n  parameters:\n"
            "    algorithm_list: [RC4]\nevaluation:\n  result_template: FAIL\n"
            "remediation: ok\nenabled: true\n", encoding="utf-8")
        rules = RuleLoader(tmp_path).load_all_rules()
        assert [r.rule_id for r in rules] == ["VALID-001"]

    def test_missing_dir_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            RuleLoader(tmp_path / "missing")

    def test_broken_yaml_skipped_not_crash(self, tmp_path):
        (tmp_path / "BROKEN-001.yaml").write_text("rule_id: [unclosed", encoding="utf-8")
        (tmp_path / "GOOD-001.yaml").write_text(
            "rule_id: GOOD-001\nrule_name: ok\nversion: 1.0\nseverity: LOW\n"
            "description: ok\ncondition:\n  type: ALGORITHM_IN_LIST\n  parameters:\n"
            "    algorithm_list: [DES]\nevaluation:\n  result_template: FAIL\n"
            "remediation: ok\nenabled: true\n", encoding="utf-8")
        rules = RuleLoader(tmp_path).load_all_rules()
        assert [r.rule_id for r in rules] == ["GOOD-001"]

    def test_loads_real_baseline_definitions(self):
        real_dir = Path(__file__).resolve().parents[2] / "rule_definitions" / "baseline"
        if not real_dir.exists():
            pytest.skip("baseline rule_definitions not present")
        rules = RuleLoader(real_dir).load_all_rules()
        assert len(rules) >= 4
        ids = {r.rule_id for r in rules}
        assert "BASELINE-001" in ids and "BASELINE-004" in ids


class TestRuleRegistry:
    def test_indexes_by_id_and_severity(self):
        registry = RuleRegistry([_rule("TEST-001", severity="HIGH"),
                                 _rule("TEST-002", severity="CRITICAL"),
                                 _rule("TEST-003", severity="HIGH", enabled=False)])
        assert registry.get_rule("TEST-002").rule_id == "TEST-002"
        assert registry.get_rule("MISSING") is None
        assert len(registry.get_rules_by_severity(Severity.HIGH)) == 2
        assert len(registry.get_rules_by_severity(Severity.CRITICAL)) == 1
        assert registry.count_rules() == 3
        assert registry.count_rules(enabled_only=True) == 2
        assert len(registry.get_enabled_rules()) == 2
        assert len(registry.get_all_rules()) == 3


class TestRuleValidator:
    def test_valid_rule_passes(self):
        assert RuleValidator().validate(_rule()) is True

    def test_missing_rule_id_raises(self):
        with pytest.raises(ValueError, match="rule_id"):
            RuleValidator().validate(_rule(rule_id=""))

    def test_missing_description_raises(self):
        rule = _rule()
        rule.description = None
        with pytest.raises(ValueError, match="description"):
            RuleValidator().validate(rule)

    def test_algorithm_in_list_requires_nonempty_list(self):
        with pytest.raises(ValueError, match="algorithm_list"):
            RuleValidator().validate(_rule(parameters={"algorithm_list": []}))
        # missing parameters entirely → parameters required
        with pytest.raises(ValueError, match="parameters"):
            RuleValidator().validate(_rule(parameters={}))

    def test_key_size_minimum_validation(self):
        good = _rule(condition_type="KEY_SIZE_MINIMUM",
                     parameters={"algorithm": "RSA", "minimum_key_size": 2048})
        assert RuleValidator().validate(good) is True
        with pytest.raises(ValueError, match="minimum_key_size"):
            RuleValidator().validate(_rule(
                condition_type="KEY_SIZE_MINIMUM",
                parameters={"algorithm": "RSA", "minimum_key_size": 0}))

    def test_id_format_warns_but_passes(self):
        assert RuleValidator().validate(_rule(rule_id="lowercase-1")) is True


class TestRuleSetIntegration:
    def test_rule_set_filters_enabled(self):
        rules = [_rule("TEST-001"), _rule("TEST-002", enabled=False)]
        rule_set = PolicyRuleSet(rules=rules)
        assert [r.rule_id for r in rule_set.get_enabled_rules()] == ["TEST-001"]
