from pathlib import Path

from normalization.rules.rule_loader import RuleLoader


def test_loads_yaml_rules():
    loader = RuleLoader(str(Path(__file__).resolve().parents[1].parent / "rule_definitions"))
    rules = loader.load_all_rules()
    assert len(rules) >= 8
    assert any(rule.output.get("algorithm") == "AES" for rule in rules)
