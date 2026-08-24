from pathlib import Path

from policy.core.engine import PolicyEngine


def test_evaluator_loads_four_baseline_rules():
    engine = PolicyEngine(str(Path(__file__).resolve().parents[1].parent / "rule_definitions"))
    counts = engine.get_rule_count()
    assert counts["enabled"] >= 4
