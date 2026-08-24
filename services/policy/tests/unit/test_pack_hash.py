from pathlib import Path

from policy.core.engine import PolicyEngine


def test_pack_hash_is_stable():
    rules = Path(__file__).resolve().parents[2] / "rule_definitions"
    engine = PolicyEngine(str(rules))
    first = engine.pack_hash()
    second = engine.pack_hash()
    assert first == second
    assert len(first) == 64
    descriptor = engine.pack_descriptor()
    assert descriptor["pack_hash"] == first
    assert descriptor["counts"]["enabled"] >= 1
