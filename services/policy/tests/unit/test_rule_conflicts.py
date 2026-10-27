"""Cross-rule conflict detection (audit 65 P0#1, round 27).

Tests the pure analyzer over synthetic rules covering every conflict
class, the scope gating that keeps multi-jurisdiction packs from
manufacturing false conflicts, plus the real shipped packs (which must
stay clean of duplicates/contradictions beyond the known entries).
"""

from __future__ import annotations

from policy.models.policy_rule import (AlgorithmInListParameters, Condition, Evaluation,
                                       KeySizeMinimumParameters, PolicyRule)
from policy.rules.rule_conflicts import detect_rule_conflicts


def _rule(rule_id: str, *, condition: Condition, severity: str = "HIGH",
          verdict: str = "FAIL", enabled: bool = True) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        rule_name=f"rule {rule_id}",
        severity=severity,
        condition=condition,
        evaluation=Evaluation(result_template=verdict),
        remediation="fix it",
        enabled=enabled,
    )


def _in_list(rule_id: str, algorithms: list[str], **kwargs) -> PolicyRule:
    return _rule(rule_id, condition=Condition(
        type="ALGORITHM_IN_LIST",
        parameters=AlgorithmInListParameters(algorithm_list=algorithms).model_dump(),
    ), **kwargs)


def _key_size(rule_id: str, algorithm: str, minimum: int, **kwargs) -> PolicyRule:
    return _rule(rule_id, condition=Condition(
        type="KEY_SIZE_MINIMUM",
        parameters=KeySizeMinimumParameters(algorithm=algorithm,
                                            minimum_key_size=minimum).model_dump(),
    ), **kwargs)


def _types(conflicts: list[dict]) -> list[str]:
    return [item["type"] for item in conflicts]


def _find(conflicts: list[dict], kind: str, a: str, b: str) -> dict | None:
    for item in conflicts:
        if item["type"] == kind and set(item["rules"]) == {a, b}:
            return item
    return None


def _find_shadowed(conflicts: list[dict], shadowed: str, shadower: str) -> dict | None:
    """SHADOWED entries are ordered [shadowed, shadower]."""
    for item in conflicts:
        if item["type"] == "SHADOWED" and item["rules"] == [shadowed, shadower]:
            return item
    return None


def test_no_conflicts_for_disjoint_rules():
    rules = [
        _in_list("A-1", ["DES", "RC4"]),
        _key_size("A-2", "RSA", 2048),
        _in_list("A-3", ["MD5"]),
    ]
    assert detect_rule_conflicts(rules) == []


def test_duplicate_rule_id_detected():
    rules = [_in_list("A-1", ["DES"]), _in_list("A-1", ["RC4"])]
    conflicts = detect_rule_conflicts(rules)
    assert _types(conflicts) == ["DUPLICATE_ID"]
    assert conflicts[0]["rules"] == ["A-1", "A-1"]


def test_exact_duplicate_conditions_different_ids():
    rules = [_in_list("A-1", ["DES", "RC4"], severity="CRITICAL"),
             _in_list("B-1", ["RC4", "DES"], severity="HIGH")]
    item = _find(detect_rule_conflicts(rules), "EXACT_DUPLICATE", "A-1", "B-1")
    assert item is not None


def test_identical_conditions_different_verdict_is_contradictory():
    rules = [_in_list("A-1", ["DES"], verdict="FAIL"),
             _in_list("B-1", ["DES"], verdict="PASS")]
    item = _find(detect_rule_conflicts(rules), "CONTRADICTORY", "A-1", "B-1")
    assert item is not None
    assert "FAIL vs PASS" in item["detail"]


def test_shadowing_by_superset_list_rule():
    # B-1 fires on everything A-1 does and is louder
    rules = [_in_list("A-1", ["TLS1.0"], severity="HIGH"),
             _in_list("B-1", ["DES", "TLS1.0"], severity="CRITICAL")]
    conflicts = detect_rule_conflicts(rules)
    item = _find(conflicts, "SHADOWED", "A-1", "B-1")
    assert item is not None
    assert "shadowed by B-1" in item["detail"]


def test_no_shadowing_when_shadower_is_not_louder():
    # A-1 (CRITICAL superset) legitimately shadows B-1 (LOW subset)...
    rules = [_in_list("A-1", ["DES", "TLS1.0"], severity="CRITICAL"),
             _in_list("B-1", ["TLS1.0"], severity="LOW")]
    conflicts = detect_rule_conflicts(rules)
    assert _find_shadowed(conflicts, "B-1", "A-1") is not None
    # ...but the reverse direction must never appear: a quieter, narrower
    # rule cannot shadow a louder, broader one
    assert _find_shadowed(conflicts, "A-1", "B-1") is None


def test_key_size_shadowing_weaker_minimum_covers_more():
    # A-2 (min 1024) fires on every RSA finding B-2 (min 2048) does
    rules = [_key_size("A-2", "RSA", 1024, severity="CRITICAL"),
             _key_size("B-2", "RSA", 2048, severity="HIGH")]
    item = _find(detect_rule_conflicts(rules), "SHADOWED", "B-2", "A-2")
    assert item is not None


def test_key_size_different_algorithms_do_not_overlap():
    rules = [_key_size("A-2", "RSA", 1024),
             _key_size("B-2", "ECDSA", 256)]
    assert detect_rule_conflicts(rules) == []


def test_list_rule_shadows_typed_rule_of_listed_algorithm():
    rules = [_in_list("A-1", ["RSA", "DES"], severity="CRITICAL"),
             _key_size("B-2", "RSA", 3072, severity="HIGH")]
    item = _find(detect_rule_conflicts(rules), "SHADOWED", "B-2", "A-1")
    assert item is not None


def test_partial_overlap_different_severities_is_overlapping():
    rules = [_in_list("A-1", ["DES", "RC4"], severity="CRITICAL"),
             _in_list("B-1", ["RC4", "MD5"], severity="MEDIUM")]
    item = _find(detect_rule_conflicts(rules), "OVERLAPPING", "A-1", "B-1")
    assert item is not None


def test_scoped_rules_are_compared_within_their_scope_regime():
    # same deny-list, different jurisdictions: NOT an exact duplicate
    scoped = _in_list("S-1", ["DES"])
    scoped.condition.parameters["required_scopes"] = ["SAMA"]
    rules = [_in_list("B-1", ["DES"]), scoped]
    assert detect_rule_conflicts(rules) == []


def test_unscoped_rule_shadows_scoped_rule():
    # the unscoped rule fires everywhere, including the scoped regime
    scoped = _in_list("S-1", ["TLS1.0"], severity="HIGH")
    scoped.condition.parameters["required_scopes"] = ["FIPS"]
    rules = [scoped, _in_list("B-1", ["DES", "TLS1.0"], severity="CRITICAL")]
    item = _find(detect_rule_conflicts(rules), "SHADOWED", "S-1", "B-1")
    assert item is not None


def test_scoped_rule_cannot_shadow_unscoped_rule():
    scoped = _in_list("S-1", ["DES", "TLS1.0"], severity="CRITICAL")
    scoped.condition.parameters["required_scopes"] = ["SAMA"]
    rules = [scoped, _in_list("B-1", ["TLS1.0"], severity="HIGH")]
    # S-1 only fires on SAMA-scoped findings; it cannot shadow a rule
    # that fires everywhere
    assert detect_rule_conflicts(rules) == []


def test_disabled_rules_are_excluded():
    rules = [_in_list("A-1", ["DES"]),
             _in_list("B-1", ["DES"], enabled=False)]
    assert detect_rule_conflicts(rules) == []


def test_boolean_flag_exact_duplicate():
    def flag(rule_id: str, field_: str) -> PolicyRule:
        return _rule(rule_id, condition=Condition(
            type="BOOLEAN_FLAG",
            parameters={"field": field_, "forbidden_value": True},
        ))
    item = _find(detect_rule_conflicts(
        [flag("A-1", "is_hardcoded"), flag("B-1", "is_hardcoded")]),
        "EXACT_DUPLICATE", "A-1", "B-1")
    assert item is not None
    # different fields never conflict
    assert detect_rule_conflicts(
        [flag("A-1", "is_hardcoded"), flag("B-1", "is_exported")]) == []


def test_incomparable_condition_types_are_skipped():
    rules = [_in_list("A-1", ["DES"]),
             _rule("C-1", condition=Condition(
                 type="COMPLEX", parameters={"require_algorithms": ["AES"]}))]
    assert detect_rule_conflicts(rules) == []


def test_real_packs_conflict_set_is_stable():
    """The shipped packs contain the two known real findings and no
    contradictions — regression-guard the live conflict surface."""
    from pathlib import Path

    from policy.core.engine import PolicyEngine

    rules_dir = Path(__file__).resolve().parents[2] / "rule_definitions"
    engine = PolicyEngine(str(rules_dir))
    conflicts = detect_rule_conflicts(engine.rule_set.rules)
    types = _types(conflicts)

    assert "DUPLICATE_ID" not in types
    assert "CONTRADICTORY" not in types
    # CBUAE-001 duplicates the baseline deny-list verbatim
    assert _find(conflicts, "EXACT_DUPLICATE", "BASELINE-001", "CBUAE-001") is not None
    # BASELINE-005 (weak TLS) is subsumed by the forbidden-algorithm rules
    assert _find_shadowed(conflicts, "BASELINE-005", "BASELINE-001") is not None
    assert _find_shadowed(conflicts, "BASELINE-005", "CBUAE-001") is not None
