"""Deterministic ruleset engine tests (no AI/ML)."""

from __future__ import annotations

import pytest

from ruleset.engine import Rule, Ruleset, RulesetEngine, RulesetError


def _rs(rules, name="baseline", version="1.0.0"):
    return Ruleset.from_dict({"name": name, "version": version, "rules": rules})


def test_rule_validation():
    with pytest.raises(RulesetError):
        Rule.from_dict({"id": "", "algorithm": "DES"})
    with pytest.raises(RulesetError):
        Rule.from_dict({"id": "r1", "decision": "MAYBE"})
    with pytest.raises(RulesetError):
        Rule.from_dict({"id": "r1", "min_key_size": -2})


def test_ruleset_requires_semver_and_unique_ids():
    with pytest.raises(RulesetError):
        Ruleset.from_dict({"name": "x", "version": "v1", "rules": []})
    with pytest.raises(RulesetError):
        Ruleset.from_dict({"name": "x", "version": "1.0.0",
                           "rules": [{"id": "a"}, {"id": "a"}]})


def test_algorithm_rule_matches():
    rs = _rs([{"id": "DES-001", "algorithm": "DES", "decision": "FAIL",
               "message": "DES is broken"}])
    eng = RulesetEngine(rs)
    ms = eng.evaluate({"algorithm": "des", "file_path": "a.java", "key_size": 56})
    assert len(ms) == 1 and ms[0].decision == "FAIL"
    assert eng.evaluate({"algorithm": "AES", "key_size": 256}) == []


def test_all_conditions_must_hold():
    # hardcoded DES only
    rs = _rs([{"id": "DES-HC", "algorithm": "DES", "is_hardcoded_key": True}])
    eng = RulesetEngine(rs)
    assert eng.evaluate({"algorithm": "DES", "is_hardcoded_key": True})
    assert not eng.evaluate({"algorithm": "DES", "is_hardcoded_key": False})


def test_key_size_and_status():
    rs = _rs([
        {"id": "WEAK-RSA", "algorithm": "RSA", "max_key_size": 1024, "decision": "FAIL"},
        {"id": "DISALLOWED", "status_in": ["DISALLOWED", "DEPRECATED"], "decision": "WARN"},
    ])
    eng = RulesetEngine(rs)
    assert eng.evaluate({"algorithm": "RSA", "key_size": 1024})[0].rule_id == "WEAK-RSA"
    assert not eng.evaluate({"algorithm": "RSA", "key_size": 2048})
    assert eng.evaluate({"algorithm": "X", "status": "disallowed"})[0].rule_id == "DISALLOWED"


def test_path_glob():
    rs = _rs([{"id": "LEGACY", "path_glob": "**/legacy/**", "decision": "WARN"}])
    eng = RulesetEngine(rs)
    assert eng.evaluate({"file_path": "src/legacy/c/Crypto.java"})
    assert not eng.evaluate({"file_path": "src/new/Crypto.java"})


def test_confidence_floor():
    rs = _rs([{"id": "HIGH-ONLY", "algorithm": "DES", "confidence_min": "HIGH"}])
    eng = RulesetEngine(rs)
    assert eng.evaluate({"algorithm": "DES", "confidence": "HIGH"})
    assert not eng.evaluate({"algorithm": "DES", "confidence": "LOW"})


def test_evaluate_many_gate():
    rs = _rs([{"id": "DES", "algorithm": "DES", "decision": "FAIL"}])
    eng = RulesetEngine(rs)
    out = eng.evaluate_many([
        {"algorithm": "DES", "file_path": "a"},
        {"algorithm": "AES", "file_path": "b"},
        {"algorithm": "DES", "file_path": "c"},
    ])
    assert out["fail_count"] == 2 and out["warn_count"] == 0
    assert out["gate"] == "FAIL"
    assert out["findings_evaluated"] == 3

    out2 = eng.evaluate_many([{"algorithm": "AES"}])
    assert out2["gate"] == "PASS"


def test_deterministic():
    rs = _rs([{"id": "DES", "algorithm": "DES"}])
    f = {"algorithm": "DES", "file_path": "a", "key_size": 56}
    eng = RulesetEngine(rs)
    a = eng.evaluate_many([f])
    b = eng.evaluate_many([dict(f)])
    assert a["results"] == b["results"]
