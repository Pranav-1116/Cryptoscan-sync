"""Deterministic Correlation Engine: formulas, tables, templates, BFS."""

from __future__ import annotations

import pytest

from correlation.engine import (
    analyze,
    correlate,
    explain,
    migration_effort,
    migration_plan,
    priority_score,
    recommend_replacement,
)


def test_priority_formula_is_revenue_times_severity_times_agility():
    assert priority_score(revenue_impact=5, severity=5, agility=1.0) == 25.0
    assert priority_score(revenue_impact=4, severity=3, agility=0.5) == 6.0
    with pytest.raises(ValueError):
        priority_score(revenue_impact=3, severity=3, agility=1.5)


def test_effort_shrinks_as_agility_grows():
    high = migration_effort(asset_count=10, complexity=2.0, agility=1.0)
    low = migration_effort(asset_count=10, complexity=2.0, agility=0.0)
    assert high == 10 * 2.0 * 1  # multiplier (2 - 1)
    assert low == 10 * 2.0 * 2  # multiplier (2 - 0)
    assert low > high
    with pytest.raises(ValueError):
        migration_effort(asset_count=1, complexity=1, agility=-0.1)


def test_replacement_rule_table():
    assert recommend_replacement("3DES")["replacement"] == "AES-256-GCM"
    assert recommend_replacement("rc4")["replacement"] == "AES-256-GCM"
    assert "ML-KEM-768" in recommend_replacement("RSA-2048")["replacement"]
    assert recommend_replacement("TWOFISH-404") is None


def test_explain_is_template_deterministic():
    a = explain("weak_tls", severity="ALERT", endpoint_or_system="e:443", evidence="scan")
    b = explain("weak_tls", severity="ALERT", endpoint_or_system="e:443", evidence="scan")
    assert a == b
    assert "deprecated" in a and "TLS 1.2+" in a


def test_correlate_bfs_with_cycles_is_safe():
    edges = {"a": ["b", "c"], "b": ["c", "a"], "c": ["d"]}
    assert correlate("a", edges) == ["b", "c", "d"]
    assert correlate("d", edges) == []
    assert correlate("a", {"a": ["a"]}) == []


def test_migration_plan_template_library():
    bank = migration_plan("banking")
    telecom = migration_plan("telecom")
    assert bank["profile"] == "banking" and len(bank["phases"]) == 4
    assert telecom["profile"] == "telecom"
    assert migration_plan("unknown-profile")["profile"] == "default"


def test_analyze_report_end_to_end():
    report = analyze({
        "kind": "algorithm_downgrade", "severity": "CRITICAL",
        "endpoint": "e:443", "evidence": "3DES offered",
        "algorithm": "3DES", "revenue_impact": 5, "agility": 0.8,
        "asset_count": 3, "complexity": 1.5,
    }, graph={"e:443": ["db:3306"]}, profile="banking")
    assert report["priority"] == pytest.approx(5 * 5 * 0.8)
    assert report["effort"] == pytest.approx(3 * 1.5 * (2 - 0.8))
    assert report["replacement"]["replacement"] == "AES-256-GCM"
    assert report["correlated"] == ["db:3306"]
    assert "broken algorithm" in report["explanation"]
    assert report["plan"]["profile"] == "banking"
