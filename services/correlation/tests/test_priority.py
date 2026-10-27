"""Prioritization engine: deterministic revenue bands, agility mapping, ranking."""

from __future__ import annotations

from correlation.priority import (
    agility_fraction,
    build_input,
    counts_by_severity,
    prioritize,
    rank_reports,
    revenue_tier,
)


def test_revenue_tiers_are_deterministic_bands():
    assert revenue_tier(0) == 1
    assert revenue_tier(5_000) == 2
    assert revenue_tier(50_000) == 3
    assert revenue_tier(500_000) == 4
    assert revenue_tier(5_000_000) == 5
    # >=10k customers bumps one tier (never past 5)
    assert revenue_tier(5_000, customer_count=20_000) == 3
    assert revenue_tier(5_000_000, customer_count=99_999) == 5
    assert revenue_tier(None) == 1


def test_agility_fraction_clamps():
    assert agility_fraction(None) == 0.5
    assert agility_fraction(0) == 0.0
    assert agility_fraction(100) == 1.0
    assert agility_fraction(80) == 0.8
    assert agility_fraction(140) == 1.0  # out-of-range input never amplifies


def test_ranking_is_priority_desc_then_effort_asc():
    reports = [
        {"ref_id": "low", "priority": 3.0, "effort": 1.0},
        {"ref_id": "cheap-critical", "priority": 20.0, "effort": 4.0},
        {"ref_id": "dear-critical", "priority": 20.0, "effort": 9.0},
        {"ref_id": "mid", "priority": 12.0, "effort": 2.0},
    ]
    ranked = rank_reports(reports)
    assert [r["ref_id"] for r in ranked] == [
        "cheap-critical", "dear-critical", "mid", "low"]
    assert [r["rank"] for r in ranked] == [1, 2, 3, 4]


def test_prioritize_end_to_end_deterministic():
    events = [
        build_input(kind="weak_tls", severity="ALERT", target="edge-1",
                    evidence="TLSv1.0 offered", algorithm="3DES",
                    asset_count=2, complexity=1.5,
                    revenue_impact=5, agility=0.8) | {"ref_id": "e1", "source": "drift"},
        build_input(kind="key_reuse", severity="HIGH", target="app-2",
                    evidence="same cert on two systems",
                    revenue_impact=2, agility=0.3) | {"ref_id": "e2", "source": "runtime"},
    ]
    run1 = prioritize(events, graph={"edge-1": ["db-1"]})
    run2 = prioritize(events, graph={"edge-1": ["db-1"]})
    assert [r["rank"] for r in run1] == [1, 2]
    assert run1 == run2  # byte-identical runs
    top = run1[0]
    assert top["ref_id"] == "e1"
    assert top["priority"] == 5 * 3 * 0.8  # ALERT severity weight = 3
    assert top["correlated"] == ["db-1"]


def test_counts_expose_standard_scale():
    events = [build_input(kind="k", severity="CRITICAL", target="t", evidence="e")
              | {"ref_id": "a", "source": "drift"}]
    c = counts_by_severity(prioritize(events))
    assert c["CRITICAL"] == 1
    assert set(c) >= {"CRITICAL", "HIGH", "ALERT", "MEDIUM", "LOW"}
