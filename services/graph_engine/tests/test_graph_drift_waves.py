"""Graph drift (fresh vs persisted) and cycle-constrained migration waves."""

from __future__ import annotations

from graph_engine.core.drift import graph_drift
from graph_engine.core.engine import GraphEngine
from graph_engine.core.migration import merge_cycle_constraints
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.testing.fake_driver import FakeDriver


def _payload(**overrides):
    base = dict(
        systems=[
            {"id": "web", "name": "web-frontend"},
            {"id": "pay", "name": "payment-api"},
            {"id": "db", "name": "customer-db"},
        ],
        edges=[
            {"parent_id": "web", "child_id": "pay", "relation": "CALLS"},
            {"parent_id": "pay", "child_id": "db", "relation": "CALLS"},
            {"parent_id": "db", "child_id": "web", "relation": "CALLS"},  # cycle
        ],
    )
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# from_vis loader
# --------------------------------------------------------------------------- #

def test_from_vis_roundtrip_preserves_nodes_and_edges():
    original = GraphEngine().build(**_payload())
    reloaded = GraphEngine.from_vis(original.to_vis())
    assert reloaded.counts() == original.counts()
    assert reloaded.find_cycles()["count"] == 1  # the cycle survives the roundtrip
    assert reloaded.blast_radius("web")["systems"]


# --------------------------------------------------------------------------- #
# drift
# --------------------------------------------------------------------------- #

def test_drift_honest_without_neo4j():
    result = graph_drift(_payload(), driver=None)
    assert result["checked"] is False
    assert result["reason"] == "neo4j_unavailable"
    assert "nothing to compare" in result["detail"]


def test_drift_detects_missing_system_and_edge():
    driver = FakeDriver()
    store = Neo4jGraphStore(driver, database="neo4j")
    # persisted graph is stale: missing the db system and its edge
    store.sync(
        systems=[{"id": "web", "name": "web-frontend"}, {"id": "pay", "name": "payment-api"}],
        edges=[{"parent_id": "web", "child_id": "pay", "relation": "CALLS"}],
    )
    result = graph_drift(_payload(), driver=driver)
    assert result["checked"] is True
    assert result["changed"] is True
    assert "system:db" in result["nodes_added"]
    assert ("system:pay", "system:db", "CALLS") in result["edges_added"]
    assert ("system:db", "system:web", "CALLS") in result["edges_added"]
    assert result["counts"]["nodes_added"] == 1


def test_drift_reports_clean_when_synced():
    driver = FakeDriver()
    Neo4jGraphStore(driver, database="neo4j").sync(**_payload())
    result = graph_drift(_payload(), driver=driver)
    assert result["checked"] is True
    assert result["changed"] is False
    assert result["counts"] == {"nodes_added": 0, "nodes_removed": 0, "edges_added": 0, "edges_removed": 0}


def test_drift_detects_removed_inventory():
    driver = FakeDriver()
    Neo4jGraphStore(driver, database="neo4j").sync(
        **_payload(systems=_payload()["systems"] + [{"id": "old", "name": "decommissioned"}])
    )
    result = graph_drift(_payload(), driver=driver)
    assert "system:old" in result["nodes_removed"]


# --------------------------------------------------------------------------- #
# cycle-constrained migration waves
# --------------------------------------------------------------------------- #

def _entry(sid, name, wave, readiness=50, agility=50, **extra):
    return {
        "system_id": sid, "name": name, "wave": wave,
        "readiness_score": readiness, "agility_score": agility, **extra,
    }


def _cycle(*members):
    return {"members": [f"system:{m}" for m in members], "size": len(members), "self_loop": False}


def test_cycle_members_bumped_to_most_conservative_wave():
    entries = [
        _entry("web", "web-frontend", 1, readiness=90),
        _entry("pay", "payment-api", 1, readiness=80),
        _entry("db", "customer-db", 3, readiness=20),  # blocker holds its cycle peers
        _entry("mail", "email-service", 2, readiness=60),
    ]
    result = merge_cycle_constraints(entries, [_cycle("web", "pay", "db")])
    assert result["cycle_groups"] == 1
    assert result["systems_bumped"] == ["pay", "web"]
    wave1_names = [row["system_id"] for row in result["waves"].get("1", [])]
    wave3_names = [row["system_id"] for row in result["waves"]["3"]]
    assert wave1_names == []  # wave 1 emptied: every member was held back to wave 3
    assert "1" not in result["waves"]
    assert set(wave3_names) == {"web", "pay", "db"}
    assert all(row["cycle_group"] == "cycle-1" for row in result["waves"]["3"])
    assert "dependency cycle" in result["waves"]["3"][0]["rationale"]
    # untouched system stays put
    assert [row["system_id"] for row in result["waves"]["2"]] == ["mail"]


def test_positions_within_wave_ordered_by_readiness():
    entries = [
        _entry("a", "alpha", 1, readiness=40),
        _entry("b", "bravo", 1, readiness=90),
        _entry("c", "charlie", 1, readiness=60),
    ]
    result = merge_cycle_constraints(entries, [])
    assert [row["system_id"] for row in result["waves"]["1"]] == ["b", "c", "a"]
    assert [row["position"] for row in result["waves"]["1"]] == [1, 2, 3]


def test_self_loops_and_partial_cycles_do_not_constrain():
    entries = [_entry("a", "alpha", 1), _entry("b", "bravo", 2)]
    self_loop = {"members": ["system:a"], "size": 1, "self_loop": True}
    unknown_member = _cycle("a", "ghost")  # ghost not in entries
    result = merge_cycle_constraints(entries, [self_loop, unknown_member])
    assert result["cycle_groups"] == 0
    assert result["systems_bumped"] == []
    assert [row["system_id"] for row in result["waves"]["1"]] == ["a"]
    assert [row["system_id"] for row in result["waves"]["2"]] == ["b"]


def test_unscored_systems_flagged_in_rationale():
    entries = [_entry("a", "alpha", 3, unscored=True, readiness=0), _entry("b", "bravo", 3, readiness=70)]
    result = merge_cycle_constraints(entries, [])
    rows = {row["system_id"]: row for row in result["waves"]["3"]}
    assert "no agility score yet" in rows["a"]["rationale"]
    assert rows["b"]["rationale"] is None


def test_merge_is_deterministic_and_input_not_mutated():
    entries = [_entry("web", "web-frontend", 1), _entry("pay", "payment-api", 1), _entry("db", "customer-db", 3)]
    cycles = [_cycle("web", "pay", "db")]
    first = merge_cycle_constraints(entries, cycles)
    second = merge_cycle_constraints(entries, cycles)
    assert first == second
    assert entries[0]["wave"] == 1  # input list untouched
    assert "cycle_group" not in entries[0]
