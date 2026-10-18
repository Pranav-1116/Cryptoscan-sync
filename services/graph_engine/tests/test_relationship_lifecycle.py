"""Lifecycle parity contracts; FakeDriver is not live Cypher qualification."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import pytest
from cbom.unified_cascade import unified_cascade
from graph_engine.builders import cypher_writes
from graph_engine.core.engine import GraphEngine
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.testing.fake_driver import FakeDriver
from shared_models.relationship_lifecycle import effective_state, current, possible, cypher_current, storage_fields
from shared_models.dependency_semantics import cypher_dependency_predicate, query_parameters, POLICY_VERSION
from graph_engine.queries.blast_radius import BLAST_RADIUS
from graph_engine.queries.dependents import DEPENDENTS, SHORTEST_PATH_DOWNSTREAM, SHORTEST_PATH_UPSTREAM
from graph_engine.queries.vendor_dependency import VENDOR_PATH

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)
CASES = [({}, "ACTIVE"), ({"lifecycle_state": "ACTIVE"}, "ACTIVE"),
         ({"lifecycle_state": "STALE"}, "STALE"), ({"lifecycle_state": "DELETED"}, "DELETED"),
         ({"lifecycle_state": "SUPERSEDED"}, "SUPERSEDED"), ({"lifecycle_state": "EXPIRED"}, "EXPIRED"),
         ({"lifecycle_state": "garbage"}, "UNKNOWN"), ({"lifecycle_state": False}, "UNKNOWN"),
         ({"lifecycle_state": ""}, "UNKNOWN"), ({"lifecycle_state": "active"}, "UNKNOWN"),
         ({"valid_until": NOW.isoformat()}, "EXPIRED"),
         ({"valid_until": (NOW+timedelta(seconds=1)).isoformat()}, "ACTIVE"),
         ({"valid_until": "broken"}, "UNKNOWN"),
         ({"projection_state": "STALE"}, "STALE"), ({"projection_state": "bad"}, "UNKNOWN")]


def data(metadata):
    return {"systems": [{"id": s, "name": s} for s in ["web", "pay", "ledger"]],
            "edges": [{"parent_id": "web", "child_id": "pay", "relation": "CALLS", **metadata},
                      {"parent_id": "pay", "child_id": "ledger", "relation": "DEPENDS_ON"}]}


@pytest.mark.parametrize("metadata, expected", CASES)
def test_effective_state_is_fail_closed_at_inclusive_deadline(metadata, expected):
    assert effective_state(metadata, now=NOW) == expected
    assert current(metadata, now=NOW) == (expected == "ACTIVE")
    assert possible(metadata, now=NOW) == (expected not in {"DELETED", "SUPERSEDED"})


@pytest.mark.parametrize("metadata, expected", CASES)
def test_lifecycle_both_directions_native_adapter_export_and_cascade(metadata, expected):
    payload = data(metadata)
    memory = GraphEngine(now=NOW).build(**payload)
    native = Neo4jGraphStore(FakeDriver(), now=NOW)
    native.sync(**payload)
    exported = GraphEngine.from_vis(native.to_vis(), now=NOW)
    for graph in (memory, native, exported):
        assert bool(graph.blast_radius("web")["systems"]) == (expected == "ACTIVE")
        assert bool(graph.dependents("pay")["systems"]) == (expected == "ACTIVE")
        assert graph.shortest_path("web", "pay")["reachable"] == (expected == "ACTIVE")
        assert graph.shortest_path("pay", "web", direction="upstream")["reachable"] == (expected == "ACTIVE")
        # Raw exports retain inactive evidence rather than deleting edges.
        assert len(graph.to_vis()["edges"]) == 2
    snapshot = {"systems": payload["systems"], "dependencies": [
        {**r, "source": r["parent_id"], "target": r["child_id"], "type": r["relation"]} for r in payload["edges"]]}
    before = deepcopy(snapshot)
    result = unified_cascade(snapshot, target="pay", kind="system", now=NOW)
    assert snapshot == before
    assert ("web" in result["impact"]["system_classification"]["dependent_consumers"]["systems"]) == (expected == "ACTIVE")
    uncertain = result["impact"]["lifecycle_uncertainty"]["possible_additional_systems"]
    assert ("web" in uncertain) == (expected not in {"ACTIVE", "DELETED", "SUPERSEDED"})
    assert result["relationship_policy"]["version"] == POLICY_VERSION


def test_expiry_is_as_of_replay_not_rewriting_old_snapshots_and_default_clock_advances(monkeypatch):
    expires = NOW + timedelta(hours=1)
    payload = data({"valid_until": expires.isoformat()})
    snapshot = {"systems": payload["systems"], "dependencies": [
        {**r, "source": r["parent_id"], "target": r["child_id"], "type": r["relation"]} for r in payload["edges"]]}
    before = unified_cascade(snapshot, target="pay", kind="system", now=NOW)
    after = unified_cascade(snapshot, target="pay", kind="system", now=expires)
    assert before["impact"]["system_classification"]["dependent_consumers"]["systems"] == ["web"]
    assert after["impact"]["system_classification"]["dependent_consumers"]["systems"] == []
    assert before == unified_cascade(snapshot, target="pay", kind="system", now=NOW)
    import graph_engine.core.engine as engine_module
    graph = GraphEngine().build(**payload)
    monkeypatch.setattr(engine_module, "clock", lambda: NOW)
    assert graph.dependents("pay")["systems"]
    monkeypatch.setattr(engine_module, "clock", lambda: expires)
    assert not graph.dependents("pay")["systems"]


@pytest.mark.parametrize("collection", [None, {}, {"outcome": "PARTIAL", "truncated": False},
    {"outcome": "FAILED", "truncated": False}, {"outcome": "COMPLETE", "truncated": True},
    {"outcome": "COMPLETE", "truncated": False, "systems_truncated": True}])
def test_incomplete_failed_unknown_or_truncated_projection_never_prunes(collection):
    driver = FakeDriver()
    graph = Neo4jGraphStore(driver)
    graph.sync(**data({}))
    graph.sync(assets=[{"id": "a1"}, {"id": "a2"}])
    result = graph.sync(systems=[{"id": "web"}], assets=[{"id": "a1"}], collection=collection)
    assert result["pruned"] == 0
    assert result["pruning_skipped"] is True
    assert ("CryptoAsset", "a2") in driver.graph.nodes
    assert ("System", "pay") in driver.graph.nodes
    assert len(graph.to_vis()["edges"]) == 2


def test_native_older_revision_cannot_overwrite_tombstone_and_ambiguous_legacy_cannot_resurrect():
    driver = FakeDriver()
    graph = Neo4jGraphStore(driver, now=NOW)
    graph.sync(**data({}))
    driver.graph.merge_edge("System", "web", "CALLS", "System", "pay", {"protocol": "https"})
    graph.sync(**data({"lifecycle_state": "DELETED", "lifecycle_revision": 3}))
    assert not graph.dependents("pay")["systems"]
    assert any(e.get("projection_state") == "STALE" for e in graph.to_vis()["edges"])
    graph.sync(**data({"lifecycle_state": "ACTIVE", "lifecycle_revision": 2}))
    assert not graph.dependents("pay")["systems"]
    assert any(e.get("lifecycle_state") == "DELETED" for e in graph.to_vis()["edges"])
    assert "WHERE coalesce(rel.lifecycle_revision, 0) <= coalesce(row.lifecycle_revision, 0)" in cypher_writes.MERGE_CALLS
    assert "ambiguous_legacy_projection" in cypher_writes.QUARANTINE_LEGACY_CALLS


def test_real_cypher_predicates_bind_clock_every_path():
    for query in [BLAST_RADIUS, DEPENDENTS, SHORTEST_PATH_DOWNSTREAM, SHORTEST_PATH_UPSTREAM, VENDOR_PATH]:
        assert cypher_dependency_predicate() in query
        assert cypher_current() in query
        assert "$lifecycle_as_of" in query
        assert "valid_until_epoch" in query
    assert query_parameters(now=NOW)["lifecycle_as_of"] == NOW.timestamp()
    assert storage_fields({"valid_until": "broken"})["lifecycle_state"] == "UNKNOWN"


def test_graph_drift_detects_lifecycle_change_without_structural_deletion():
    before = GraphEngine(now=NOW).build(**data({"lifecycle_revision": 0}))
    after = GraphEngine(now=NOW).build(**data({"lifecycle_state": "DELETED", "lifecycle_revision": 1}))
    result = before.diff(after)
    assert result["changed"] is True
    assert result["edges_removed"] == []
    assert len(result["relationship_lifecycle_changes"]) == 1
    assert result["eligibility_change_is_not_remediation"] is True


def test_native_facade_refreshes_known_sql_lifecycle_before_serving_populated_graph(monkeypatch):
    import graph_engine.core.facade as facade
    driver = FakeDriver()
    Neo4jGraphStore(driver).sync(**data({"lifecycle_revision": 0}))
    monkeypatch.setattr(facade, "tenant_isolated", lambda: False)
    monkeypatch.setattr(facade, "probe_neo4j", lambda _: {"ok": True})
    graph = facade.resolve_graph(data({"lifecycle_state": "DELETED", "lifecycle_revision": 1}), driver=driver)
    assert graph.backend == "neo4j"
    assert not graph.dependents("pay")["systems"]
    assert any(edge.get("lifecycle_state") == "DELETED" for edge in graph.to_vis()["edges"])


def test_native_lifecycle_refresh_failure_does_not_serve_stale_active_answer(monkeypatch):
    import graph_engine.core.facade as facade
    driver = FakeDriver()
    Neo4jGraphStore(driver).sync(**data({"lifecycle_revision": 0}))
    monkeypatch.setattr(facade, "tenant_isolated", lambda: False)
    monkeypatch.setattr(facade, "probe_neo4j", lambda _: {"ok": True})
    def fail(*args, **kwargs):
        raise RuntimeError("lifecycle projection unavailable")
    monkeypatch.setattr(Neo4jGraphStore, "refresh_relationship_lifecycle", fail)
    with pytest.raises(RuntimeError, match="lifecycle projection unavailable"):
        facade.resolve_graph(data({"lifecycle_state": "DELETED", "lifecycle_revision": 1}), driver=driver)


@pytest.mark.parametrize("revision", [0, 1])
@pytest.mark.parametrize("state", ["ACTIVE", "STALE", "DELETED"])
def test_unregistered_duplicate_cannot_overwrite_managed_eligibility_even_at_revision_zero(revision, state):
    managed = data({"lifecycle_revision": revision, "lifecycle_state": state})
    managed["edges"].append({"parent_id": "web", "child_id": "pay", "relation": "CALLS", "source": "legacy_projection"})
    memory = GraphEngine(now=NOW).build(**managed)
    native = Neo4jGraphStore(FakeDriver(), now=NOW)
    native.sync(**managed)
    for graph in [memory, native, GraphEngine.from_vis(native.to_vis(), now=NOW)]:
        assert bool(graph.dependents("pay")["systems"]) == (state == "ACTIVE")
        edge = next(e for e in graph.to_vis()["edges"] if e["from"] == "system:web")
        assert edge["lifecycle_revision"] == revision
        assert edge["lifecycle_state"] == state


def test_active_only_context_not_in_target_adapter_scope_is_not_lifecycle_uncertainty():
    payload = data({})
    snapshot = {"systems": payload["systems"], "dependencies": [
        {**r, "source": r["parent_id"], "target": r["child_id"], "type": r["relation"]} for r in payload["edges"]],
        "business_processes": {"pay": [{"id": "authorize", "name": "Authorization"}]}}
    result = unified_cascade(snapshot, target="authorize", kind="process", now=NOW)
    assert result["relationship_lifecycle"]["excluded_count"] == 0
    assert result["impact"]["lifecycle_uncertainty"]["possible_additional_systems"] == []
    snapshot["dependencies"][1]["lifecycle_state"] = "STALE"
    result = unified_cascade(snapshot, target="authorize", kind="process", now=NOW)
    assert result["impact"]["lifecycle_uncertainty"]["possible_additional_systems"] == ["ledger"]
