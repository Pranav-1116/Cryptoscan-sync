"""Same fixture/policy across memory, Bolt adapter double and unified cascade.

FakeDriver tests adapter parameters/behavior, NOT real Neo4j query execution.
The explicit Cypher contracts below prevent the double alone hiding an omitted
predicate, but a real deployment still needs its own Neo4j qualification.
"""
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from cbom.unified_cascade import unified_cascade
from graph_engine.builders.payload import call_rows
from graph_engine.builders.relationship_builder import RelationshipBuilder
from graph_engine.core.engine import GraphEngine
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.queries.blast_radius import BLAST_RADIUS
from graph_engine.queries.dependents import DEPENDENTS, SHORTEST_PATH_DOWNSTREAM, SHORTEST_PATH_UPSTREAM
from graph_engine.testing.fake_driver import FakeDriver
from shared_models.dependency_semantics import POLICY_VERSION, cypher_dependency_predicate, query_parameters

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def payload():
    return {
        "systems": [{"id": sid, "name": sid} for sid in ("mobile", "gateway", "pay", "signing", "ledger", "admin", "unknown", "orphan")],
        "edges": [
            {"parent_id": "mobile", "child_id": "gateway", "relation": "calls"},
            {"parent_id": "gateway", "child_id": "pay", "relation": "DEPENDS-ON"},
            {"parent_id": "pay", "child_id": "signing", "relation": "imports-crypto"},
            {"parent_id": "pay", "child_id": "ledger", "relation": "IMPORTS"},
            {"parent_id": "admin", "child_id": "pay", "relation": "contains"},
            {"parent_id": "unknown", "child_id": "pay", "relation": "MAGIC"},
            # A non-existing node cannot bridge a path even with a CALLS label.
            {"parent_id": "signing", "child_id": "ghost", "relation": "CALLS"},
            {"parent_id": "ghost", "child_id": "orphan", "relation": "CALLS"},
        ],
    }


def adapters(data):
    memory = GraphEngine().build(**data)
    driver = FakeDriver()
    store = Neo4jGraphStore(driver, database="neo4j")
    store.sync(**data)
    return memory, store


def cascade(data, seed, depth):
    snapshot = {"systems": data["systems"], "dependencies": [
        {"source": row["parent_id"], "target": row["child_id"], "type": row.get("relation")}
        for row in data["edges"]]}
    original = deepcopy(snapshot)
    result = unified_cascade(snapshot, target=seed, kind="system", max_depth=depth, now=NOW)
    assert snapshot == original
    return result


def flat_depths(groups):
    return {sid: int(depth) for depth, ids in groups.items() for sid in ids}


@pytest.mark.parametrize("seed", ["pay", "signing", "mobile", "admin", "unknown", "orphan"])
@pytest.mark.parametrize("depth", [1, 2, 6, 12])
def test_direction_and_min_hops_match_across_paths(seed, depth):
    data = payload()
    memory, store = adapters(data)
    result = cascade(data, seed, depth)
    for method, field in [("blast_radius", "downstream_by_depth"), ("dependents", "dependents_by_depth")]:
        expected = flat_depths(result["layers"]["system"][field])
        for graph in (memory, store):
            actual = getattr(graph, method)(seed, hops=depth)
            assert {row["id"]: row["hops"] for row in actual["systems"]} == expected
            assert actual["nodes_visited"] == len(expected) + 1
            assert actual["relationship_policy"]["version"] == POLICY_VERSION
    assert result["relationship_policy"]["version"] == POLICY_VERSION


def test_context_unknown_and_inventory_edges_cannot_bridge_systems():
    data = payload()
    data["assets"] = [{"id": "shared-key", "system_id": "pay"}]
    memory, store = adapters(data)
    memory.add_edge("asset:shared-key", "system:orphan", "CALLS")
    for graph in (memory, store):
        assert graph.dependents("pay")["systems"] == [
            {"id": "gateway", "name": "gateway", "criticality": None, "hops": 1},
            {"id": "mobile", "name": "mobile", "criticality": None, "hops": 2}]
        assert "orphan" not in {row["id"] for row in graph.blast_radius("pay")["systems"]}
        assert graph.shortest_path("admin", "pay")["reachable"] is False
        assert graph.shortest_path("unknown", "pay")["reachable"] is False


def test_diamond_cycles_parallel_labels_and_minimum_depth():
    data = payload()
    data["edges"] += [
        {"parent_id": "signing", "child_id": "gateway", "relation": "CALLS"},
        {"parent_id": "mobile", "child_id": "pay", "relation": "CALLS"},
        {"parent_id": "mobile", "child_id": "pay", "relation": "CONTAINS"},
    ]
    memory, store = adapters(data)
    for graph in (memory, store):
        rows = graph.blast_radius("mobile")["systems"]
        by_id = {row["id"]: row["hops"] for row in rows}
        assert len(rows) == len(by_id)
        assert by_id == {"gateway": 1, "pay": 1, "ledger": 2, "signing": 2}
        assert graph.shortest_path("mobile", "signing")["hops"] == 2
        assert graph.shortest_path("signing", "mobile", direction="upstream")["hops"] == 2
        cycles = graph.find_cycles()
        assert cycles["relationship_policy"]["version"] == POLICY_VERSION
        assert {"system:gateway", "system:pay", "system:signing"} in [set(c["members"]) for c in cycles["cycles"]]
    # Semantic label survives storage export, not collapsed back to CALLS.
    labels = {edge["label"] for edge in store.to_vis()["edges"]}
    assert {"CONTAINS", "IMPORTS_CRYPTO", "IMPORTS", "DEPENDS_ON", "MAGIC"} <= labels


def test_asset_starts_include_all_owners_once():
    data = payload()
    data["assets"] = [{"id": "shared-key", "system_id": sid} for sid in ("pay", "gateway")]
    for graph in adapters(data):
        forward = graph.blast_radius("shared-key")
        assert forward["owning_systems"] == ["gateway", "pay"]
        assert {r["id"]: r["hops"] for r in forward["systems"]} == {"ledger": 1, "signing": 1}
        reverse = graph.dependents("shared-key")
        assert reverse["owning_systems"] == ["gateway", "pay"]
        assert {r["id"]: r["hops"] for r in reverse["systems"]} == {"mobile": 1}


def test_shared_shortest_path_bound_and_missing_nodes():
    data = {"systems": [{"id": str(i), "name": str(i)} for i in range(14)],
            "edges": [{"parent_id": str(i), "child_id": str(i + 1), "relation": "CALLS"} for i in range(13)]}
    for graph in adapters(data):
        assert graph.shortest_path("0", "12")["hops"] == 12
        assert graph.shortest_path("0", "13")["reachable"] is False
        assert graph.shortest_path("0", "0")["hops"] == 0
        assert graph.shortest_path("missing", "0")["resolved_start"] is False
        assert len(graph.blast_radius("0", hops=99)["systems"]) == 12
        assert graph.blast_radius("missing")["nodes_visited"] == 0


def test_legacy_neo4j_transport_does_not_override_new_explicit_relation():
    driver = FakeDriver()
    store = Neo4jGraphStore(driver, database="neo4j")
    data = payload()
    data["edges"] = []
    store.sync(**data)
    driver.graph.merge_edge("System", "pay", "CALLS", "System", "signing", {"protocol": "https"})
    driver.graph.merge_edge("System", "pay", "CALLS", "System", "ledger", {"protocol": "imports-crypto"})
    driver.graph.merge_edge("System", "pay", "CALLS", "System", "admin", {"protocol": "contains"})
    driver.graph.merge_edge("System", "pay", "CALLS", "System", "unknown", {"protocol": "custom"})
    driver.graph.merge_edge("System", "pay", "CALLS", "System", "orphan", {"protocol": "https", "relation": "HTTP"})
    assert {row["id"] for row in store.blast_radius("pay")["systems"]} == {"signing", "ledger"}
    exported = GraphEngine.from_vis(store.to_vis())
    assert {row["id"] for row in exported.blast_radius("pay")["systems"]} == {"signing", "ledger"}


def test_query_contract_is_filtered_parameterized_and_min_hop_grouped():
    # These assertions inspect the REAL Cypher, not just the test double.
    for query in (BLAST_RADIUS, DEPENDENTS, SHORTEST_PATH_DOWNSTREAM, SHORTEST_PATH_UPSTREAM):
        assert cypher_dependency_predicate() in query
        assert "all(n IN nodes(path) WHERE n:System)" in query
        assert "__DEPENDENCY_POLICY__" not in query
        assert "$dependency_relations" in query and "$legacy_dependency_relations" in query
    assert "min(length(path)) AS hops" in BLAST_RADIUS
    assert "min(length(path)) AS hops" in DEPENDENTS
    assert "downstream <> s" in BLAST_RADIUS and "up <> s" in DEPENDENTS
    assert "[:CALLS*0..12]" in SHORTEST_PATH_DOWNSTREAM
    assert "CONTAINS" not in query_parameters()["dependency_relations"]
    assert call_rows([{"parent_id": "system:a", "child_id": "system:b", "relation": "imports-crypto", "protocol": "HTTP"}])[0]["relation"] == "IMPORTS_CRYPTO"
    builder = RelationshipBuilder()
    builder.calls("a", "b", protocol="HTTP")
    assert builder.engine.blast_radius("a")["systems"][0]["id"] == "b"


@pytest.mark.parametrize("relation,reachable", [("IMPORTS_CRYPTO", True), ("DEPENDS_ON", True), ("CONTAINS", False), ("CUSTOM", False)])
def test_vendor_path_filters_only_system_prefix_not_vendor_link(relation, reachable):
    from graph_engine.queries.vendor_dependency import VENDOR_PATH

    data = {"systems": [{"id": "pay", "name": "pay"}, {"id": "sign", "name": "sign"}],
            "edges": [{"parent_id": "pay", "child_id": "sign", "relation": relation}],
            "vendors": [{"id": "hsm", "name": "HSM supplier", "system_ids": ["sign"]}]}
    for graph in adapters(data):
        result = graph.vendor_path("pay")
        assert result["relationship_policy"]["version"] == POLICY_VERSION
        assert result["path"] == (["pay", "sign", "HSM supplier"] if reachable else [])
    assert cypher_dependency_predicate() in VENDOR_PATH
    assert "relationships(path)[0..-1]" in VENDOR_PATH


def test_prefixed_dependency_endpoints_match_raw_ids():
    data = payload()
    data["edges"] = [{**row, "parent_id": "system:" + row["parent_id"], "child_id": "system:" + row["child_id"]}
                     for row in data["edges"]]
    for graph in adapters(data):
        assert {r["id"] for r in graph.blast_radius("system:pay")["systems"]} == {"ledger", "signing"}


def test_zero_hop_store_path_avoids_native_shortest_path_common_node_restriction(monkeypatch):
    _memory, store = adapters(payload())
    queries = []
    original = store._run

    def capture(query, **params):
        queries.append(query)
        return original(query, **params)

    monkeypatch.setattr(store, "_run", capture)
    result = store.shortest_path("pay", "pay")
    assert result["path"] == ["pay"] and result["hops"] == 0
    assert all("shortestPath(" not in query for query in queries)
