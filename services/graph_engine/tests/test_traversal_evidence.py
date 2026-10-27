"""Actual selected-link metadata across memory/Bolt double; not Neo4j certification."""

from datetime import datetime, timezone
import pytest
from graph_engine.core.engine import GraphEngine
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.testing.fake_driver import FakeDriver
from shared_models.traversal_evidence import native_properties, native_path, path_evidence

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def adapters():
    payload = {
        "systems": [{"id": s, "name": s, "compliance_scopes": ["PCI"]} for s in ["a", "b", "c", "dead"]],
        "assets": [{"id": "key", "system_id": "b", "algorithm": "RSA", "confidence": "HIGH"}],
        "vendors": [{"id": "v", "name": "Vendor", "system_ids": ["c"]}],
        "processes": [{"id": "p", "name": "Payments", "system_ids": ["c"]}],
        "edges": [
            {
                "parent_id": "a",
                "child_id": "b",
                "relation": "CALLS",
                "id": "e1",
                "provenance": "OBSERVED",
                "source": "mesh",
                "evidence_ref": "mesh:span",
                "observed_at": "2026-10-17T00:00:00Z",
                "confidence": 0.8,
                "confidence_meaning": "collector correlation",
                "last_verified": "2026-10-16T00:00:00Z",
            },
            {
                "parent_id": "b",
                "child_id": "c",
                "relation": "IMPORTS",
                "id": "e2",
                "provenance": "DECLARED",
                "source": "manifest",
                "evidence_refs": [{"evidence_id": "ev", "content_hash": "a" * 64}],
                "last_confirmed_at": "2026-10-17T00:00:00Z",
            },
            {
                "parent_id": "c",
                "child_id": "dead",
                "relation": "CALLS",
                "id": "e3",
                "lifecycle_state": "DELETED",
                "evidence_ref": "retirement:ticket",
            },
        ],
    }
    memory = GraphEngine(now=NOW).build(**payload)
    native = Neo4jGraphStore(FakeDriver(), database="neo4j", now=NOW)
    native.sync(**payload)
    return memory, native


@pytest.mark.parametrize("method,start,target", [("blast_radius", "a", "c"), ("dependents", "c", "a")])
def test_selected_edges_keep_origin_pointers_freshness_and_physical_orientation(method, start, target):
    answers = []
    for graph in adapters():
        result = getattr(graph, method)(start)
        paths = {p["system_id"]: p for p in result["traversal_evidence"]["paths"]}
        assert "dead" not in paths
        path = paths[target]
        assert path["available"] and path["mixed_provenance"] and path["evidence_gap_count"] == 0
        by_id = {e["record_id"]: e for e in path["edges"]}
        assert by_id["e1"]["from"] == "a" and by_id["e1"]["to"] == "b"
        assert by_id["e1"]["evidence_references"] == ["mesh:span"]
        assert by_id["e1"]["freshness"]["observation"]["age_seconds"] == 86400
        assert by_id["e1"]["confidence_meaning"] == "collector correlation"
        assert by_id["e2"]["freshness"]["observation"]["status"] == "MISSING"
        assert by_id["e2"]["freshness"]["confirmation"]["status"] == "DATED"
        assert by_id["e2"]["evidence_references"][0]["evidence_id"] == "ev"
        assert all(not e["references_verified_by_traversal"] for e in path["edges"])
        answers.append(path)
    assert answers[0] == answers[1]


def test_shortest_vendor_and_domain_context_are_actual_witnesses_without_export_fallback(monkeypatch):
    for graph in adapters():
        if isinstance(graph, Neo4jGraphStore):
            monkeypatch.setattr(graph, "to_vis", lambda: pytest.fail("must not export entire graph for path evidence"))
        shortest = graph.shortest_path("c", "a", direction="upstream")["traversal_evidence"]["paths"][0]
        assert shortest["nodes"] == ["c", "b", "a"] and shortest["available"]
        assert graph.shortest_path("a", "a")["traversal_evidence"]["paths"][0]["hops"] == 0
        vendor = graph.vendor_path("a")["traversal_evidence"]["paths"][0]
        assert vendor["nodes"] == ["a", "b", "c", "vendor:v"] and vendor["available"]
        assert vendor["edges"][-1]["source"] == "vendor dependency mapping"
        impact = graph.business_impact("a")
        assert any(e["to"] == "process:p" and e["evidence_missing"] for e in impact["domain_links"]["edges"])
        assert graph.compliance_inheritance("a")["traversal_evidence"]["requested_count"] == 2
        assert graph.blast_radius("asset:key")["start_links"]["edges"][0]["to"] == "asset:key"
        assert graph.vendor_chain("v")["backend"] == graph.backend


def test_native_missing_selected_path_is_explicit_and_does_not_remove_membership(monkeypatch):
    _, graph = adapters()
    original = graph._run
    monkeypatch.setattr(graph, "_run", lambda q, **p: [] if "cryptoscan.query=witness_" in q else original(q, **p))
    result = graph.blast_radius("a")
    assert {s["id"] for s in result["systems"]} == {"b", "c"}
    evidence = result["traversal_evidence"]
    assert evidence["returned_count"] == 0 and evidence["missing_witness_count"] == 2
    assert not evidence["complete_for_requested_systems"]


@pytest.mark.parametrize("backend", ["memory", "native"])
def test_witness_cap_does_not_change_membership_counts(backend):
    systems = [{"id": f"s{i:04}", "name": f"s{i:04}"} for i in range(503)]
    data = dict(systems=systems, edges=[{"parent_id": "s0000", "child_id": s["id"]} for s in systems[1:]])
    if backend == "memory":
        graph = GraphEngine(now=NOW).build(**data)
    else:
        graph = Neo4jGraphStore(FakeDriver(), now=NOW)
        graph.sync(**data)
    result = graph.blast_radius("s0000")
    assert len(result["systems"]) == 502
    assert result["traversal_evidence"]["returned_count"] == 500 and result["traversal_evidence"]["truncated"]


def test_corrupt_missing_native_payload_is_not_an_available_or_verified_path():
    path = native_path({"path_nodes": ["a", "b"], "path_edges": []}, now=NOW)
    assert not path["available"]
    assert not path_evidence(["a"], [{"from": "a", "to": "b"}], now=NOW)["available"]
    edge = path_evidence(
        ["a", "b"],
        [{"from": "a", "to": "b", "provenance": "nonsense", "observed_at": "bad", "last_verified": "2027-01-01"}],
        now=NOW,
    )["edges"][0]
    assert edge["provenance"] == "UNATTRIBUTED" and edge["evidence_missing"]
    assert edge["freshness"]["observation"]["status"] == "INVALID"
    assert edge["freshness"]["verification_timestamp"]["status"] == "FUTURE"


def test_references_are_bounded_in_memory_and_native_serialization():
    row = {"from": "a", "to": "b", "evidence_refs": [{"id": str(i)} for i in range(100)]}
    for properties in [row, native_properties(row), native_properties(native_properties(row))]:
        path = path_evidence(["a", "b"], [{**properties, "from": "a", "to": "b"}], now=NOW)
        edge = path["edges"][0]
        assert len(edge["evidence_references"]) == 50 and edge["references_truncated"]
        assert "evidence_refs" not in edge


def test_json_roundtrip_keeps_edge_evidence_and_revision_guard():
    for graph in adapters():
        projected = GraphEngine.from_vis(graph.to_vis())
        path = next(p for p in projected.blast_radius("a")["traversal_evidence"]["paths"] if p["system_id"] == "c")
        assert path["mixed_provenance"] and path["evidence_gap_count"] == 0
        assert path["edges"][1]["evidence_references"][0]["evidence_id"] == "ev"
        assert path["edges"][0]["confidence_meaning"] == "collector correlation"


def test_native_queries_return_selected_properties_with_policy_and_bounds():
    from graph_engine.queries.traversal_evidence import WITNESS_UPSTREAM, WITNESS_DOWNSTREAM
    from graph_engine.queries.dependents import SHORTEST_PATH_UPSTREAM, SHORTEST_PATH_DOWNSTREAM
    from graph_engine.queries.vendor_dependency import VENDOR_PATH, VENDOR_NEIGHBORHOOD
    from graph_engine.builders import cypher_writes
    from shared_models.dependency_semantics import cypher_dependency_predicate
    import re

    for query in [WITNESS_UPSTREAM, WITNESS_DOWNSTREAM, SHORTEST_PATH_UPSTREAM, SHORTEST_PATH_DOWNSTREAM, VENDOR_PATH]:
        assert "properties(r)" in query and "path_edges" in query and "path_nodes" in query
        assert cypher_dependency_predicate() in query
    assert "reverse(" in WITNESS_UPSTREAM and "LIMIT $witness_limit" in WITNESS_DOWNSTREAM
    assert "DEPENDS_ON_VENDOR" in VENDOR_NEIGHBORHOOD and "MATCH (n)" not in VENDOR_NEIGHBORHOOD
    assert "row.evidence_refs_json" in cypher_writes.MERGE_CALLS
    assert "rel.lifecycle_revision IS NULL OR row.lifecycle_revision IS NOT NULL" in cypher_writes.MERGE_CALLS
    for name, value in vars(cypher_writes).items():
        if name.startswith("MERGE_"):
            assert not re.search(r",\s*SET\b", value), name
