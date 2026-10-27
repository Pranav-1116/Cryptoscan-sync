"""Bank-process parity of memory/Bolt double/unified projection, not live Neo4j."""

from datetime import datetime, timezone, timedelta
from copy import deepcopy
import pytest
from cbom.unified_cascade import unified_cascade
from graph_engine.core.engine import GraphEngine
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.testing.fake_driver import FakeDriver

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def data():
    return {
        "systems": [{"id": s, "name": s} for s in ["mobile", "pay", "ledger", "island"]],
        "edges": [
            {"parent_id": "mobile", "child_id": "pay", "id": "call1"},
            {"parent_id": "pay", "child_id": "ledger", "id": "call2"},
        ],
        "processes": [
            {
                "id": "p1",
                "name": "Payments",
                "revenue_daily": 100,
                "customer_count": 10,
                "system_ids": ["pay", "mobile"],
                "system_links": [
                    {"id": "sp1", "system_id": "pay", "role": "PRIMARY", "evidence_ref": "change:42"},
                    {"id": "sp2", "system_id": "mobile", "role": "FRONTEND"},
                ],
            },
            {"id": "p2", "name": "Payments", "revenue_daily": 100, "customer_count": 10, "system_ids": ["mobile"]},
            {
                "id": "context",
                "name": "Reconciliation",
                "revenue_daily": 9999,
                "customer_count": 999,
                "system_ids": ["ledger"],
            },
            {"id": "unrelated", "name": "Isolated", "revenue_daily": 777, "system_ids": ["island"]},
        ],
    }


def backends(payload, now=NOW):
    memory = GraphEngine(now=now).build(**payload)
    native = Neo4jGraphStore(FakeDriver(), now=now)
    native.sync(**payload)
    return memory, native


def test_consumer_and_context_closure_distinct_ids_equal_values_and_actual_roles(monkeypatch):
    answers = []
    for graph in backends(data()):
        if isinstance(graph, Neo4jGraphStore):
            monkeypatch.setattr(graph, "to_vis", lambda: pytest.fail("no whole-graph export for process impact"))
        result = graph.business_impact("pay")
        projection = result["process_impact"]
        assert projection["counts"] == {"review": 3, "exposure": 2, "context_only": 1, "potential_only": 0}
        assert result["total_revenue_at_risk"] == 200 and result["total_customers_at_risk"] == 20
        assert {p["id"] for p in projection["processes"]} == {"p1", "p2", "context"}
        p1 = next(p for p in projection["processes"] if p["id"] == "p1")
        assert p1["reason_count"] == 2
        reason = next(r for r in p1["reasons"] if r["system_id"] == "pay")
        assert reason["role"] == "PRIMARY" and reason["support_link"]["record_id"] == "sp1"
        assert reason["support_link"]["evidence_references"] == ["change:42"]
        assert reason["support_link"]["provenance"] == "DECLARED"
        assert reason["system_explanation"]["available"]
        mobile = next(r for r in p1["reasons"] if r["system_id"] == "mobile")
        assert mobile["system_scope"] == "dependent_consumers" and mobile["system_explanation"]["available"]
        answers.append(projection)
    assert answers[0] == answers[1]


def test_shared_asset_all_owners_and_support_metadata_roundtrip():
    payload = data()
    payload["assets"] = [{"id": "key", "system_id": "pay"}, {"id": "key", "system_id": "mobile"}]
    for graph in backends(payload):
        result = graph.business_impact("asset:key")
        assert set(result["system_classification"]["direct_exposure"]["systems"]) == {"pay", "mobile"}
        projected = GraphEngine.from_vis(graph.to_vis())
        reason = next(
            r
            for p in projected.business_impact("pay")["process_impact"]["processes"]
            if p["id"] == "p1"
            for r in p["reasons"]
            if r["system_id"] == "pay"
        )
        assert reason["role"] == "PRIMARY" and reason["support_link"]["record_id"] == "sp1"


@pytest.mark.parametrize(
    "relation,consumer", [("CALLS", True), ("IMPORTS", True), ("CONTAINS", False), ("CUSTOM", False)]
)
def test_process_projection_cannot_bridge_nonpropagating_context_labels(relation, consumer):
    payload = data()
    payload["edges"][0]["relation"] = relation
    for graph in backends(payload):
        projection = graph.business_impact("pay")["process_impact"]
        assert (any(p["id"] == "p2" for p in projection["processes"])) == consumer


def test_uncertain_mapping_is_potential_and_terminal_mapping_is_excluded():
    payload = data()
    payload["processes"][0]["system_links"][0]["lifecycle_state"] = "STALE"
    payload["processes"][0]["system_links"][1]["lifecycle_state"] = "DELETED"
    for graph in backends(payload):
        projection = graph.business_impact("pay")["process_impact"]
        p1 = next(p for p in projection["processes"] if p["id"] == "p1")
        assert p1["potential_only"] and not p1["exposed"] and p1["reason_count"] == 1
        assert projection["economic_context"]["revenue_daily"]["known_sum"] == 100


def test_one_clock_per_impact_does_not_mutate_future_reads(monkeypatch):
    import graph_engine.core.engine as memory_module
    import graph_engine.core.store as native_module

    for graph, module in zip(backends(data(), now=None), [memory_module, native_module]):
        calls = []

        def tick():
            calls.append(1)
            return NOW + timedelta(seconds=len(calls))

        monkeypatch.setattr(module, "clock", tick)
        result = graph.business_impact("pay")
        assert len(calls) == 1 and graph._as_of is None
        assert result["process_impact"]["as_of"] == (NOW + timedelta(seconds=1)).isoformat()


def test_unified_review_closure_and_uncertain_processes_keep_old_result_immutable():
    payload = data()
    registry = {}
    for process in payload["processes"]:
        links = {link["system_id"]: link for link in process.get("system_links") or []}
        for sid in process["system_ids"]:
            registry.setdefault(sid, []).append(
                {
                    "id": process["id"],
                    "name": process["name"],
                    "revenue_daily": process.get("revenue_daily"),
                    "customer_count": process.get("customer_count"),
                    "relationship_record_id": (links.get(sid) or {}).get("id"),
                }
            )
    snapshot = {
        "systems": payload["systems"],
        "business_processes": registry,
        "dependencies": [
            {"source": e["parent_id"], "target": e["child_id"], "type": "CALLS"} for e in payload["edges"]
        ],
    }
    original = deepcopy(snapshot)
    answer = unified_cascade(snapshot, target="pay", kind="system", now=NOW)
    assert answer["impact"]["process_impact"]["counts"] == {
        "review": 3,
        "exposure": 2,
        "context_only": 1,
        "potential_only": 0,
    }
    snapshot["dependencies"][0]["lifecycle_state"] = "STALE"
    later = unified_cascade(snapshot, target="pay", kind="system", now=NOW)
    assert later["impact"]["process_impact"]["counts"]["potential_only"] == 1
    assert later["impact"]["process_impact"]["counts"]["exposure"] == 1
    assert answer == unified_cascade(original, target="pay", kind="system", now=NOW)
