"""Selected-row Bolt-double parity is not live Cypher/backend certification."""

from copy import deepcopy
from datetime import datetime, timezone
import pytest
from cbom.unified_cascade import unified_cascade
from graph_engine.core.engine import GraphEngine
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.testing.fake_driver import FakeDriver
from shared_models.operational_dependencies import MODES

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def data(mode):
    return {
        "systems": [{"id": s} for s in ["pay", "web", "db", "alt"]],
        "edges": [
            {
                "id": "edge",
                "parent_id": "web",
                "child_id": "pay",
                "relation": "CALLS",
                "lifecycle_revision": 0,
                "operational_dependency": {
                    "mode": mode,
                    **({"failover_system_ids": ["alt"]} if mode == "FAILOVER" else {}),
                },
            },
            {"id": "context", "parent_id": "pay", "child_id": "db", "relation": "DEPENDS_ON"},
        ],
    }


@pytest.mark.parametrize("mode", MODES)
def test_modes_preserved_in_memory_native_vis_witnesses_and_cascade_without_scope_changes(mode, monkeypatch):
    payload = data(mode)
    memory = GraphEngine(now=NOW).build(**payload)
    native = Neo4jGraphStore(FakeDriver(), now=NOW)
    native.sync(**payload)
    for graph in [memory, native]:
        exported = graph.to_vis()
        edge = next(e for e in exported["edges"] if e["from"] == "system:web")
        assert edge["operational_dependency"]["mode"] == mode
        if graph is native:
            monkeypatch.setattr(graph, "to_vis", lambda: pytest.fail("do not export/recompute entire graph"))
        result = graph.business_impact("pay")
        assert result["system_classification"]["review_system_count"] == 3
        assert result["system_classification"]["exposure_system_count"] == 2
        op = result["operational_impact"]
        assert op["edge_count"] == 2 and op["mode_counts"][mode] >= 1
        row = next(e for e in op["edges"] if e["from"] == "web")
        if mode == "FAILOVER":
            assert row["condition"]["failover_references"]["loaded_system_ids"] == ["alt"]
            assert "alt" not in result["system_classification"]["review_systems"]
        assert (
            result["process_traversal_evidence"]["dependent_consumers"]["paths"][0]["edges"][0][
                "operational_condition"
            ]["mode"]
            == mode
        )
    snapshot = {
        "systems": payload["systems"],
        "dependencies": [{**e, "source": e["parent_id"], "target": e["child_id"]} for e in payload["edges"]],
    }
    before = deepcopy(snapshot)
    unified = unified_cascade(snapshot, target="pay", kind="system", now=NOW)
    assert (
        unified["impact"]["operational_impact"]["mode_counts"]
        == memory.business_impact("pay")["operational_impact"]["mode_counts"]
    )
    assert snapshot == before


def test_clear_and_lower_revision_replay_do_not_revive_old_mode():
    payload = data("HARD")
    memory = GraphEngine(now=NOW).build(**payload)
    native = Neo4jGraphStore(FakeDriver(), now=NOW)
    native.sync(**payload)
    updated = deepcopy(payload)
    updated["edges"][0].update(lifecycle_revision=1, operational_dependency=None)
    for graph in (memory, native):
        (graph.build if graph is memory else graph.sync)(**updated)
        (graph.build if graph is memory else graph.sync)(**payload)
        result = graph.business_impact("pay")["operational_impact"]
        assert result["mode_counts"]["UNKNOWN"] == 2 and result["mode_counts"]["HARD"] == 0


def test_noncurrent_edges_and_unknown_relation_do_not_gain_operational_propagation():
    payload = data("HARD")
    payload["edges"][0].update(lifecycle_state="DELETED")
    payload["edges"][1]["relation"] = "BACKS_UP"
    for graph in [GraphEngine(now=NOW).build(**payload), Neo4jGraphStore(FakeDriver(), now=NOW)]:
        if isinstance(graph, Neo4jGraphStore):
            graph.sync(**payload)
        answer = graph.business_impact("pay")
        assert answer["system_classification"]["review_system_count"] == 1
        assert answer["operational_impact"]["edge_count"] == 0


def test_omitted_partial_metadata_does_not_clear_operational_annotation():
    payload = data("HARD")
    memory = GraphEngine(now=NOW).build(**payload)
    native = Neo4jGraphStore(FakeDriver(), now=NOW)
    native.sync(**payload)
    partial = deepcopy(payload)
    partial["edges"][0].pop("operational_dependency")
    partial["edges"][0]["lifecycle_revision"] = 1
    for graph in (memory, native):
        (graph.build if graph is memory else graph.sync)(**partial)
        assert graph.business_impact("pay")["operational_impact"]["mode_counts"]["HARD"] == 1
