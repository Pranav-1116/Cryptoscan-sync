from datetime import datetime, timezone

import pytest
from graph_engine.core.engine import GraphEngine
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.testing.fake_driver import FakeDriver

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


@pytest.mark.parametrize("reverse", [False, True])
def test_memory_horizon_is_qualified_without_expanding_walk(reverse):
    graph = GraphEngine(now=NOW).build(
        systems=[{"id": s} for s in "abc"],
        edges=[
            {"parent_id": "a", "child_id": "b", "relation": "CALLS"},
            {"parent_id": "b", "child_id": "c", "relation": "CALLS"},
        ],
    )
    walk = graph.dependents("c", hops=1) if reverse else graph.blast_radius("a", hops=1)
    assert [s["id"] for s in walk["systems"]] == ["b"]
    assert walk["coverage"]["known_horizon_omission"]
    assert walk["coverage"]["traversals"][0]["unvisited_neighbour_count"] == 1
    assert not walk["coverage"]["source_metadata_available"]


def test_native_selected_query_reports_unchecked_extension_without_full_export(monkeypatch):
    graph = Neo4jGraphStore(FakeDriver(), now=NOW)
    graph.sync(systems=[{"id": s} for s in "abc"], edges=[{"parent_id": "a", "child_id": "b", "relation": "CALLS"}])
    monkeypatch.setattr(graph, "to_vis", lambda: pytest.fail("native coverage must not export graph"))
    result = graph.business_impact("a", hops=1)
    assert result["coverage"]["horizon_extension_unknown"]
    assert all(w["more_loaded_systems"] is None for w in result["coverage"]["traversals"])
    assert result["system_classification"]["review_system_count"] == 2


def test_collector_truncation_is_prominent_but_not_a_reconstructed_count():
    graph = GraphEngine(now=NOW).build(systems=[{"id": "a"}], collection={"systems_truncated": True})
    report = graph.business_impact("a")["coverage"]
    assert report["known_input_truncation"]
    assert report["collections"]["collector_systems"]["returned"] is None
