from copy import deepcopy
from datetime import datetime, timezone

import pytest

from shared_models.coverage import (
    SOURCE_SCHEMA,
    analysis_coverage,
    collection_read,
    compare_coverage,
    coverage_summary,
    native_traversal_bound,
    traversal_bound,
    vendor_traversal_bound,
)

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def edge(src, dst, **values):
    return {"source": src, "target": dst, "type": "CALLS", **values}


def coverage():
    return analysis_coverage(
        {"source_coverage": {"schema": SOURCE_SCHEMA, "collections": {"systems": collection_read(3, 5)}}},
        {"analysis_performed": True},
    )


@pytest.mark.parametrize(
    "returned,limit,more,total,lower",
    [(5, 5, False, None, 5), (5, 5, True, None, 6), (0, 0, True, None, 1), (2, 2, True, 10, 10)],
)
def test_collection_lower_bound_is_not_invented_total(returned, limit, more, total, lower):
    read = collection_read(returned, limit, more=more, total=total)
    assert read["truncated"] is more
    assert read["known_total"] == total
    assert read["observed_lower_bound"] == lower
    assert "not proof" in read["scope"]


@pytest.mark.parametrize("reverse", [False, True])
def test_horizon_reports_only_unique_unvisited_eligible_neighbours(reverse):
    rows = [
        edge("a", "b"),
        edge("b", "a"),
        edge("b", "c"),
        edge("b", "c"),
        edge("b", "unknown"),
        edge("b", "d", lifecycle_state="DELETED"),
        edge("b", "e", type="USES"),
    ]
    if reverse:
        rows = [{**row, "source": row["target"], "target": row["source"]} for row in rows]
    original = deepcopy(rows)
    bound = traversal_bound(rows, {"system:a"}, known=list("abcde"), hops=1, now=NOW, reverse=reverse)
    assert bound["more_loaded_systems"] is True
    assert bound["reached_system_count"] == 1
    assert bound["unvisited_neighbour_count"] == 1
    assert rows == original
    assert (
        traversal_bound(rows, {"a"}, known=list("abcde"), hops=2, now=NOW, reverse=reverse)["more_loaded_systems"]
        is False
    )


def test_cycle_at_horizon_is_not_omission():
    bound = traversal_bound([edge("a", "b"), edge("b", "a")], {"a"}, known=list("ab"), hops=1, now=NOW)
    assert bound["frontier_system_count"] == 1
    assert bound["more_loaded_systems"] is False


def test_potential_horizon_is_distinct_from_active_horizon():
    rows = [edge("a", "b"), edge("b", "c", lifecycle_state="STALE")]
    kwargs = dict(known=list("abc"), hops=1, now=NOW)
    assert traversal_bound(rows, {"a"}, **kwargs)["more_loaded_systems"] is False
    assert traversal_bound(rows, {"a"}, potential=True, **kwargs)["more_loaded_systems"] is True


def test_native_horizon_unknown_even_with_no_rows():
    bound = native_traversal_bound([], 2)
    assert bound["more_loaded_systems"] is None
    assert bound["unvisited_neighbour_count"] is None
    report = analysis_coverage({}, {}, traversals=[bound])
    assert report["status"] == "UNKNOWN" and report["horizon_extension_unknown"]


def test_vendor_horizon_has_vendor_units_not_system_exposure():
    rows = [{"parent": a, "child": b} for a, b in zip("abcd", "bcde")]
    bound = vendor_traversal_bound(rows, {"a"}, known=list("abcde"), now=NOW)
    assert bound["more_loaded_entities"] and bound["unit"] == "vendors"
    assert "more_loaded_systems" not in bound


@pytest.mark.parametrize("change", ["missing", "input", "horizon", "unknown_horizon", "depth", "limit", "source"])
def test_incomparable_inputs_withhold_deltas(change):
    before = {"coverage": coverage()}
    after = deepcopy(before)
    if change == "missing":
        after = {}
    elif change == "input":
        after["coverage"]["known_input_truncation"] = True
    elif change == "horizon":
        after["coverage"]["known_horizon_omission"] = True
    elif change == "unknown_horizon":
        after["coverage"]["horizon_extension_unknown"] = True
    elif change == "depth":
        after["coverage"]["traversals"] = [{"direction": "upstream", "max_depth": 1}]
    elif change == "limit":
        after["coverage"]["collections"]["systems"]["limit"] = 10
    else:
        after["coverage"]["dependency_source"] = "different_backend"
    assert compare_coverage(before, after)["comparable"] is False
    assert "withheld" in compare_coverage(before, after)["reason"]


def test_explanation_limits_do_not_invalidate_membership_comparison():
    before = {"coverage": coverage()}
    after = deepcopy(before)
    after["coverage"]["explanation_truncation"] = True
    assert compare_coverage(before, after)["comparable"]
    assert coverage_summary({}) is None
    assert coverage_summary(after)["explanation_truncation"]


def test_missing_dependency_references_exclude_context_relations_and_preserve_original_rows():
    snapshot = {"systems": [{"id": "a"}], "dependencies": [edge("a", "ghost"), edge("a", "asset", type="USES")]}
    saved = deepcopy(snapshot)
    report = analysis_coverage(snapshot, {})
    gap = next(g for g in report["missing_links"] if g["name"] == "dependency_endpoint_references")
    assert gap["count"] == gap["denominator"] == 1
    assert snapshot == saved
    assert report["estate_completeness"] == "UNKNOWN"


def test_compact_counts_survive_process_witness_and_operational_detail_caps():
    result = {
        "impact": {
            "process_impact": {
                "processes": [{"reasons_truncated": True}],
                "coverage": {
                    "total_process_count": 800,
                    "returned_process_count": 500,
                    "process_limit": 500,
                    "processes_truncated": True,
                },
            },
            "operational_impact": {"edge_count": 900, "edges": [], "edge_limit": 500, "edges_truncated": True},
        },
        "traversal_evidence": {
            "direct_count": 700,
            "direct": [],
            "direct_truncated": True,
            "dependent_consumers": {
                "requested_count": 600,
                "returned_count": 500,
                "limit": 500,
                "truncated": True,
                "missing_witness_count": 1,
            },
        },
    }
    report = analysis_coverage({}, result)
    assert report["explanation_truncation"]
    assert not report["known_input_truncation"]
    listings = {r["name"]: r for r in report["explanations"]}
    assert listings["process_details"]["requested"] == 800
    assert listings["operational_details"]["requested"] == 900


def test_vendor_horizon_preserves_external_unregistered_intermediate_identifiers():
    rows = [{"parent": a, "child": b} for a, b in zip("abcde", "bcdef")]
    report = vendor_traversal_bound(rows, {"a"}, known={"a", "f"}, now=NOW)
    assert report["more_loaded_entities"]
    assert report["reached_entity_count"] == 3
    assert report["unvisited_neighbour_count"] == 1
