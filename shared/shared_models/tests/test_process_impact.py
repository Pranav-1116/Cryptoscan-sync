from copy import deepcopy
from datetime import datetime, timezone
import pytest
from shared_models.process_impact import classify_systems, project_processes

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def test_identity_dedup_keeps_all_scoped_reasons_and_separates_context_potential():
    scope = classify_systems(["pay"], ["mobile", "pay"], ["ledger", "mobile"])
    rows = {
        "pay": [
            {
                "id": "p",
                "name": "Payments",
                "revenue_daily": 100,
                "customer_count": 10,
                "relationship_record_id": "sp1",
                "provenance": "DECLARED",
                "role": "primary",
            }
        ],
        "mobile": [
            {
                "id": "p",
                "name": "Payments",
                "revenue_daily": 100,
                "customer_count": 10,
                "relationship_record_id": "sp2",
            },
            {"id": "q", "name": "Payments", "revenue_daily": 100, "customer_count": 10},
        ],
        "ledger": [{"id": "context", "revenue_daily": 9999}],
        "stale": [{"id": "possible", "revenue_daily": 9999}],
    }
    original = deepcopy(rows)
    result = project_processes(rows, scope, now=NOW, uncertain_systems=["stale"])
    assert result["counts"] == {"review": 3, "exposure": 2, "context_only": 1, "potential_only": 1}
    assert result["economic_context"]["revenue_daily"]["known_sum"] == 200
    assert result["economic_context"]["customer_count"]["known_sum"] == 20
    process = next(p for p in result["processes"] if p["id"] == "p")
    assert {r["system_scope"] for r in process["reasons"]} == {"direct_exposure", "dependent_consumers"}
    link = next(r for r in process["reasons"] if r["system_id"] == "pay")["support_link"]
    assert link["record_id"] == "sp1" and link["provenance"] == "DECLARED" and link["evidence_missing"]
    assert rows == original


@pytest.mark.parametrize(
    "state,expected",
    [("STALE", "potential"), ("DELETED", "terminal"), ("SUPERSEDED", "terminal"), ("nonsense", "potential")],
)
def test_uncertain_support_mapping_does_not_become_active_exposure(state, expected):
    result = project_processes(
        {"pay": [{"id": "p", "lifecycle_state": state, "revenue_daily": 100}]},
        classify_systems(["pay"], [], []),
        now=NOW,
    )
    assert result["counts"]["exposure"] == 0
    assert result["counts"]["potential_only"] == (1 if expected == "potential" else 0)
    assert result["economic_context"]["revenue_daily"]["known_sum"] == 0
    assert result["economic_context"]["revenue_daily"]["complete_sum"] is None


def test_missing_conflicting_or_unregistered_data_is_not_a_fictional_zero_or_name_join():
    scope = classify_systems(["a", "b", "c"], [], [])
    result = project_processes(
        {
            "a": [{"id": "p", "name": "P", "revenue_daily": 1}, {"name": "No ID"}],
            "b": [{"id": "p", "name": "Rename", "revenue_daily": 2}, {"id": "foreign", "process_registered": False}],
            "c": [],
        },
        scope,
        now=NOW,
    )
    assert result["counts"]["exposure"] == 1
    assert result["processes"][0]["name_conflict"]
    assert result["economic_context"]["revenue_daily"]["complete_sum"] is None
    assert result["economic_context"]["customer_count"]["complete_sum"] is None
    assert result["coverage"]["unresolved_or_invalid_link_count"] == 2
    assert result["coverage"]["systems_without_recorded_links"] == ["c"]


def test_process_and_reason_bounds_never_change_counts_or_economic_context():
    scope = classify_systems(["a"], [], [])
    result = project_processes(
        {"a": [{"id": str(i), "revenue_daily": 1, "customer_count": 1} for i in range(502)]}, scope, now=NOW
    )
    assert result["counts"]["exposure"] == 502 and len(result["review_processes"]) == 502
    assert len(result["processes"]) == 500 and result["coverage"]["processes_truncated"]
    assert result["economic_context"]["revenue_daily"]["known_sum"] == 502
    scope = classify_systems([str(i) for i in range(202)], [], [])
    result = project_processes({str(i): [{"id": "p"}] for i in range(202)}, scope, now=NOW)
    assert result["processes"][0]["reason_count"] == 202
    assert len(result["processes"][0]["reasons"]) == 200 and result["processes"][0]["reasons_truncated"]


def test_extreme_declared_values_do_not_return_non_json_infinite_totals():
    result = project_processes(
        {"pay": [{"id": "a", "revenue_daily": 1e308}, {"id": "b", "revenue_daily": 1e308}]},
        classify_systems(["pay"], [], []),
        now=NOW,
    )
    assert result["economic_context"]["revenue_daily"]["known_sum"] is None
    assert result["economic_context"]["revenue_daily"]["aggregate_overflow"]
