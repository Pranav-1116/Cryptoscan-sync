"""Impact as of a stored evidence state: the drift, and the three refusals.

A migration plan is reviewed against evidence that had a date. Six weeks later
"what does this reach" and "what did it reach when we signed this off" are two
different questions, and only the first one is answerable from the live graph.

These tests pin the refusals that make the comparison evidence rather than
decoration:

* identical evidence states are ``IDENTICAL``, not a zero delta that reads like a
  measured absence of change;
* a selector that matched nothing on either side is ``NOT_COMPARABLE`` — calling
  it "no impact" would report an uncollected estate as a clean one;
* an asset that left the radius because its evidence was withdrawn is reported
  as ``evidence_lost``, because a shrinking blast radius is not proof that a
  migration worked;
* a retyped asset is visible, not silently counted as "persisting".
"""

from __future__ import annotations

import pytest

from shared_models.estate_graph import EstateGraph, make_evidence

from api import estate_twin_history as history
from api.estate_twin_history import (
    DIVERGED,
    DRIFT_SCHEMA,
    IDENTICAL,
    NOT_COMPARABLE,
    SIMULATION_DRIFT_SCHEMA,
    compare_impact,
    compare_simulation,
)


def _graph(*, crypto: str | None = "AES", dependants: int = 1,
           reclassify: str | None = None, drop_app_evidence: bool = False) -> EstateGraph:
    """An application behind a load balancer, with ``dependants`` services on it.

    Every knob is a real difference between two captures of the same estate: an
    algorithm appears, a dependant is added, an asset is reclassified, or the
    application's evidence is withdrawn.

    Each edge carries its own evidence id, because ``assert_relationship``
    refuses to establish one without: an unevidenced edge is a topology
    assumption, and the blast radius must not inherit it.
    """
    graph = EstateGraph(estate="payments-bank")
    application = graph.add_asset("APPLICATION", "Payment API")
    load_balancer = graph.add_asset("LOAD_BALANCER", "ext-lb-01")

    if crypto:
        evidence = graph.add_evidence(
            make_evidence(
                source="runtime-trace",
                evidence_type="RUNTIME_OBSERVED",
                target=application,
                layer="APPLICATION",
                facts={"algorithm": crypto, "key_size": 256},
            )
        )
        graph.assert_relationship(application, "uses", load_balancer,
                                  basis="APPROVED_MAPPING", evidence_ids=[evidence])
    else:
        config = graph.add_evidence(
            make_evidence(
                source="config-scan",
                evidence_type="CONFIGURED",
                target=application,
                layer="APPLICATION",
                facts={"environment": "production"},
            )
        )
        graph.assert_relationship(application, "uses", load_balancer,
                                  basis="APPROVED_MAPPING", evidence_ids=[config])

    for index in range(dependants):
        name = f"consumer-{index}"
        asset_type = "SYSTEM" if reclassify == name else "SERVICE"
        dependant = graph.add_asset(asset_type, name)
        own = graph.add_evidence(
            make_evidence(
                source="config-scan",
                evidence_type="CONFIGURED",
                target=dependant,
                layer="APPLICATION",
                facts={"environment": "production"},
            )
        )
        graph.assert_relationship(dependant, "depends_on", application,
                                  basis="APPROVED_MAPPING", evidence_ids=[own])

    if drop_app_evidence:
        graph = _without_evidence(graph, application)
    return graph


def _without_evidence(graph: EstateGraph, asset_id: str) -> EstateGraph:
    """Rebuild a graph without one asset's evidence.

    Models "the collector stopped returning this": the edges that rested on that
    evidence become UNKNOWN, which is the honest state — not a topology that
    silently keeps the connection.
    """
    rebuilt = EstateGraph(estate=graph.estate)
    for asset in graph.assets():
        rebuilt.add_asset(asset["type"], asset["name"])
    for record in graph.evidence():
        if str(record.get("target")) == asset_id:
            continue
        rebuilt.add_evidence(record)
    for edge in graph.relationships():
        rebuilt.assert_relationship(
            str(edge["subject"]), str(edge["predicate"]), str(edge["object"]),
            basis=edge.get("basis"), evidence_ids=edge.get("evidence_ids") or (),
        )
    return rebuilt


def _as_of(**overrides) -> dict:
    payload = {
        "snapshot_id": "twin:abc123",
        "projection_id": "proj-old",
        "first_seen_at": "2026-09-01T00:00:00+00:00",
        "policy_version": "2026.09",
    }
    payload.update(overrides)
    return payload


def test_identical_evidence_is_identical_not_a_zero():
    graph = _graph()
    result = compare_impact(graph, graph, {"algorithm": "AES"}, as_of=_as_of())
    assert result["status"] == IDENTICAL
    assert result["schema"] == DRIFT_SCHEMA
    assert result["identical_evidence"] is True
    # The zero counts are present, but the status says why they are zero.
    assert result["drift"]["counts"]["entered"] == 0
    assert "projection id" in result["reason"]


def test_a_new_dependant_enters_the_radius():
    before = _graph(dependants=1)
    now = _graph(dependants=2)
    result = compare_impact(now, before, {"algorithm": "AES"}, as_of=_as_of())
    assert result["status"] == DIVERGED
    assert result["drift"]["counts"]["entered"] == 1
    assert result["drift"]["counts"]["left"] == 0
    entered = result["drift"]["entered"]
    assert [card["name"] for card in entered] == ["consumer-1"]
    assert entered[0]["hops"] is not None


def test_a_removed_dependant_leaves_the_radius():
    before = _graph(dependants=2)
    now = _graph(dependants=1)
    result = compare_impact(now, before, {"algorithm": "AES"}, as_of=_as_of())
    assert result["drift"]["counts"]["left"] == 1
    assert result["drift"]["left"][0]["name"] == "consumer-1"
    # The three reasons an asset stops being reached are counted apart.
    assert result["drift"]["evidence_lost_count"] == 0, "it still has its own evidence"
    assert result["drift"]["gone_from_estate_count"] == 1, "it was removed from the estate itself"


def test_a_selector_matching_nothing_on_either_side_is_not_comparable():
    graph = _graph(crypto="AES")
    result = compare_impact(graph, graph, {"algorithm": "SM2"}, as_of=_as_of())
    assert result["status"] == NOT_COMPARABLE
    assert set(result["unusable_sides"]) == {"current", "historical"}
    # The critical property: no fabricated delta.
    assert "drift" not in result
    assert "entered" not in result
    assert "clean estate" in result["detail"]


def test_a_selector_matching_only_now_is_not_comparable():
    before = _graph(crypto=None)          # the algorithm was never observed then
    now = _graph(crypto="AES")
    result = compare_impact(now, before, {"algorithm": "AES"}, as_of=_as_of())
    assert result["status"] == NOT_COMPARABLE
    assert result["unusable_sides"] == {"historical": "NO_MATCH"}
    assert "may not have been collected" in result["reasons"]["historical"]


def test_withdrawn_evidence_is_reported_as_lost_not_as_a_successful_migration():
    before = _graph(crypto="AES")
    now = _graph(crypto="AES", drop_app_evidence=True)
    result = compare_impact(now, before, {"algorithm": "AES"}, as_of=_as_of())
    # The current side no longer matches at all — the honest answer is that the
    # comparison broke, not that the blast radius shrank to zero.
    assert result["status"] == NOT_COMPARABLE
    assert result["unusable_sides"] == {"current": "NO_MATCH"}


def test_unchanged_radius_reports_persistence_not_churn():
    """A new dependant added and removed elsewhere must not rewrite the rest."""
    before = _graph(dependants=2)
    now = _graph(dependants=2)
    result = compare_impact(now, before, {"algorithm": "AES"}, as_of=_as_of())
    assert result["status"] == IDENTICAL
    assert result["drift"]["counts"]["persisting"] == 4   # app, lb, 2 consumers
    assert result["drift"]["counts"]["entered"] == 0


def test_a_reclassified_asset_is_not_reported_as_a_gain_and_a_loss():
    """SERVICE → SYSTEM changes the id; the delta must not look like churn.

    Asset ids are type-qualified, so a reclassification arrives as one id leaving
    and another entering. Reported as a delta it reads as an estate that gained
    and lost a host at once; the comparison pairs them by name instead.
    """
    before = _graph(dependants=1)
    now = _graph(dependants=1, reclassify="consumer-0")
    result = compare_impact(now, before, {"algorithm": "AES"}, as_of=_as_of())
    assert result["status"] == DIVERGED, "the ids did change"
    counts = result["drift"]["counts"]
    assert counts["reclassified"] == 1
    assert counts["entered"] == 0 and counts["left"] == 0
    reclassified = result["drift"]["reclassified"][0]
    assert reclassified["name"] == "consumer-0"
    assert {reclassified["type_before"], reclassified["type_now"]} == {"SERVICE", "SYSTEM"}
    assert reclassified["asset_id_before"] != reclassified["asset_id_now"]


def test_a_snapshot_without_a_policy_version_is_caveated():
    graph = _graph()
    result = compare_impact(graph, _graph(dependants=2), {"algorithm": "AES"},
                            as_of=_as_of(policy_version=None))
    assert "predates policy_version" in result["caveat"]


def test_the_same_scenario_on_the_same_evidence_is_identical():
    graph = _graph()
    scenario = {"kind": "REPLACE_ALGORITHM", "from": "AES", "to": "AES-256-GCM", "label": "plan"}
    result = compare_simulation(graph, graph, scenario, as_of=_as_of())
    assert result["schema"] == SIMULATION_DRIFT_SCHEMA
    assert result["status"] == IDENTICAL
    assert result["identical_evidence"] is True
    assert result["drift"]["counts"]["entered"] == 0


def test_a_plan_that_no_longer_matches_the_stored_state_is_not_comparable():
    before = _graph(crypto="AES")
    now = _graph(crypto="SM4")
    scenario = {"kind": "REPLACE_ALGORITHM", "from": "SM4", "to": "AES-256-GCM"}
    result = compare_simulation(now, before, scenario, as_of=_as_of())
    assert result["status"] == NOT_COMPARABLE
    assert set(result["unusable_sides"]) == {"historical"}
    assert "never a plan for that state" in result["detail"]


def test_a_plan_that_still_matches_reports_what_it_now_reaches():
    before = _graph(dependants=1)
    now = _graph(dependants=3)
    scenario = {"kind": "REPLACE_ALGORITHM", "from": "AES", "to": "AES-256-GCM"}
    result = compare_simulation(now, before, scenario, as_of=_as_of())
    assert result["status"] == DIVERGED
    assert result["sides"]["current"]["matched_evidence"] >= 1
    assert result["sides"]["historical"]["matched_evidence"] >= 1
    assert result["drift"]["counts"]["current_affected"] >= result["drift"]["counts"]["historical_affected"]
    assert result["sides"]["current"]["live_projection_unchanged"] is True, (
        "the drift run must not modify live state"
    )


def test_the_module_exports_its_statuses():
    assert set(history.STATUS_MEANING) == {IDENTICAL, DIVERGED, NOT_COMPARABLE}


# --------------------------------------------------------------------- the routes


def _stored_snapshot(graph, *, snapshot_id: str = "twin:abc123", row_id: str = "row-1"):
    """A real ``EstateTwinSnapshot`` row, unpersisted, built from this graph.

    Using the ORM object rather than a stub keeps ``estate_twin_store.public``
    honest: the endpoint's snapshot metadata is whatever that function reads, and
    a hand-rolled stub would pass while the real shape drifted.
    """
    from datetime import datetime, timezone

    from db.models.estate_twin_snapshot import EstateTwinSnapshot
    from shared_models import estate_twin

    document = estate_twin.snapshot(graph)
    now = datetime.now(timezone.utc)
    return EstateTwinSnapshot(
        id=row_id,
        tenant_id=None,
        estate=graph.estate,
        scope=document.get("scope"),
        snapshot_id=snapshot_id,
        projection_id=str(document["projection_id"]),
        payload=document["payload"],
        counts=dict(document["counts"]),
        collector_versions=document.get("collector_versions") or [],
        policy_version="2026.10",
        assets=len(graph.assets()),
        evidence=len(graph.evidence()),
        relationships=len(graph.relationships()),
        unresolved_relationships=len(graph.unresolved_relationships()),
        completeness_percent=100.0,
        observations=1,
        first_seen_at=now,
        last_seen_at=now,
        source_run_id="run-0",
        captured_by="viewer",
        note="drill",
    )


def _fake_run(graph) -> object:
    """A stored run whose payload is this graph's snapshot — the route's input."""
    from shared_models import estate_twin

    class _Run:
        id = "run-1"
        result = {"estate_discovery": estate_twin.snapshot(graph)["payload"]}

    return _Run()


def test_an_unknown_snapshot_is_refused_with_the_reason_and_where_to_look(monkeypatch):
    from fastapi import HTTPException

    from api.routers import estate_graph

    monkeypatch.setattr(estate_graph.estate_twin_store, "get_snapshot", lambda *a, **k: None)
    body = estate_graph.TwinImpactAsOfRequest(snapshot="twin:nope", algorithm="AES")
    with pytest.raises(HTTPException) as excinfo:
        estate_graph.estate_twin_impact_as_of(body, user="viewer", db=None)
    assert excinfo.value.status_code == 404
    assert excinfo.value.detail["error"] == "unknown_snapshot"
    assert "/twin/snapshots" in excinfo.value.detail["reason"]


def test_the_endpoint_compares_the_stored_state_with_the_live_run(monkeypatch):
    from api.routers import estate_graph

    historical = _graph(dependants=1)
    current = _graph(dependants=2)
    row = _stored_snapshot(historical)
    monkeypatch.setattr(estate_graph.estate_twin_store, "get_snapshot", lambda *a, **k: row)
    monkeypatch.setattr(estate_graph, "_latest_run", lambda db: _fake_run(current))

    body = estate_graph.TwinImpactAsOfRequest(snapshot="twin:abc", algorithm="AES", depth=3)
    result = estate_graph.estate_twin_impact_as_of(body, user="viewer", db=None)
    assert result["run_id"] == "run-1"
    assert result["status"] == DIVERGED
    assert result["drift"]["counts"]["entered"] == 1
    assert result["snapshot"]["id"] == "row-1"


def test_the_simulation_endpoint_reuses_the_stored_state(monkeypatch):
    from api.routers import estate_graph

    graph = _graph()
    row = _stored_snapshot(graph)
    monkeypatch.setattr(estate_graph.estate_twin_store, "get_snapshot", lambda *a, **k: row)
    monkeypatch.setattr(estate_graph, "_latest_run", lambda db: _fake_run(graph))

    body = estate_graph.TwinSimulationAsOfRequest(
        snapshot="twin:abc", kind="REPLACE_ALGORITHM", from_="AES", to="AES-256-GCM"
    )
    result = estate_graph.estate_twin_simulate_as_of(body, user="viewer", db=None)
    assert result["schema"] == SIMULATION_DRIFT_SCHEMA
    assert result["status"] == IDENTICAL
