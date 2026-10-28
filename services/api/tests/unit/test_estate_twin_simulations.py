"""Persisted simulations are quarantined (spec 94 §17, §19).

Spec 94 asks for a ``simulation_runs`` table. The whole risk of having one is that a
stored answer to "what if" gets read, a year later, as a record of "what happened".
These tests hold the quarantine to something stronger than a docstring: a stored
simulation must not be reachable as estate state through *any* surface.

Concretely, each test below closes one route by which a simulation could leak into
the estate:

* it cannot be stored at all unless the engine says the live state was untouched;
* storing it does not change the live projection id, the snapshot list, the drift
  comparison, or the graph export;
* ``/twin`` never counts it, and no snapshot id ever equals a simulation id;
* when the estate moves, the stored answer is labelled ``superseded`` rather than
  presented as a current impact figure;
* a scenario that matched nothing is refused at write time, because "we found
  nothing to simulate" stored as a run reads like a finding.
"""

from __future__ import annotations

import pytest

from api import estate_simulation_store as sims
from shared_models import estate_twin as twin
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api
from test_estate_twin import _payload

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

BASE = "/api/v1/estate/evidence"

SCENARIO = {"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM"}


def _discover(http) -> dict:
    created = http.post(f"{BASE}/discover", json=_payload())
    assert created.status_code == 200, created.text
    return created.json()


@pytest.fixture()
def graph():
    return build_graph(_payload())


# -- the store refuses what is not a simulation ---------------------------- #


def test_a_simulation_that_matched_nothing_is_not_storable():
    """Storing "nothing to simulate" as a run makes an empty answer look like a finding."""
    graph = build_graph({"estate": "B", "assets": [], "evidence": [], "relationships": []})
    result = twin.simulate(graph, {"kind": "REPLACE_ALGORITHM", "from": "ChaCha20", "to": "ML-KEM"})
    assert result["status"] != "SIMULATED"
    with pytest.raises(ValueError) as exc:
        sims.record_simulation(None, result, tenant_id=None)
    assert "not storable" in str(exc.value)


def test_a_simulation_that_modified_the_live_state_is_refused(graph):
    """A stored simulation must be known to have left the estate alone."""
    result = twin.simulate(graph, SCENARIO)
    assert result["status"] == "SIMULATED"
    forged = {**result, "live_state_modified": True}
    with pytest.raises(ValueError) as exc:
        sims.record_simulation(None, forged, tenant_id=None)
    assert "live_state_modified" in str(exc.value)


# -- the quarantine holds through the API ---------------------------------- #


def test_a_stored_simulation_never_becomes_estate_state(api):
    http, _session = api
    _discover(http)
    before = http.get(f"{BASE}/twin").json()

    stored = http.post(f"{BASE}/twin/simulate", json={**SCENARIO, "persist": True}).json()
    assert stored["persisted"] is True
    record = stored["simulation_record"]
    assert record["quarantined"] is True
    assert record["is_estate_state"] is False
    assert record["live_state_modified"] is False

    after = http.get(f"{BASE}/twin").json()
    # the twin is unchanged by a question about it
    assert after["projection_id"] == before["projection_id"]
    assert after["summary"] == before["summary"]
    assert after["completeness"] == before["completeness"]

    # and the simulation is not a snapshot: history cannot be read as estate state
    history = http.get(f"{BASE}/twin/snapshots").json()
    assert record["simulation_id"] not in {item["snapshot_id"] for item in history["snapshots"]}
    assert all(item.get("is_estate_state", True) is not False for item in history["snapshots"])


def test_the_stored_simulation_is_listed_with_its_quarantine(api):
    http, _session = api
    _discover(http)
    http.post(f"{BASE}/twin/simulate", json={**SCENARIO, "persist": True})

    listing = http.get(f"{BASE}/twin/simulations").json()
    assert listing["count"] == 1
    assert listing["quarantined"] is True
    assert listing["is_estate_state"] is False
    entry = listing["simulations"][0]
    assert entry["scenario"]["to"] == "ML-KEM"
    assert entry["superseded"] is False
    assert entry["observations"] == 1

    single = http.get(f"{BASE}/twin/simulations/{entry['simulation_id']}").json()
    assert single["simulation_id"] == entry["simulation_id"]
    assert single["is_estate_state"] is False


def test_asking_the_same_question_twice_advances_a_counter_not_a_result(api):
    """A second row for the same question would look like the estate moved."""
    http, _session = api
    _discover(http)
    first = http.post(f"{BASE}/twin/simulate", json={**SCENARIO, "persist": True}).json()
    second = http.post(f"{BASE}/twin/simulate", json={**SCENARIO, "persist": True}).json()
    assert first["simulation_record"]["id"] == second["simulation_record"]["id"]
    assert second["simulation_record"]["observations"] == 2
    assert "already stored" in second["persist_note"]
    assert http.get(f"{BASE}/twin/simulations").json()["count"] == 1


def test_not_persisting_is_the_default(api):
    http, _session = api
    _discover(http)
    body = http.post(f"{BASE}/twin/simulate", json=SCENARIO).json()
    assert "persisted" not in body
    assert http.get(f"{BASE}/twin/simulations").json()["count"] == 0


def test_a_matchless_simulation_reports_why_it_was_not_stored(api):
    http, _session = api
    _discover(http)
    body = http.post(
        f"{BASE}/twin/simulate",
        json={"kind": "REPLACE_ALGORITHM", "from": "ChaCha20", "to": "ML-KEM", "persist": True},
    ).json()
    assert body["status"] != "SIMULATED"
    assert body["persisted"] is False
    assert "not a simulation result" in body["persist_refused_because"]
    assert http.get(f"{BASE}/twin/simulations").json()["count"] == 0


def test_an_unknown_simulation_is_a_404_not_an_empty_answer(api):
    http, _session = api
    _discover(http)
    response = http.get(f"{BASE}/twin/simulations/does-not-exist")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "unknown_simulation"


def test_a_stored_simulation_goes_stale_rather_than_current_when_the_estate_moves(api):
    """An answer about a different estate is history, never a current impact figure."""
    http, _session = api
    _discover(http)
    stored = http.post(f"{BASE}/twin/simulate", json={**SCENARIO, "persist": True}).json()
    simulation_id = stored["simulation_record"]["simulation_id"]

    # the estate changes underneath the stored answer
    changed = _payload()
    changed["assets"][0]["name"] = "Payment API v2"
    http.post(f"{BASE}/discover", json=changed)

    entry = http.get(f"{BASE}/twin/simulations/{simulation_id}").json()
    assert entry["superseded"] is True
    assert entry["superseded_by"]
    assert "STALE" in entry["freshness"]


def test_the_graph_export_never_contains_a_simulation(api):
    """The export is the evidence projection; a hypothetical must not be renderable from it."""
    http, _session = api
    _discover(http)
    before = http.get(f"{BASE}/twin/graph").json()
    http.post(f"{BASE}/twin/simulate", json={**SCENARIO, "persist": True})
    after = http.get(f"{BASE}/twin/graph").json()
    assert after["counts"] == before["counts"]
    assert after["projection_id"] == before["projection_id"]
