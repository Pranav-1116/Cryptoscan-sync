"""The simulation workspace: ask "what if" against the estate, and never bend the estate.

The workspace adds two things the engine did not have: a **catalog** of what this estate
can be asked (with the values it actually holds) and a **plan** that answers "would this
selector match anything?" before the copy is made. The run, the quarantine and the
"no match is not no impact" sentence are the engine's and the store's, so these tests
mostly check that the workspace does not lose them on the way to the console.
"""
from __future__ import annotations

import pytest

from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api
from test_estate_twin import _payload

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

BASE = "/api/v1/estate/evidence"


def _discover(http) -> dict:
    created = http.post(f"{BASE}/discover", json=_payload())
    assert created.status_code == 200, created.text
    return created.json()


@pytest.fixture()
def graph():
    return build_graph(_payload())


# -- the catalog says what can be asked, with this estate's own values ------ #


def test_the_catalog_lists_every_kind_with_the_limit_it_carries(graph):
    from api import estate_simulation

    body = estate_simulation.catalog(graph)

    assert {entry["kind"] for entry in body["kinds"]} == {
        "REPLACE_ALGORITHM", "RETIRE_ALGORITHM", "DISABLE_PROTOCOL", "UPGRADE_COMPONENT",
        "REMOVE_COMPONENT", "CHANGE_KEY_SIZE", "MIGRATE_QUANTUM_VULNERABLE",
        "CASCADE_ASSET_UNAVAILABLE", "CASCADE_CRYPTO_COMPROMISE", "CASCADE_ALGORITHM_BREAK",
    }
    for entry in body["kinds"]:
        assert entry["question"]
        assert entry["inputs"]
        # a kind rendered without its limit is the failure this field exists to prevent
        assert entry["does_not_answer"], entry["kind"]
    assert body["base_projection_id"] == graph.fingerprint()
    assert body["limits"]


def test_the_catalog_offers_the_algorithms_this_estate_actually_holds(graph):
    from api import estate_simulation

    vocabulary = estate_simulation.selector_vocabulary(graph)
    values = {item["value"] for item in vocabulary["algorithms"]}

    assert values, "no algorithm vocabulary despite an estate that reports algorithms"
    for item in vocabulary["algorithms"]:
        assert item["count"] >= 1
    # the value an operator would type, taken from the evidence rather than invented
    assert any("AES" in value for value in values)
    assert vocabulary["targets"], "targets are how a scenario is narrowed to one asset"
    assert "never reported" not in vocabulary["note"]
    assert "not forbidden" in vocabulary["note"]


def test_the_catalog_route_reports_the_run_it_was_measured_against(api):
    http, _session = api
    _discover(http)

    response = http.get(f"{BASE}/simulation/catalog")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["run_id"]
    assert body["estate"]["assets"] >= 1
    assert body["kinds"]


def test_the_catalog_route_says_there_is_no_estate_rather_than_inventing_one(api):
    http, _session = api

    response = http.get(f"{BASE}/simulation/catalog")

    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "no_estate_discovery"


# -- the plan answers "would this match" before the work -------------------- #


def test_a_plan_counts_what_the_run_would_touch(graph):
    from shared_models import estate_twin

    preview = estate_twin.preview(graph, {"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM"})

    assert preview["status"] == "WOULD_MATCH"
    assert preview["matched_evidence"] >= 1
    assert preview["affected_assets"]
    for asset in preview["affected_assets"]:
        assert asset["asset_id"]
        assert asset["evidence_matched"] >= 1
    assert preview["by_layer"]
    assert preview["live_state_modified"] is False


def test_a_plan_that_matches_nothing_is_not_a_statement_of_no_impact(graph):
    from shared_models import estate_twin

    preview = estate_twin.preview(graph, {"kind": "REPLACE_ALGORITHM", "from": "ChaCha20", "to": "ML-KEM"})

    assert preview["status"] == "WOULD_NOT_MATCH"
    assert preview["matched_evidence"] == 0
    assert "not 'no impact'" in preview["note"]


def test_a_plan_agrees_with_the_run_it_is_previewing(graph):
    """A preview that disagrees with the run is worse than no preview."""
    from shared_models import estate_twin

    scenario = {"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM"}
    preview = estate_twin.preview(graph, scenario)
    result = estate_twin.simulate(graph, scenario)

    assert preview["matched_evidence"] == result["matched_evidence"]
    assert {item["asset_id"] for item in preview["affected_assets"]} == {
        item["asset_id"] for item in result["affected_assets"]
    }
    assert preview["base_projection_id"] == result["base_projection_id"]


def test_a_plan_needs_a_before_state_and_says_which_one(graph):
    from shared_models import estate_twin

    preview = estate_twin.preview(graph, {"kind": "DISABLE_PROTOCOL"})

    assert preview["status"] == "INVALID_SCENARIO"
    assert "from" in preview["detail"]


def test_a_plan_names_targets_the_twin_does_not_hold(graph):
    from shared_models import estate_twin

    preview = estate_twin.preview(
        graph,
        {"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM", "targets": ["not-an-asset"]},
    )

    assert preview["unresolved_targets"] == ["not-an-asset"]
    assert preview["evidence_considered"] == 0
    assert preview["status"] == "WOULD_NOT_MATCH"


def test_the_plan_route_returns_the_preview_and_the_run(api):
    http, _session = api
    _discover(http)

    response = http.post(
        f"{BASE}/simulation/plan",
        json={"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "WOULD_MATCH"
    assert body["workspace"] == "cryptoscan.simulation-workspace/1"
    assert body["run_id"]


def test_the_plan_route_rejects_an_unanswerable_scenario(api):
    http, _session = api
    _discover(http)

    response = http.post(f"{BASE}/simulation/plan", json={"kind": "DISABLE_PROTOCOL"})

    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "invalid_scenario"


# -- the run keeps the engine's promises ------------------------------------ #


def test_a_run_projects_the_six_boms_from_the_copy_and_leaves_the_estate_alone(api):
    http, _session = api
    before = _discover(http)["projection_id"]

    response = http.post(
        f"{BASE}/simulation/run",
        json={"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM", "persist": False},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "SIMULATED"
    assert body["live_state_modified"] is False
    assert body["live_projection_unchanged"] is True
    assert body["base_projection_id"] == before
    assert set(body["bom_diff"]) == {"SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM"}
    assert body["plan"]["status"] == "WOULD_MATCH"
    assert body["persisted"] is False
    # the estate did not move: a second discovery of the same payload is the same projection
    assert _discover(http)["projection_id"] == before


def test_a_run_is_stored_quarantined_and_lands_in_the_history(api):
    http, _session = api
    _discover(http)

    run = http.post(
        f"{BASE}/simulation/run",
        json={"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM", "label": "PQC pilot"},
    ).json()
    assert run["persisted"] is True
    assert run["simulation_record"]["quarantined"] is True
    assert run["simulation_record"]["is_estate_state"] is False

    history = http.get(f"{BASE}/simulation/runs")

    assert history.status_code == 200, history.text
    body = history.json()
    assert body["count"] == 1
    assert body["simulations"][0]["simulation_id"] == run["simulation_id"]
    assert body["simulations"][0]["label"] == "PQC pilot"
    assert body["quarantined"] is True
    assert body["current_projection_id"] == run["base_projection_id"]


def test_rerunning_the_same_question_advances_the_counter_not_the_history(api):
    http, _session = api
    _discover(http)
    body = {"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM"}

    first = http.post(f"{BASE}/simulation/run", json=body).json()
    second = http.post(f"{BASE}/simulation/run", json=body).json()

    assert first["simulation_id"] == second["simulation_id"]
    assert second["simulation_record"]["observations"] >= 2
    assert "observation counter advanced" in second["persist_note"]
    assert http.get(f"{BASE}/simulation/runs").json()["count"] == 1


def test_a_run_that_matched_nothing_is_refused_a_row(api):
    http, _session = api
    _discover(http)

    response = http.post(
        f"{BASE}/simulation/run",
        json={"kind": "REPLACE_ALGORITHM", "from": "ChaCha20", "to": "ML-KEM"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "NO_MATCH"
    assert body["persisted"] is False
    assert "not a simulation result" in body["persist_refused_because"]
    assert http.get(f"{BASE}/simulation/runs").json()["count"] == 0


def test_a_stored_run_from_a_different_estate_is_marked_superseded(api):
    http, session = api
    _discover(http)
    stored = http.post(
        f"{BASE}/simulation/run",
        json={"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM"},
    ).json()

    # the estate moves on: a second discovery with one more asset
    changed = _payload()
    changed["assets"] = [*changed["assets"], {"ref": "new", "type": "HOST", "name": "new-host"}]
    assert http.post(f"{BASE}/discover", json=changed).status_code == 200

    history = http.get(f"{BASE}/simulation/runs").json()

    row = next(item for item in history["simulations"] if item["simulation_id"] == stored["simulation_id"])
    assert row["computed_against"] == stored["base_projection_id"]
    assert row["superseded"] is True
    assert row["superseded_by"] == history["current_projection_id"]


def test_the_history_route_needs_an_estate(api):
    http, _session = api

    assert http.get(f"{BASE}/simulation/runs").status_code == 404


def test_the_workspace_never_returns_a_result_that_moved_the_estate(api, monkeypatch):
    """If the engine ever reported a changed live projection, the run is withheld."""
    http, _session = api
    _discover(http)
    from api import estate_simulation

    def lying_run(graph, scenario):  # noqa: ANN001
        return {"status": "SIMULATED", "live_state_modified": True, "base_projection_id": "x"}

    monkeypatch.setattr(estate_simulation, "run", lying_run)

    response = http.post(
        f"{BASE}/simulation/run",
        json={"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM"},
    )

    assert response.status_code == 500
    assert response.json()["detail"]["error"] == "simulation_modified_live_state"
