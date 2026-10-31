"""One simulation engine: subject → modification → recompute, for any question.

"PQC shouldn't be the only simulation" is a claim about *generality*, and generality
is easy to assert. These tests pin the three properties that make it true, and the
refusals that keep a projection from quietly measuring a smaller estate than the one
the scenario described.
"""
from __future__ import annotations

import inspect
import json

import pytest

from shared_models import simulation_engine as S


def _view() -> S.View:
    return S.View(
        assets=(
            {"asset_id": "app-payments", "type": "APPLICATION", "name": "payments"},
            {"asset_id": "lb-payments", "type": "LOAD_BALANCER", "name": "lb"},
            {"asset_id": "hsm-01", "type": "HSM", "name": "hsm"},
            {"asset_id": "host-quiet", "type": "HOST", "name": "quiet"},
        ),
        relationships=(
            {"subject": "app-payments", "predicate": "terminates_at", "object": "lb-payments",
             "basis": "CONFIGURATION", "status": "ESTABLISHED"},
            {"subject": "lb-payments", "predicate": "uses", "object": "hsm-01",
             "basis": "RUNTIME_OBSERVATION", "status": "ESTABLISHED"},
        ),
        crypto=(
            {"asset_id": "app-payments", "algorithm": "RSA-2048", "key_size": 2048},
            {"asset_id": "hsm-01", "algorithm": "AES-256", "key_size": 256},
        ),
    )


def _scenario(**overrides) -> dict:
    base = {
        "schema": S.SCENARIO_SCHEMA,
        "id": "pqc-rsa",
        "label": "replace RSA",
        "subject": {"type": "CRYPTO"},
        "modifications": [
            {"op": "REPLACE", "target": "app-payments", "attribute": "algorithm", "value": "ML-KEM-768"}
        ],
        "models": ["shor_vulnerable", "crypto_coverage"],
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# scenarios are data
# --------------------------------------------------------------------------- #


def test_a_scenario_carrying_a_callable_is_refused():
    with pytest.raises(ValueError, match="callable"):
        S.validate(_scenario(models=["shor_vulnerable"], extra={"compute": lambda view: 1}))


def test_a_scenario_round_trips_through_json():
    document = _scenario()
    assert json.loads(json.dumps(document)) == document


def test_unknown_ops_and_models_are_refused_rather_than_skipped():
    with pytest.raises(ValueError, match="unknown op"):
        S.validate(_scenario(modifications=[{"op": "MELT", "target": "app-payments"}]))
    with pytest.raises(ValueError, match="unknown model"):
        S.validate(_scenario(models=["attacker_profit"]))


def test_a_scenario_needs_a_change_to_simulate():
    with pytest.raises(ValueError, match="at least one modification"):
        S.validate(_scenario(modifications=[]))


def test_every_shipped_example_validates_and_runs():
    view = _view()
    assert len(S.EXAMPLES) >= 4
    subject_types = {example["subject"]["type"] for example in S.EXAMPLES}
    assert {"CRYPTO", "HSM", "LOAD_BALANCER", "LIBRARY"} <= subject_types, (
        "the examples exist to show the engine is not a PQC planner — they must span domains"
    )
    for example in S.EXAMPLES:
        result = S.run(example, view)
        assert result["complete"] is True, (example["id"], result["modifications"]["refused"])
        assert result["delta"]


# --------------------------------------------------------------------------- #
# the cycle itself
# --------------------------------------------------------------------------- #


def test_a_crypto_replacement_lowers_the_vulnerable_count():
    result = S.run(_scenario(), _view())
    by_model = {row["model"]: row for row in result["delta"]}
    assert by_model["shor_vulnerable"]["before"] == 1.0
    assert by_model["shor_vulnerable"]["after"] == 0.0
    assert by_model["shor_vulnerable"]["direction"] == "BETTER"
    assert result["complete"] is True
    assert result["modifications"]["applied"][0]["op"] == "REPLACE"


def test_disabling_an_hsm_strands_its_dependents_without_moving_the_graph():
    """The honest shape of a maintenance window: nothing is deleted, so only the
    *stranded* metric moves. A model that reported zero would be measuring edges."""
    result = S.run(
        _scenario(
            id="hsm-window",
            modifications=[{"op": "DISABLE", "target": "hsm-01"}],
            models=["blast_radius", "stranded_dependents"],
        ),
        _view(),
    )
    by_model = {row["model"]: row for row in result["delta"]}
    assert by_model["blast_radius"]["after"] == by_model["blast_radius"]["before"]
    assert by_model["stranded_dependents"]["before"] == 0.0
    assert by_model["stranded_dependents"]["after"] == 2.0
    assert by_model["stranded_dependents"]["direction"] == "WORSE"
    assert set(by_model["stranded_dependents"]["evidence_ids"]) == {"app-payments", "lb-payments"}


def test_a_removal_takes_its_edges_and_its_coverage_with_it():
    result = S.run(
        _scenario(
            id="decommission",
            modifications=[{"op": "REMOVE", "target": "lb-payments"}],
            models=["blast_radius", "stranded_dependents", "crypto_coverage"],
        ),
        _view(),
    )
    by_model = {row["model"]: row for row in result["delta"]}
    # the edges that pointed at the load balancer are gone with it
    assert by_model["blast_radius"]["after"] == 0.0
    assert by_model["stranded_dependents"]["after"] == 1.0  # hsm-01 lost its dependent
    assert by_model["crypto_coverage"]["direction"] == "UNCHANGED"


def test_coverage_going_up_is_not_called_worse():
    result = S.run(
        _scenario(
            id="add-crypto",
            modifications=[{"op": "ADD", "target": "host-new", "asset_type": "HOST",
                            "algorithm": "AES-256"}],
            models=["crypto_coverage", "shor_vulnerable"],
        ),
        _view(),
    )
    by_model = {row["model"]: row for row in result["delta"]}
    assert by_model["crypto_coverage"]["after"] == by_model["crypto_coverage"]["before"] + 1
    assert by_model["crypto_coverage"]["direction"] == "BETTER"


# --------------------------------------------------------------------------- #
# refusals
# --------------------------------------------------------------------------- #


def test_an_unknown_target_is_refused_and_the_projection_says_so():
    result = S.run(
        _scenario(id="ghost", modifications=[{"op": "REMOVE", "target": "host-that-never-existed"}]),
        _view(),
    )
    assert result["complete"] is False
    assert result["modifications"]["applied"] == []
    refused = result["modifications"]["refused"]
    assert refused[0]["reason"].startswith("no asset or crypto artefact")
    # nothing moved, and the delta is reported rather than omitted
    assert all(row["change"] == 0 for row in result["delta"])


def test_a_partial_scenario_does_not_pass_off_the_remainder_as_the_answer():
    result = S.run(
        _scenario(
            id="mixed",
            modifications=[
                {"op": "REPLACE", "target": "app-payments", "attribute": "algorithm",
                 "value": "ML-KEM-768"},
                {"op": "DISABLE", "target": "hsm-does-not-exist"},
            ],
        ),
        _view(),
    )
    assert result["complete"] is False
    assert len(result["modifications"]["applied"]) == 1
    assert len(result["modifications"]["refused"]) == 1


def test_adding_an_asset_that_already_exists_is_refused():
    result = S.run(
        _scenario(id="dup", modifications=[{"op": "ADD", "target": "hsm-01"}]),
        _view(),
    )
    assert result["complete"] is False
    assert "already in this estate" in result["modifications"]["refused"][0]["reason"]


def test_replace_without_an_attribute_is_refused():
    result = S.run(
        _scenario(id="vague", modifications=[{"op": "REPLACE", "target": "app-payments"}]),
        _view(),
    )
    assert result["complete"] is False
    assert "no attribute" in result["modifications"]["refused"][0]["reason"]


# --------------------------------------------------------------------------- #
# genericity: a new question does not touch the engine
# --------------------------------------------------------------------------- #


def test_a_model_registered_at_run_time_is_evaluated_with_no_engine_change():
    """The proof of genericity: add a question from outside, and the cycle just runs it."""

    def disabled_assets(view: S.View, context) -> S.Result:
        count = len([asset for asset in view.assets if asset.get("disabled")])
        return S.Result(
            model="disabled_assets",
            label="Disabled assets",
            metric="disabled_assets",
            value=float(count),
            evidence_ids=tuple(
                str(asset.get("asset_id")) for asset in view.assets if asset.get("disabled")
            ),
        )

    model = S.Model(
        id="disabled_assets",
        label="Disabled assets",
        reads=("assets",),
        metric="disabled_assets",
        evaluate=disabled_assets,
    )
    scenario = _scenario(
        id="hsm-window",
        modifications=[{"op": "DISABLE", "target": "hsm-01"}],
        models=["disabled_assets"],
    )
    with pytest.raises(ValueError, match="unknown model"):
        S.validate(scenario)  # not registered globally
    result = S.run(scenario, _view(), models={"disabled_assets": model})
    assert result["delta"][0]["model"] == "disabled_assets"
    assert result["delta"][0]["before"] == 0.0
    assert result["delta"][0]["after"] == 1.0
    # and the engine's own registry is unchanged by it
    assert "disabled_assets" not in S.catalogue_models()


def test_the_engine_knows_no_scenario_by_name():
    """A scenario-specific branch would make this a PQC planner with extra cases."""
    source = inspect.getsource(S.run) + inspect.getsource(S.View.apply)
    for example in S.EXAMPLES:
        assert example["id"] not in source, f"{example['id']} is special-cased in the engine"
    assert "quantum" not in source.lower()


def test_the_catalogue_is_what_is_registered_and_nothing_more():
    catalogue = S.catalogue()
    assert {model["id"] for model in catalogue["models"]} == set(S.REGISTRY)
    assert catalogue["ops"] == list(S.OPS)
    for model in catalogue["models"]:
        assert model["reads"], model["id"]
    assert {model["id"] for model in catalogue["models"]} >= {
        "shor_vulnerable", "blast_radius", "stranded_dependents", "crypto_coverage",
    }


# --------------------------------------------------------------------------- #
# determinism and provenance
# --------------------------------------------------------------------------- #


def test_the_same_scenario_on_the_same_view_is_the_same_document():
    first = S.run(_scenario(), _view())
    second = S.run(_scenario(), _view())
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_a_projection_never_mutates_the_baseline_view():
    view = _view()
    before = json.dumps([view.assets, view.relationships, view.crypto], sort_keys=True, default=str)
    S.run(_scenario(id="decommission", modifications=[{"op": "REMOVE", "target": "hsm-01"}]), view)
    after = json.dumps([view.assets, view.relationships, view.crypto], sort_keys=True, default=str)
    assert before == after


def test_every_delta_row_carries_the_evidence_it_was_computed_from():
    result = S.run(
        _scenario(models=["shor_vulnerable", "stranded_dependents", "crypto_coverage"],
                  modifications=[{"op": "DISABLE", "target": "hsm-01"}]),
        _view(),
    )
    for row in result["delta"]:
        assert "evidence_ids" in row
        assert len(row["evidence_ids"]) <= 50
    shor = result["baseline"]["shor_vulnerable"]
    assert shor["evidence_count"] == shor["value"]
    assert "arithmetic" in result["note"]


def test_a_view_can_be_built_from_an_estate_graph():
    from shared_models.estate_graph import EstateGraph

    graph = EstateGraph(estate="probe")
    app = graph.add_asset("APPLICATION", "payments-api")
    hsm = graph.add_asset("HSM", "hsm-01", attributes={"algorithm": "AES-256"})
    evidence = graph.add_evidence(
        {
            "target": hsm,
            "evidence_type": "RUNTIME_OBSERVED",
            "confidence": "HIGH",
            "facts": {"algorithm": "AES-256", "key_size": 256},
            "layer": "runtime",
            "source": "runtime.agent.preload_trace",
            "collector": "runtime.agent.preload_trace:trace_command",
            "observed_at": "2026-10-31T09:00:00+00:00",
        }
    )
    graph.assert_relationship(
        app,
        "uses",
        hsm,
        basis="RUNTIME_OBSERVATION",
        evidence_ids=[evidence],
    )
    view = S.View.from_graph(graph)
    assert view.asset_ids() == {app, hsm}
    assert len(view.relationships) == 1
    assert view.crypto and view.crypto[0]["algorithm"] == "AES-256"
    assert view.dependents(hsm) == [app]


# --------------------------------------------------------------------------- #
# served: a scenario is a request body, never a code path
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_engine_publishes_its_models_and_ops(authenticated_client):
    response = await authenticated_client.get("/api/v1/estate/evidence/simulation/engine/models")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert {model["id"] for model in payload["models"]} == S.catalogue_models()
    assert payload["ops"] == list(S.OPS)
    assert payload["examples"], "a caller should see a scenario before writing one"


@pytest.mark.asyncio
async def test_a_scenario_without_a_stored_estate_says_so_instead_of_projecting_nothing(
    authenticated_client,
):
    response = await authenticated_client.post(
        "/api/v1/estate/evidence/simulation/engine/run",
        json={"scenario": S.EXAMPLES[0]},
    )
    assert response.status_code == 404, response.text
    assert response.json()["detail"]["error"] == "no_estate_discovery"


@pytest.mark.asyncio
async def test_an_invalid_scenario_is_refused_before_it_is_run(authenticated_client):
    response = await authenticated_client.post(
        "/api/v1/estate/evidence/simulation/engine/run",
        json={"scenario": {"id": "x", "modifications": [{"op": "MELT", "target": "a"}]}},
    )
    # either the estate gate or the scenario check answers first; both refuse, neither runs
    assert response.status_code in (400, 404), response.text
    if response.status_code == 400:
        assert response.json()["detail"]["error"] == "invalid_scenario"
