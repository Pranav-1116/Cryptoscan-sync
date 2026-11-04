"""Cascade simulation: a failure travels, and the answer says where it stops.

A scenario asks what a *change* does to the six BOMs. A cascade asks a different
question — something stopped, what is reached — and it changes no evidence at all, so
the two failure modes this file guards against are:

* a cascade presented as a prediction of downtime. It propagates over *established*
  edges, states that redundancy and failover are not modelled, and counts the refused
  edges in its radius as blind spots rather than traversing them;
* "nothing reached" read as "nothing affected". A seed whose dependents were never
  collected resolves, reaches nothing, and says which of the two it is.
"""
from __future__ import annotations

import copy

import pytest

from shared_models import estate_twin as twin
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api
from test_estate_twin import _payload

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

BASE = "/api/v1/estate/evidence"

PG = "database:22ee6fc834d2a0668aa0ca94"
API_ASSET = "application:ce10861dcf977c3ba2fa702f"
HOST = "host:"


@pytest.fixture()
def graph():
    return build_graph(_payload())


def _asset_id(graph, name: str) -> str:
    for asset in graph.assets():
        if asset["name"] == name:
            return asset["asset_id"]
    raise AssertionError(f"no asset named {name}")


def _discover(http) -> dict:
    created = http.post(f"{BASE}/discover", json=_payload())
    assert created.status_code == 200, created.text
    return created.json()


# -- the walk --------------------------------------------------------------- #


def test_a_cascade_walks_away_from_the_seed_and_names_the_edge_it_arrived_by(graph):
    pg = _asset_id(graph, "PostgreSQL")

    result = twin.cascade(graph, {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [pg]})

    assert result["status"] == "SIMULATED"
    assert [seed["name"] for seed in result["seeds"]] == ["PostgreSQL"]
    first = result["waves"][0]
    assert first["depth"] == 1
    assert [asset["name"] for asset in first["assets"]] == ["Payment API"]
    assert first["assets"][0]["via"]["predicate"] == "depends_on"
    assert first["assets"][0]["via"]["meaning"]
    # the seed is where the cascade starts; it is not reported as something it reached
    assert pg not in [asset["asset_id"] for asset in result["affected_assets"]]


def test_a_cascade_reaches_the_business_system_holding_the_component(graph):
    pg = _asset_id(graph, "PostgreSQL")

    result = twin.cascade(graph, {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [pg]})

    systems = result["impact"]["business_systems"]
    assert [system["name"] for system in systems] == ["Payment System"]
    path = systems[0]["path"]
    # a route, not a number: seed -> ... -> system
    assert path[0]["name"] == "PostgreSQL"
    assert path[-1]["name"] == "Payment System"


def test_depth_bounds_the_walk(graph):
    pg = _asset_id(graph, "PostgreSQL")

    shallow = twin.cascade(graph, {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [pg], "depth": 1})
    deep = twin.cascade(graph, {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [pg], "depth": 3})

    assert shallow["depth"] == 1
    assert [wave["depth"] for wave in shallow["waves"]] == [1]
    assert deep["impact"]["counts"]["total"] > shallow["impact"]["counts"]["total"]


def test_an_algorithm_break_starts_from_every_use_at_once(graph):
    result = twin.cascade(graph, {"kind": "CASCADE_ALGORITHM_BREAK", "from": "AES-256-GCM"})

    assert result["status"] == "SIMULATED"
    assert len(result["seeds"]) >= 2, "every asset using the algorithm is a seed, not one"
    assert all("AES-256-GCM" in seed["reason"] for seed in result["seeds"])


def test_a_crypto_compromise_follows_the_crypto_edges_not_the_network(graph):
    hsm = _asset_id(graph, "HSM-03")

    result = twin.cascade(graph, {"kind": "CASCADE_CRYPTO_COMPROMISE", "targets": [hsm]})

    reached = {asset["name"]: asset["via_predicate"] for asset in result["affected_assets"]}
    assert reached.get("Payment API") == "uses_hsm"


def _trust_payload() -> dict:
    """A three-hop PKI chain with a sibling that shares the host but not the trust."""
    return {
        "estate": "Synthetic Bank",
        "assets": [
            {"ref": "root", "type": "CA", "name": "Bank Root CA"},
            {"ref": "issuing", "type": "CA", "name": "Bank Issuing CA"},
            {"ref": "cert", "type": "CERTIFICATE", "name": "payments.bank:443"},
            {"ref": "api", "type": "APPLICATION", "name": "Payment API"},
            {"ref": "batch", "type": "APPLICATION", "name": "Batch Job"},
            {"ref": "host", "type": "HOST", "name": "payment-prod-01"},
        ],
        "evidence": [
            {"evidence_id": "ev-1", "source": "probe", "evidence_type": "NETWORK_ACTIVE_OBSERVED",
             "target": "cert", "layer": "NETWORK_TRANSPORT",
             "facts": {"algorithm": "RSA", "protocol": "TLSv1.3"}},
        ],
        "relationships": [
            {"subject": "issuing", "predicate": "issued_by", "object": "root",
             "basis": "CONFIGURATION", "evidence_ids": ["ev-1"]},
            {"subject": "cert", "predicate": "issued_by", "object": "issuing",
             "basis": "CONFIGURATION", "evidence_ids": ["ev-1"]},
            {"subject": "api", "predicate": "uses_certificate", "object": "cert",
             "basis": "CONFIGURATION", "evidence_ids": ["ev-1"]},
            # the sibling shares the host: a network walk would reach it, a trust walk must not
            {"subject": "batch", "predicate": "runs_on", "object": "host",
             "basis": "DEPLOYMENT_CONFIG", "evidence_ids": ["ev-1"]},
            {"subject": "api", "predicate": "runs_on", "object": "host",
             "basis": "DEPLOYMENT_CONFIG", "evidence_ids": ["ev-1"]},
        ],
    }


def test_a_trust_compromise_walks_the_vouching_edges_and_stops_before_the_host():
    graph = build_graph(_trust_payload())
    root = _asset_id(graph, "Bank Root CA")

    result = twin.cascade(graph, {"kind": "CASCADE_TRUST_COMPROMISE", "targets": [root], "depth": 4})

    assert result["status"] == "SIMULATED"
    reached = {asset["name"]: asset["via_predicate"] for asset in result["affected_assets"]}
    assert reached == {
        "Bank Issuing CA": "issued_by",
        "payments.bank:443": "issued_by",
        "Payment API": "uses_certificate",
    }
    assert "Batch Job" not in reached, "sharing a host is not inheriting trust"
    assert result["bom_diff"] == {}, "a trust walk changes no evidence fact"


def test_the_trust_cascade_names_its_trust_store_and_revocation_blind_spots():
    graph = build_graph(_trust_payload())
    root = _asset_id(graph, "Bank Root CA")

    result = twin.cascade(graph, {"kind": "CASCADE_TRUST_COMPROMISE", "targets": [root]})

    limits = " ".join(result["limits"]).lower()
    assert "trust store" in limits
    assert "revocation" in limits and "ocsp" in limits
    assert "name constraints" in limits
    # the radius is stated as a superset, not as a correct PKI walk
    assert "superset" in limits


# -- what a cascade refuses to claim ---------------------------------------- #


def test_a_cascade_says_it_modelled_no_downtime_and_has_no_bom_diff(graph):
    pg = _asset_id(graph, "PostgreSQL")

    result = twin.cascade(graph, {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [pg]})

    assert result["bom_diff"] == {}
    assert "no evidence fact" in result["bom_diff_note"]
    assert result["estate_copy"] is None
    limits = " ".join(result["limits"])
    assert "redundancy" in limits
    assert "not seconds" in limits or "graph distance" in limits
    # read-only, and checked rather than promised
    assert result["live_state_modified"] is False
    assert result["live_projection_unchanged"] is True
    assert graph_fingerprint_stable(result)


def graph_fingerprint_stable(result) -> bool:
    # the run reports the projection it captured; a cascade must not produce a second one
    return result["simulated_projection_id"] == result["base_projection_id"]


def test_a_cascade_does_not_traverse_a_refused_edge_and_counts_it_instead(graph):
    pg = _asset_id(graph, "PostgreSQL")

    result = twin.cascade(graph, {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [pg]})

    # the imported "uses" edge from the API to the database was refused; it is a blind spot
    assert result["unknown"]["unresolved_relationships_in_radius"] >= 1
    assert any(blocker["kind"] == "UNRESOLVED_RELATIONSHIP" for blocker in result["blockers"])


def test_a_seed_that_starts_nothing_is_not_reported_as_no_impact(graph):
    ghost = _asset_id(graph, "legacy-batch")

    result = twin.cascade(graph, {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [ghost]})

    assert result["status"] == "NO_MATCH"
    assert "not 'nothing is affected'" in result["detail"]
    assert result["seeds"], "the seed resolved — that is a different answer from 'no such asset'"


def test_an_unresolvable_seed_says_it_was_not_found(graph):
    result = twin.cascade(graph, {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": ["no-such-asset"]})

    assert result["status"] == "NO_MATCH"
    assert result["unresolved_seeds"] == ["no-such-asset"]
    assert "not 'no impact'" in result["detail"]


def test_a_cascade_without_a_seed_is_refused(graph):
    result = twin.cascade(graph, {"kind": "CASCADE_ASSET_UNAVAILABLE"})

    assert result["status"] == "INVALID_SCENARIO"
    assert "targets" in result["detail"]


def test_the_estate_is_not_modified_by_a_cascade(graph):
    before = graph.fingerprint()
    pg = _asset_id(graph, "PostgreSQL")

    twin.cascade(graph, {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [pg]})

    assert graph.fingerprint() == before


# -- preview agrees with the run -------------------------------------------- #


def test_the_cascade_preview_counts_what_the_run_will_reach(graph):
    pg = _asset_id(graph, "PostgreSQL")
    scenario = {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [pg], "depth": 3}

    preview = twin.preview(graph, scenario)
    result = twin.simulate(graph, scenario)

    assert preview["status"] == "WOULD_MATCH"
    assert preview["status"] == "WOULD_MATCH" and result["status"] == "SIMULATED"
    assert preview["affected_asset_count"] == len(result["affected_assets"])
    assert [wave["count"] for wave in preview["wave_counts"]] == [wave["count"] for wave in result["waves"]]
    assert preview["live_state_modified"] is False


def test_a_cascade_preview_that_reaches_nothing_is_not_a_statement_of_safety(graph):
    ghost = _asset_id(graph, "legacy-batch")

    preview = twin.preview(graph, {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [ghost]})

    assert preview["status"] == "WOULD_NOT_MATCH"
    assert "nothing reached" in preview["note"]


# -- the wider vocabulary --------------------------------------------------- #


def test_changing_a_key_size_edits_only_the_size():
    payload = _payload()
    payload["evidence"].append(
        {"evidence_id": "ev-rsa", "source": "probe", "evidence_type": "RUNTIME_OBSERVED",
         "target": "api", "layer": "APPLICATION",
         "facts": {"algorithm": "RSA-2048", "key_size": 2048, "role": "sign"}}
    )
    graph = build_graph(payload)

    result = twin.simulate(graph, {"kind": "CHANGE_KEY_SIZE", "from": "RSA-2048", "key_size": 3072})

    assert result["status"] == "SIMULATED"
    assert result["matched_evidence"] == 1
    effect = result["effects"][0]
    assert effect["before"]["algorithm"] == effect["after"]["algorithm"] == "RSA-2048"
    assert effect["after"]["key_size"] == 3072


def test_a_removed_component_is_not_replaced_by_anything():
    result = twin.simulate(build_graph(_payload()), {"kind": "REMOVE_COMPONENT", "from": "OpenSSL"})

    assert result["status"] == "SIMULATED"
    effect = result["effects"][0]
    assert effect["after"]["version"] is None
    assert effect["after"]["simulated_removed_component"]["version"] == "3.0.13"


def test_the_vulnerable_sweep_uses_the_registry_not_a_typed_list():
    payload = _payload()
    payload["evidence"].extend([
        {"evidence_id": "ev-rsa", "source": "probe", "evidence_type": "RUNTIME_OBSERVED",
         "target": "api", "layer": "APPLICATION", "facts": {"algorithm": "RSA-2048", "role": "sign"}},
        {"evidence_id": "ev-ecc", "source": "probe", "evidence_type": "RUNTIME_OBSERVED",
         "target": "lb", "layer": "NETWORK_TRANSPORT", "facts": {"algorithm": "ECDSA-P-256", "role": "sign"}},
    ])
    graph = build_graph(payload)

    result = twin.simulate(graph, {"kind": "MIGRATE_QUANTUM_VULNERABLE", "to": "ML-KEM-768"})

    assert result["status"] == "SIMULATED"
    assert result["matched_evidence"] == 2, "both Shor-vulnerable artefacts, and only those"
    moved = {effect["before"]["algorithm"] for effect in result["effects"]}
    assert moved == {"RSA-2048", "ECDSA-P-256"}
    # AES is Grover-weakened, not Shor-broken, so it stays
    assert all(effect["after"]["algorithm"] == "ML-KEM-768" for effect in result["effects"])


def test_an_unmatched_sweep_says_the_estate_holds_no_vulnerable_algorithm():
    result = twin.simulate(build_graph(_payload()), {"kind": "MIGRATE_QUANTUM_VULNERABLE", "to": "ML-KEM-768"})

    assert result["status"] == "NO_MATCH"
    assert "not 'no impact'" in result["detail"]


# -- the workspace exposes both families ------------------------------------ #


def test_the_catalog_lists_both_families_and_what_each_one_is(api):
    http, _session = api
    _discover(http)

    body = http.get(f"{BASE}/simulation/catalog").json()

    modes = {mode["mode"]: mode for mode in body["modes"]}
    assert set(modes) == {"SCENARIO", "CASCADE"}
    assert modes["CASCADE"]["has_bom_diff"] is False
    assert modes["SCENARIO"]["changes_evidence"] is True
    by_kind = {entry["kind"]: entry for entry in body["kinds"]}
    assert by_kind["CASCADE_ALGORITHM_BREAK"]["mode"] == "CASCADE"
    assert by_kind["MIGRATE_QUANTUM_VULNERABLE"]["mode"] == "SCENARIO"
    assert by_kind["CASCADE_TRUST_COMPROMISE"]["mode"] == "CASCADE"
    assert by_kind["COMPOSITE"]["mode"] == "SCENARIO"
    assert len(by_kind) == 13
    for entry in body["kinds"]:
        assert entry["does_not_answer"]


def test_the_catalog_offers_questions_this_estate_can_actually_be_asked(api):
    http, _session = api
    _discover(http)

    presets = http.get(f"{BASE}/simulation/catalog").json()["presets"]

    assert presets, "a workspace with an empty form is a guessing game"
    assert any(preset["mode"] == "CASCADE" for preset in presets)
    for preset in presets:
        assert preset["why"]
        assert preset["scenario"]["kind"] == preset["kind"]


def test_a_preset_is_runnable_as_offered(api):
    http, _session = api
    _discover(http)
    presets = http.get(f"{BASE}/simulation/catalog").json()["presets"]
    cascade = next(preset for preset in presets if preset["kind"] == "CASCADE_ASSET_UNAVAILABLE")

    planned = http.post(f"{BASE}/simulation/plan", json={**cascade["scenario"], "depth": 3})

    assert planned.status_code == 200, planned.text
    assert planned.json()["status"] == "WOULD_MATCH"


def test_a_cascade_run_is_stored_quarantined_with_its_kind(api):
    http, _session = api
    discover = _discover(http)
    graph = build_graph(_payload())
    pg = _asset_id(graph, "PostgreSQL")

    run = http.post(
        f"{BASE}/simulation/run",
        json={"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [pg], "depth": 3, "label": "db down"},
    )

    assert run.status_code == 200, run.text
    body = run.json()
    assert body["mode"] == "CASCADE"
    assert body["status"] == "SIMULATED"
    assert body["persisted"] is True
    assert body["bom_diff"] == {}
    assert body["live_state_modified"] is False
    assert body["simulation_record"]["quarantined"] is True

    history = http.get(f"{BASE}/simulation/runs").json()
    row = next(item for item in history["simulations"] if item["simulation_id"] == body["simulation_id"])
    assert row["kind"] == "CASCADE_ASSET_UNAVAILABLE"
    assert row["computed_against"] == discover["projection_id"]


def test_a_cascade_and_a_scenario_with_the_same_words_are_different_questions(graph):
    pg = _asset_id(graph, "PostgreSQL")

    cascade = twin.cascade(graph, {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [pg]})
    scenario = twin.simulate(graph, {"kind": "RETIRE_ALGORITHM", "from": "AES-256-GCM"})

    assert cascade["simulation_id"] != scenario["simulation_id"]
    assert cascade["bom_diff"] == {} and scenario["bom_diff"]


def test_the_run_request_carries_depth_to_the_engine(api):
    http, _session = api
    _discover(http)
    graph = build_graph(_payload())
    pg = _asset_id(graph, "PostgreSQL")

    one = http.post(
        f"{BASE}/simulation/run",
        json={"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [pg], "depth": 1, "persist": False},
    ).json()
    three = http.post(
        f"{BASE}/simulation/run",
        json={"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [pg], "depth": 3, "persist": False},
    ).json()

    assert one["depth"] == 1 and three["depth"] == 3
    assert one["impact"]["counts"]["total"] < three["impact"]["counts"]["total"]
    assert one["simulation_id"] != three["simulation_id"], "depth is part of the question"


def test_a_cascade_that_reaches_nothing_is_refused_a_row(api):
    http, _session = api
    _discover(http)
    graph = build_graph(_payload())
    ghost = _asset_id(graph, "legacy-batch")

    body = http.post(
        f"{BASE}/simulation/run",
        json={"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [ghost]},
    ).json()

    assert body["status"] == "NO_MATCH"
    assert body["persisted"] is False
    assert http.get(f"{BASE}/simulation/runs").json()["count"] == 0


def test_the_scenario_engine_still_works_after_the_wider_vocabulary(graph):
    payload = copy.deepcopy(_payload())

    result = twin.simulate(build_graph(payload), {"kind": "REPLACE_ALGORITHM", "from": "AES-256-GCM", "to": "ML-KEM"})

    assert result["status"] == "SIMULATED"
    assert set(result["bom_diff"]) == {"SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM"}
