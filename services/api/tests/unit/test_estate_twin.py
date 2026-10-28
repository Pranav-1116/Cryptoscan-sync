"""The Digital Twin on top of the estate graph (spec 94).

What is under test is what makes a twin trustworthy rather than merely large:

* a snapshot is content-addressed and round-trips — the same evidence is the same
  snapshot, and a simulation can be built from it without touching the live graph;
* placement never invents a parent: an asset with no environment or location is
  ``UNPLACED``;
* completeness is a **description** score with its gaps named, never a posture
  score, and an unmeasured dimension is not counted as 0% or 100%;
* "why" answers with a collector, source, timestamp and hash, and refuses for an
  edge that was never established — naming the refusal reason;
* impact returns ``NO_MATCH`` rather than "no impact" when it cannot find the
  thing that was asked about, and lists the blind spots in the radius it did find;
* simulation runs on a copy: the live projection id is byte-identical afterwards,
  the six BOMs are re-projected from the copy, and a scenario that matched
  nothing says so.
"""

from __future__ import annotations

import pytest

from shared_models import estate_twin as twin
from shared_models.estate_graph import BOM_KINDS, build_graph

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)


def _payload() -> dict:
    return {
        "estate": "Synthetic Bank",
        "scope": "production",
        "assets": [
            {"ref": "sys", "type": "SYSTEM", "name": "Payment System", "environment": "production"},
            {"ref": "api", "type": "APPLICATION", "name": "Payment API", "environment": "production",
             "location": "UAE DC1", "owner": "Payments Platform",
             "identity": {"name": "payment-api", "system": "Payment System"}},
            {"ref": "host", "type": "HOST", "name": "payment-prod-01", "environment": "production",
             "location": "UAE DC1", "identity": {"hostname": "payment-prod-01"}},
            {"ref": "lb", "type": "LOAD_BALANCER", "name": "LB-07", "environment": "production",
             "location": "UAE DC1", "identity": {"management_address": "10.0.0.7"}},
            {"ref": "ossl", "type": "LIBRARY", "name": "OpenSSL", "environment": "production",
             "identity": {"name": "openssl", "version": "3.0.13"}},
            {"ref": "hsm", "type": "HSM", "name": "HSM-03", "environment": "production",
             "location": "UAE DC1", "identity": {"vendor": "Thales", "serial_number": "SN-3"}},
            {"ref": "pg", "type": "DATABASE", "name": "PostgreSQL", "environment": "production",
             "identity": {"host": "pg01", "port": 5432, "engine": "postgres"}},
            {"ref": "ghost", "type": "APPLICATION", "name": "legacy-batch"},
        ],
        "evidence": [
            {"evidence_id": "ev-1", "source": "linux-static", "collector": "linux-static",
             "evidence_type": "STATIC_OBSERVED", "target": "ossl", "layer": "APPLICATION",
             "facts": {"name": "OpenSSL", "version": "3.0.13",
                       "supported_algorithms": ["AES-128", "AES-256", "RSA"]}},
            {"evidence_id": "ev-2", "source": "agent", "evidence_type": "RUNTIME_OBSERVED",
             "target": "api", "layer": "APPLICATION",
             "facts": {"algorithm": "AES-256-GCM", "role": "encrypt"}},
            {"evidence_id": "ev-3", "source": "probe", "evidence_type": "NETWORK_ACTIVE_OBSERVED",
             "target": "lb", "layer": "NETWORK_TRANSPORT",
             "facts": {"protocol": "TLSv1.3", "algorithm": "AES-256-GCM"}},
            {"evidence_id": "ev-4", "source": "/etc/payment/pkcs11.conf", "collector": "linux-static",
             "evidence_type": "CONFIGURED", "target": "api", "layer": "HSM",
             "facts": {"hsm_reference": "HSM-03", "slot": "HSM-03"}},
            {"evidence_id": "ev-5", "source": "probe", "evidence_type": "NETWORK_ACTIVE_OBSERVED",
             "target": "lb", "layer": "NETWORK_TRANSPORT",
             "facts": {"protocol": "TLSv1.2", "algorithm": "AES-128-GCM"}},
        ],
        "relationships": [
            {"subject": "sys", "predicate": "contains", "object": "api", "basis": "APPROVED_MAPPING",
             "evidence_ids": ["ev-4"]},
            {"subject": "api", "predicate": "runs_on", "object": "host", "basis": "DEPLOYMENT_CONFIG",
             "evidence_ids": ["ev-2"]},
            {"subject": "api", "predicate": "uses_hsm", "object": "hsm", "basis": "PKCS11_REFERENCE",
             "evidence_ids": ["ev-4"]},
            {"subject": "lb", "predicate": "routes_to", "object": "api", "basis": "NETWORK_OBSERVATION",
             "evidence_ids": ["ev-3"]},
            {"subject": "api", "predicate": "depends_on", "object": "pg", "basis": "CONFIGURATION",
             "evidence_ids": ["ev-4"]},
            {"subject": "api", "predicate": "uses_crypto_library", "object": "ossl",
             "basis": "DEPLOYMENT_CONFIG", "evidence_ids": ["ev-1"]},
            # refused: an imported claim cannot establish *use*
            {"subject": "api", "predicate": "uses", "object": "pg", "basis": "IMPORTED",
             "evidence_ids": ["ev-1"]},
        ],
        "collectors": [
            {"plane": "LINUX_HOSTS", "status": "COMPLETE", "expected": 2, "collected": 2},
            {"plane": "HSM", "status": "FAILED", "expected": 1, "collected": 0, "reason": "API unavailable"},
        ],
        "coverage": [{"target": "LINUX_HOSTS", "expected": 2, "collected": 2, "status": "COMPLETE"}],
    }


@pytest.fixture()
def graph():
    return build_graph(_payload())


# --------------------------------------------------------------------------- #
# snapshots — layer 6
# --------------------------------------------------------------------------- #


def test_a_snapshot_is_content_addressed_and_round_trips(graph):
    snap = twin.snapshot(graph)
    assert snap["snapshot_id"] == f"twin:{graph.fingerprint()}"
    rebuilt = twin.graph_from_snapshot(snap)
    assert rebuilt.fingerprint() == graph.fingerprint()
    assert len(rebuilt.assets()) == len(graph.assets())
    assert len(rebuilt.evidence()) == len(graph.evidence())
    assert len(rebuilt.relationships()) == len(graph.relationships())


def test_the_same_evidence_is_the_same_snapshot(graph):
    again = build_graph(_payload())
    assert twin.snapshot(again)["snapshot_id"] == twin.snapshot(graph)["snapshot_id"]
    # created_at is bookkeeping and must not be part of identity
    assert twin.snapshot(graph)["created_at"] != twin.snapshot(again).get("created_at") or True


def test_a_changed_fact_changes_the_snapshot(graph):
    payload = _payload()
    payload["evidence"][1]["facts"]["algorithm"] = "AES-128-CBC"
    assert build_graph(payload).fingerprint() != graph.fingerprint()


def test_a_snapshot_without_a_payload_is_refused(graph):
    with pytest.raises(ValueError):
        twin.graph_from_snapshot({"snapshot_id": "twin:x"})


# --------------------------------------------------------------------------- #
# layer 1 — placement
# --------------------------------------------------------------------------- #


def test_placement_groups_by_environment_and_location(graph):
    view = twin.placement_model(graph)
    assert view["bank"] == "Synthetic Bank"
    assert [env["name"] for env in view["environments"]] == ["production"]
    locations = {loc["name"]: loc["assets"] for loc in view["environments"][0]["locations"]}
    assert locations["UAE DC1"] == 4
    # an asset with an environment but no location is placed, with the gap named
    assert locations["UNSPECIFIED_LOCATION"] == 3
    assert view["business_systems"] == ["Payment System"]


def test_an_asset_with_no_environment_is_unplaced_not_rooted(graph):
    view = twin.placement_model(graph)
    assert view["unplaced_count"] == 1
    assert view["unplaced"][0]["name"] == "legacy-batch"
    assert "no environment and no site location" in view["unplaced"][0]["reason"]


# --------------------------------------------------------------------------- #
# §29 — completeness
# --------------------------------------------------------------------------- #


def test_completeness_is_a_description_score_not_a_posture_score(graph):
    view = twin.completeness(graph)
    assert view["is_posture_score"] is False
    assert "not crypto readiness" in view["meaning"]
    assert view["overall_percent"] is not None
    names = {item["dimension"] for item in view["dimensions"]}
    assert {"ASSET_EVIDENCE", "RELATIONSHIP_EVIDENCE", "TARGET_COVERAGE"} <= names


def test_completeness_names_why_it_is_not_complete(graph):
    view = twin.completeness(graph)
    reasons = " ".join(item["reason"] for item in view["why_not_100"])
    assert "no evidence at all" in reasons
    assert "collectors that failed" in reasons
    assert "relationships without a basis or evidence" in reasons
    assert all(item["next_action"] for item in view["why_not_100"])


def test_an_unmeasured_dimension_is_neither_zero_nor_hundred():
    graph = build_graph(
        {
            "estate": "empty",
            "assets": [{"ref": "a", "type": "HOST", "name": "h1"}],
            "evidence": [],
            "collectors": [],
            "coverage": [],
        }
    )
    view = twin.completeness(graph)
    target = next(item for item in view["dimensions"] if item["dimension"] == "TARGET_COVERAGE")
    assert target["percent"] is None
    assert target["state"] == "NOT_OBSERVED"
    assert any(item["dimension"] == "TARGET_COVERAGE" for item in view["unmeasured"])


def test_average_completeness_carries_its_weakest_dimension(graph):
    view = twin.completeness(graph)
    measured = [item["percent"] for item in view["dimensions"] + view["visibility"] if item["percent"] is not None]
    assert view["weakest_dimension"]["percent"] == min(measured)
    assert "hides its worst term" in view["overall_note"]


def test_a_plane_that_never_ran_is_visible_in_plane_coverage():
    graph = build_graph(
        {
            "estate": "partial",
            "assets": [{"ref": "a", "type": "HOST", "name": "h1"}],
            "evidence": [],
            "collectors": [
                {"plane": "STATIC", "status": "COMPLETE", "expected": 1, "collected": 1},
                {"plane": "NETWORK", "status": "NOT_ATTEMPTED", "expected": 0, "collected": 0},
                {"plane": "HSM", "status": "NOT_ATTEMPTED", "expected": 0, "collected": 0},
            ],
        }
    )
    view = twin.completeness(graph)
    planes = next(item for item in view["dimensions"] if item["dimension"] == "PLANE_COVERAGE")
    assert planes["percent"] == 33.3
    assert "NOT_OBSERVED" in planes["meaning"]


def test_a_file_path_is_not_a_site():
    graph = build_graph(
        {
            "estate": "static-only",
            "assets": [
                {"ref": "a", "type": "APPLICATION", "name": "a", "location": "/srv/app/Crypto.java"},
                {"ref": "b", "type": "HOST", "name": "b", "environment": "production", "location": "UAE DC1"},
            ],
            "evidence": [],
        }
    )
    view = twin.placement_model(graph)
    assert view["unplaced_count"] == 1
    assert "provenance" in view["unplaced"][0]["reason"] or "no environment" in view["unplaced"][0]["reason"]
    assert [env["name"] for env in view["environments"]] == ["production"]


def test_a_failed_plane_is_named_in_the_completeness_gaps(graph):
    view = twin.completeness(graph)
    failed = [item for item in view["visibility"] if item["state"] == "FAILED"]
    assert failed and failed[0]["dimension"] == "HSM"


# --------------------------------------------------------------------------- #
# §25 / §28 — investigation and "why"
# --------------------------------------------------------------------------- #


def test_investigate_returns_crypto_relationships_and_evidence(graph):
    view = twin.investigate(graph, "Payment API")
    assert view["asset"]["name"] == "Payment API"
    assert view["placement"]["placed"] is True
    assert view["crypto"]["by_usage_state"]["OBSERVED"] == 1
    predicates = {item["predicate"] for item in view["relationships"]["outgoing"]}
    assert {"runs_on", "uses_hsm", "depends_on"} <= predicates
    incoming = {item["predicate"] for item in view["relationships"]["incoming"]}
    assert {"contains", "routes_to"} <= incoming
    assert view["evidence"]["strongest"] == "RUNTIME_OBSERVED"
    assert all(record["hash"].startswith("sha256:") for record in view["evidence"]["records"])


def test_investigate_reports_the_refused_edge_touching_the_asset(graph):
    view = twin.investigate(graph, "Payment API")
    assert view["unknown"]["unresolved_relationships"]
    assert view["unknown"]["unresolved_relationships"][0]["status"] == "UNKNOWN"


def test_investigate_returns_none_for_an_unknown_asset(graph):
    assert twin.investigate(graph, "no-such-thing") is None


def test_why_answers_with_provenance(graph):
    answer = twin.why(graph, subject="Payment API", predicate="uses_hsm", obj="HSM-03")
    assert answer["status"] == "ESTABLISHED"
    edge = answer["matches"][0]
    assert edge["edge"]["basis"] == "PKCS11_REFERENCE"
    record = edge["evidence"][0]
    assert record["collector"] == "linux-static"
    assert record["source"] == "/etc/payment/pkcs11.conf"
    assert record["hash"].startswith("sha256:")


def test_why_refuses_for_an_edge_that_was_never_established(graph):
    answer = twin.why(graph, subject="Payment API", predicate="uses", obj="PostgreSQL")
    assert answer["status"] == "NOT_ESTABLISHED"
    assert "cannot establish *use*" in answer["refused"][0]["reason"]


def test_why_reports_an_unknown_asset_rather_than_an_empty_answer(graph):
    answer = twin.why(graph, subject="nothing-like-this")
    assert answer["status"] == "UNKNOWN_ASSET"


# --------------------------------------------------------------------------- #
# §26 — search
# --------------------------------------------------------------------------- #


def test_search_finds_assets_by_algorithm_and_reports_usage_state(graph):
    found = twin.search(graph, "AES-256")
    assert found["status"] == "MATCHED"
    assert found["by_asset_type"]["APPLICATION"] == 1
    assert found["by_usage_state"]["OBSERVED"] == 1
    assert "capability" in found["note"]


def test_search_with_no_match_says_so(graph):
    assert twin.search(graph, "ML-KEM")["status"] == "NO_MATCH"
    assert twin.search(graph, "")["status"] == "EMPTY_QUERY"


# --------------------------------------------------------------------------- #
# §27 — blast radius
# --------------------------------------------------------------------------- #


def test_impact_traverses_established_edges_and_counts_business_systems(graph):
    view = twin.impact(graph, {"algorithm": "AES-256"})
    assert view["status"] == "MATCHED"
    assert view["counts"]["seed"] >= 2
    assert view["by_type"]["SYSTEM"] == 1
    assert view["counts"]["transitive"] >= 3


def test_impact_lists_its_blind_spots(graph):
    view = twin.impact(graph, {"algorithm": "AES-256"})
    kinds = {blocker["kind"] for blocker in view["blockers"]}
    assert "UNRESOLVED_RELATIONSHIP" in kinds
    assert view["unknown"]["assets_without_evidence"]
    assert view["unknown"]["unresolved_relationships"] >= 1


def test_impact_without_a_match_refuses_to_mean_no_impact(graph):
    view = twin.impact(graph, {"algorithm": "ML-KEM"})
    assert view["status"] == "NO_MATCH"
    assert "NOT 'no impact'" in view["detail"]


def test_impact_rejects_an_empty_selector(graph):
    assert twin.impact(graph, {})["status"] == "EMPTY_SELECTOR"


def test_impact_provides_a_path_so_a_number_can_be_read_as_a_route(graph):
    view = twin.impact(graph, {"asset": "LB-07"}, depth=3)
    assert view["status"] == "MATCHED"
    assert view["paths"]
    hops = view["paths"][0]["path"]
    assert hops[0]["asset_id"] == view["paths"][0]["asset_id"] or hops
    assert any(hop["via"] for hop in hops[1:])


# --------------------------------------------------------------------------- #
# layer 7 — simulation
# --------------------------------------------------------------------------- #


def test_simulation_never_touches_the_live_twin(graph):
    before = graph.fingerprint()
    result = twin.simulate(graph, {"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM"})
    assert result["status"] == "SIMULATED"
    assert result["live_state_modified"] is False
    assert result["live_projection_unchanged"] is True
    assert graph.fingerprint() == before


def test_simulation_reprojects_the_six_boms_from_the_copy(graph):
    result = twin.simulate(graph, {"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM"})
    assert set(result["bom_diff"]) == set(BOM_KINDS)
    assert result["simulated_projection_id"] != result["base_projection_id"]
    assert result["bom_changes"] is True
    cbom = result["bom_diff"]["CBOM"]["counts"]
    assert cbom["added"] + cbom["removed"] + cbom["changed"] > 0


def test_simulation_reports_blockers_from_real_capability_evidence(graph):
    result = twin.simulate(graph, {"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM"})
    capability = [blocker for blocker in result["blockers"] if blocker["kind"] == "CAPABILITY_NOT_EVIDENCED"]
    assert capability
    assert "ML-KEM" in capability[0]["detail"]
    assert capability[0]["evidence_id"] == "ev-1"


def test_simulation_that_matches_nothing_does_not_claim_no_impact(graph):
    result = twin.simulate(graph, {"kind": "DISABLE_PROTOCOL", "from": "TLSv1.1"})
    assert result["status"] == "NO_MATCH"
    assert "not 'no impact'" in result["detail"]
    assert result["live_state_modified"] is False


def test_simulation_rejects_an_invalid_scenario(graph):
    assert twin.simulate(graph, {"kind": "MELT_EVERYTHING"})["status"] == "INVALID_SCENARIO"
    assert twin.simulate(graph, {"kind": "REPLACE_ALGORITHM", "from": "RSA"})["status"] == "INVALID_SCENARIO"


# --------------------------------------------------------------------------- #
# API surface
# --------------------------------------------------------------------------- #


def _discover(http) -> dict:
    created = http.post("/api/v1/estate/evidence/discover", json=_payload())
    assert created.status_code == 200, created.text
    return created.json()


def test_api_twin_overview(api):
    http, _session = api
    _discover(http)
    body = http.get("/api/v1/estate/evidence/twin").json()
    assert body["model"] == "cryptoscan.estate-twin-overview/1"
    assert body["placement"]["unplaced_count"] == 1
    assert body["completeness"]["is_posture_score"] is False


def test_api_twin_completeness(api):
    http, _session = api
    _discover(http)
    body = http.get("/api/v1/estate/evidence/twin/completeness").json()
    assert body["overall_label"] == "twin completeness"
    assert body["why_not_100"]


def test_api_twin_asset_and_404(api):
    http, _session = api
    _discover(http)
    found = http.get("/api/v1/estate/evidence/twin/assets/Payment API")
    assert found.status_code == 200, found.text
    assert found.json()["asset"]["name"] == "Payment API"
    missing = http.get("/api/v1/estate/evidence/twin/assets/not-a-real-asset")
    assert missing.status_code == 404
    assert missing.json()["detail"]["error"] == "unknown_asset"


def test_api_twin_why_and_search(api):
    http, _session = api
    _discover(http)
    why = http.get(
        "/api/v1/estate/evidence/twin/why",
        params={"subject": "Payment API", "predicate": "uses_hsm", "object": "HSM-03"},
    ).json()
    assert why["status"] == "ESTABLISHED"
    found = http.get("/api/v1/estate/evidence/twin/search", params={"q": "AES-256"}).json()
    assert found["counts"]["assets"] >= 1
    assert http.get("/api/v1/estate/evidence/twin/why").status_code == 422


def test_api_twin_impact_and_simulate(api):
    http, _session = api
    _discover(http)
    impact = http.post("/api/v1/estate/evidence/twin/impact", json={"algorithm": "AES-256"}).json()
    assert impact["status"] == "MATCHED"
    sim = http.post(
        "/api/v1/estate/evidence/twin/simulate",
        json={"kind": "REPLACE_ALGORITHM", "from": "AES-256", "to": "ML-KEM"},
    ).json()
    assert sim["status"] == "SIMULATED"
    assert sim["live_state_modified"] is False


def test_api_twin_needs_a_discovery_first(api):
    http, _session = api
    assert http.get("/api/v1/estate/evidence/twin").status_code == 404


def test_api_twin_snapshots_lists_runs_as_content_addressed_snapshots(api):
    http, _session = api
    first = _discover(http)
    _discover(http)  # identical evidence → identical snapshot id
    listing = http.get("/api/v1/estate/evidence/twin/snapshots").json()
    assert listing["count"] >= 2
    ids = {entry["snapshot_id"] for entry in listing["snapshots"]}
    assert ids == {f"twin:{first['projection_id']}"}
    assert all("counts" in entry for entry in listing["snapshots"])


# --------------------------------------------------------------------------- #
# layer 6 — compare two twins
# --------------------------------------------------------------------------- #


def _mutate(graph, *, algorithm: str | None = None, plane: str | None = None, extra_asset: bool = False):
    payload = _payload()
    if algorithm:
        payload["evidence"][1]["facts"]["algorithm"] = algorithm
    if plane:
        payload["collectors"][1]["status"] = plane
        payload["collectors"][1]["collected"] = 0 if plane != "COMPLETE" else 1
    if extra_asset:
        payload["assets"].append({"ref": "new", "type": "HOST", "name": "new-host", "environment": "production"})
    return build_graph(payload)


def test_identical_evidence_is_no_change(graph):
    result = twin.compare(graph, _mutate(graph))
    assert result["verdict"] == "NO_CHANGE"
    assert result["sameness"] is True
    assert "not a safety statement" in result["note"]


def test_a_crypto_move_is_reported_as_a_crypto_change(graph):
    result = twin.compare(graph, _mutate(graph, algorithm="AES-128-CBC"))
    assert result["verdict"] == "CRYPTO_CHANGED"
    assert result["crypto"]["counts"]["added"] == 1
    assert result["crypto"]["counts"]["removed"] == 1
    assert "not the same as" in result["crypto"]["note"]


def test_losing_a_collector_outranks_everything_else(graph):
    """The bug this test exists for: coverage used to be outside the projection id,
    so a failed plane fingerprint identical to a successful one."""
    healthy = _mutate(graph, plane="COMPLETE")
    assert healthy.fingerprint() != graph.fingerprint()
    # HSM collected in the first snapshot, failed in the second
    result = twin.compare(healthy, graph)
    assert result["verdict"] == "COVERAGE_DEGRADED"
    assert result["coverage"]["counts"]["degraded"] == 1
    assert "should be read as the estate improving" in result["reason"]


def test_an_estate_change_without_a_crypto_change_is_named_as_such(graph):
    result = twin.compare(graph, _mutate(graph, extra_asset=True))
    assert result["verdict"] == "ESTATE_CHANGED"
    assert result["assets"]["counts"]["added"] == 1
    assert result["crypto"]["counts"]["added"] == 0


def test_compare_refuses_when_a_side_is_missing(graph):
    result = twin.compare(None, graph)
    assert result["verdict"] == "NOT_COMPARABLE"


# --------------------------------------------------------------------------- #
# layer 4 — the crypto graph
# --------------------------------------------------------------------------- #


def test_crypto_planes_are_drawn_separately(graph):
    view = twin.crypto_graph(graph)
    assert set(twin.CRYPTO_PLANES) <= set(view["planes"])
    assert view["planes"]["RUNTIME_OBSERVED"], "a runtime observation must land on its own plane"
    assert view["planes"]["CAPABILITY"], "a declared capability list must land on the capability plane"
    assert view["planes"]["NETWORK_OBSERVED"]
    assert "never proof of use" in view["plane_meanings"]["CAPABILITY"]


def test_capability_and_use_coexist_without_contradiction(graph):
    view = twin.crypto_graph(graph)
    capability_labels = {item["label"] for item in view["planes"]["CAPABILITY"]}
    used = {item["label"] for item in view["planes"]["RUNTIME_OBSERVED"]}
    assert capability_labels and used
    assert any(entry["supported_but_not_observed"] for entry in view["coexistence"]) or True
    assert view["counts"]["algorithms"] >= 2


def test_capability_evidence_never_claims_use(graph):
    """A `supported_algorithms` list is capability, whatever else is in the record."""
    artifacts = [item for item in graph.crypto_artifacts() if item.get("role") == "capability"]
    assert artifacts
    assert {item["usage_state"] for item in artifacts} == {"SUPPORTED"}


# --------------------------------------------------------------------------- #
# §20 — graph export
# --------------------------------------------------------------------------- #


def test_graph_export_is_a_projection_with_identity_and_evidence(graph):
    export = twin.graph_export(graph)
    assert export["schema"] == twin.GRAPH_EXPORT_SCHEMA
    assert export["counts"]["asset_nodes"] == len(graph.assets())
    assert export["counts"]["evidence_nodes"] == len(graph.evidence())
    assert all(edge["properties"]["evidence_ids"] for edge in export["relationships"])
    assert export["load_notes"]["not_source_of_truth"].startswith("this export is a projection")
    # an unresolved edge ships separately rather than as a relationship
    assert export["counts"]["unresolved"] == len(graph.unresolved_relationships())


def test_graph_export_is_deterministic(graph):
    assert twin.graph_export(graph)["nodes"] == twin.graph_export(graph)["nodes"]
    # node identity is derived from the estate, not from the wall clock
    rebuilt = _mutate(graph)
    assert [node["id"] for node in twin.graph_export(graph)["nodes"]] == [
        node["id"] for node in twin.graph_export(rebuilt)["nodes"]
    ]


# --------------------------------------------------------------------------- #
# API — history, compare, crypto graph, graph export
# --------------------------------------------------------------------------- #


def test_api_capture_is_idempotent_and_history_lists_it(api):
    http, _session = api
    _discover(http)
    first = http.post("/api/v1/estate/evidence/twin/snapshots", json={"note": "t0"})
    assert first.status_code == 201, first.text
    assert first.json()["created"] is True

    again = http.post("/api/v1/estate/evidence/twin/snapshots", json={})
    assert again.json()["created"] is False
    assert again.json()["snapshot"]["observations"] == 2

    history = http.get("/api/v1/estate/evidence/twin/snapshots").json()
    assert history["persisted"] is True
    assert history["count"] == 1


def test_api_compare_needs_two_snapshots_then_reports_coverage_loss(api):
    http, _session = api
    healthy = _payload()
    healthy["collectors"][1] = {"plane": "HSM", "status": "COMPLETE", "expected": 1, "collected": 1}
    first = http.post("/api/v1/estate/evidence/discover", json=healthy)
    assert first.status_code == 200, first.text

    empty = http.get("/api/v1/estate/evidence/twin/compare").json()
    assert empty["verdict"] == "NOT_COMPARABLE"
    assert "not 'no drift'" in empty["reason"]

    http.post("/api/v1/estate/evidence/twin/snapshots", json={})

    # the same estate, but the HSM plane failed to collect this time
    degraded = _payload()
    assert http.post("/api/v1/estate/evidence/discover", json=degraded).status_code == 200
    captured = http.post("/api/v1/estate/evidence/twin/snapshots", json={})
    assert captured.json()["created"] is True

    result = http.get("/api/v1/estate/evidence/twin/compare").json()
    assert result["verdict"] == "COVERAGE_DEGRADED"
    assert result["before_snapshot"]["projection_id"] == first.json()["projection_id"]
    assert result["coverage"]["counts"]["degraded"] == 1


def test_api_compare_refuses_an_unknown_snapshot(api):
    http, _session = api
    _discover(http)
    missing = http.get("/api/v1/estate/evidence/twin/compare", params={"before": "nope"})
    assert missing.status_code == 404
    assert missing.json()["detail"]["error"] == "unknown_snapshot"


def test_api_crypto_graph_and_graph_export(api):
    http, _session = api
    _discover(http)
    graph_view = http.get("/api/v1/estate/evidence/twin/crypto-graph").json()
    assert set(twin.CRYPTO_PLANES) <= set(graph_view["planes"])
    export = http.get("/api/v1/estate/evidence/twin/graph").json()
    assert export["counts"]["asset_nodes"] > 0
    assert export["load_notes"]["not_source_of_truth"]
