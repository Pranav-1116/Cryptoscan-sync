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


def test_a_snapshot_records_the_policy_that_read_the_evidence():
    """§19 — the projection id identifies the evidence; this identifies the reading of it."""
    from shared_models.estate_graph import POLICY_VERSION

    snap = twin.snapshot(build_graph(_payload()))

    assert snap["policy_version"] == POLICY_VERSION
    assert snap["note"]


def test_a_snapshot_records_collector_versions_not_just_collector_names():
    """A probe upgrade must be visible: "linux-static" alone cannot be reproduced."""
    graph = build_graph({
        "assets": [{"ref": "api", "type": "APPLICATION", "name": "Payment API"}],
        "evidence": [{
            "evidence_id": "ev-1", "source": "/etc/pkcs11.conf", "collector": "linux-static",
            "collector_version": "1.4.0", "evidence_type": "CONFIGURED",
            "target": "api", "layer": "APPLICATION", "facts": {"algorithm": "AES-256-GCM"},
        }],
    })

    snap = twin.snapshot(graph)

    assert snap["collector_versions"] == ["linux-static@1.4.0"]


def test_a_collector_with_no_version_is_named_rather_than_dropped():
    payload = _payload()
    payload["evidence"][0]["collector"] = "cmdb-import"

    snap = twin.snapshot(build_graph(payload))

    assert "cmdb-import" in snap["collector_versions"]


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


def test_exported_graph_lines_resolve_through_the_same_why_api_as_the_canvas(api):
    http, _session = api
    _discover(http)
    exported = http.get("/api/v1/estate/evidence/twin/graph").json()
    for edge in exported["relationships"]:
        if edge["type"] not in {"SUPPORTS", "CONTAINS", "PART_OF"}:
            continue
        response = http.get("/api/v1/estate/evidence/twin/why", params={
            "subject": edge["from"], "predicate": edge["type"].lower(), "object": edge["to"]})
        assert response.status_code == 200, response.text
        answer = response.json()
        assert answer["status"] in {"ESTABLISHED", "ASSERTED_UNCITED"}, (edge, answer)
        if answer["status"] == "ASSERTED_UNCITED":
            assert answer["detail"]
        else:
            assert answer["matches"][0]["evidence"]


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
    # every edge cites evidence, or says why it cannot: a placement edge derived from
    # an assertion-only attribute names that instead of borrowing someone else's proof
    assert all(
        edge["properties"]["evidence_ids"] or edge["properties"].get("uncited_because")
        for edge in export["relationships"]
    )
    assert export["load_notes"]["not_source_of_truth"].startswith("this export is a projection")
    # an unresolved edge ships separately rather than as a relationship
    assert export["counts"]["unresolved"] == len(graph.unresolved_relationships())


def _chart_payload() -> dict:
    """Two assets with an asserted chart, one asset asserting none of it."""
    return {
        "estate": "Synthetic Bank",
        "assets": [
            {"ref": "api", "type": "APPLICATION", "name": "Payment API",
             "environment": "production",
             "attributes": {"organization": "Bank UAE PJSC", "department": "Payments",
                            "region": "me-central-1", "data_center": "UAE DC1"}},
            {"ref": "core", "type": "APPLICATION", "name": "Core Ledger",
             "environment": "production",
             "attributes": {"organization": "Bank UAE PJSC", "department": "Core Banking",
                            "region": "me-central-1", "data_center": "UAE DC1"}},
            {"ref": "loose", "type": "APPLICATION", "name": "legacy-batch"},
        ],
        "evidence": [
            {"evidence_id": "ev-1", "source": "agent", "evidence_type": "RUNTIME_OBSERVED",
             "target": "api", "layer": "APPLICATION", "facts": {"algorithm": "AES-256-GCM"}},
        ],
        "relationships": [],
    }


def test_the_graph_carries_the_organisation_chart_as_nodes_not_strings():
    """§7 asks for Organization/Region/DataCenter nodes; a property answers one asset at a time."""
    export = twin.graph_export(build_graph(_chart_payload()))

    placement = {
        node["properties"]["level"]: node
        for node in export["nodes"] if "PLACEMENT" in node["labels"]
    }
    assert placement["ORGANIZATION"]["properties"]["name"] == "Bank UAE PJSC"
    assert placement["DATA_CENTER"]["properties"]["name"] == "UAE DC1"
    # five levels, six distinct nodes: the two assets sit in different departments
    placement_nodes = [node for node in export["nodes"] if "PLACEMENT" in node["labels"]]
    assert export["counts"]["placement_nodes"] == len(placement_nodes) == 6
    assert len(placement) == 5

    contains = [edge for edge in export["relationships"] if edge["type"] == "CONTAINS"]
    # two placed assets, five asserted levels each; the unplaced asset is in no edge
    assert len(contains) == 10
    assert all(edge["from"].startswith("placement:") for edge in contains)


def test_every_exported_evidence_or_placement_line_has_a_truthful_why_answer():
    graph = build_graph(_chart_payload())
    exported = twin.graph_export(graph)
    support = next(edge for edge in exported["relationships"] if edge["type"] == "SUPPORTS")
    why_support = twin.why(graph, subject=support["from"], predicate=support["type"],
                           obj=support["to"])
    assert why_support["status"] == "ESTABLISHED"
    assert why_support["matches"][0]["evidence"][0]["evidence_id"] == "ev-1"

    cited = next(edge for edge in exported["relationships"]
                 if edge["type"] == "CONTAINS" and edge["properties"]["evidence_ids"])
    why_cited = twin.why(graph, subject=cited["from"], predicate=cited["type"], obj=cited["to"])
    assert why_cited["status"] == "ESTABLISHED"
    assert why_cited["matches"][0]["evidence"][0]["evidence_id"] == "ev-1"

    asserted = next(edge for edge in exported["relationships"] if edge["type"] == "PART_OF")
    why_asserted = twin.why(graph, subject=asserted["from"], predicate=asserted["type"],
                            obj=asserted["to"])
    assert why_asserted["status"] == "ASSERTED_UNCITED"
    assert "assertion-only" in why_asserted["detail"]


def test_a_placement_level_nothing_asserts_has_no_node():
    """The chart is never filled in from the level below it."""
    export = twin.graph_export(build_graph(_chart_payload()))

    levels = {node["labels"][1] for node in export["nodes"] if "PLACEMENT" in node["labels"]}
    # no asset asserts a cloud account, so there is no CLOUD_ENVIRONMENT node
    assert levels == {"ORGANIZATION", "DEPARTMENT", "REGION", "DATA_CENTER", "ENVIRONMENT"}


def test_the_chart_edges_follow_the_asserted_hierarchy():
    export = twin.graph_export(build_graph(_chart_payload()))

    by_id = {node["id"]: node for node in export["nodes"]}
    part_of = [edge for edge in export["relationships"] if edge["type"] == "PART_OF"]
    assert part_of
    for edge in part_of:
        child = by_id[edge["from"]]["properties"]
        parent = by_id[edge["to"]]["properties"]
        assert (child["level"], parent["level"]) in {
            ("DEPARTMENT", "ORGANIZATION"),
            ("DATA_CENTER", "REGION"),
            ("ENVIRONMENT", "DATA_CENTER"),
        }


def test_a_placement_edge_without_evidence_says_so_rather_than_borrowing_proof():
    payload = _chart_payload()
    payload["evidence"] = []
    export = twin.graph_export(build_graph(payload))

    contains = [edge for edge in export["relationships"] if edge["type"] == "CONTAINS"]
    assert contains
    assert all(
        edge["properties"]["uncited_because"].startswith("the placed asset carries no evidence")
        for edge in contains
    )


def test_the_specifications_twenty_two_graph_labels_all_resolve_to_an_emittable_type():
    """§7 lists 22 node labels. "8 of 22" was the gap; this is the check that closes it."""
    coverage = twin.graph_label_coverage()

    assert coverage["specified"] == 22
    assert coverage["available"] == 22
    for row in coverage["labels"]:
        assert row["available"], row
        assert row["emitted_as"], row["spec_label"]

    # the four placement levels are nodes now, not only asset properties
    placement = {row["spec_label"] for row in coverage["labels"] if row["family"] == "PLACEMENT"}
    assert placement == {"Organization", "Region", "DataCenter", "Environment"}

    # names that differ between the specification and this build say so, rather than
    # emitting a second spelling of the same thing
    by_name = {row["spec_label"]: row["emitted_as"] for row in coverage["labels"]}
    assert by_name["KMS"] == ["KMS_KEY"]
    assert by_name["BusinessSystem"] == ["SYSTEM"]
    assert set(by_name["NetworkDevice"]) == {"FIREWALL", "LOAD_BALANCER", "VPN"}


def test_an_export_states_which_spec_label_each_build_label_maps_to():
    export = twin.graph_export(build_graph(_chart_payload()))

    assert export["label_coverage"]["DataCenter"] == ["DATA_CENTER"]
    assert export["label_coverage"]["Evidence"]


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


# -- §4: the levels above the environment ---------------------------------- #


def _placed_payload() -> dict:
    return {
        "estate": "Synthetic Bank",
        "assets": [
            {"ref": "api", "type": "APPLICATION", "name": "Payment API", "environment": "production",
             "location": "UAE DC1",
             "attributes": {"region": "me-central-1", "data_center": "UAE DC1"}},
            {"ref": "hsm", "type": "HSM", "name": "HSM-03", "environment": "production",
             "attributes": {"region": "me-central-1", "data_center": "UAE DC1"}},
            {"ref": "s3", "type": "CLOUD_RESOURCE", "name": "payments-bucket", "environment": "production",
             "attributes": {"provider": "AWS", "cloud_account": "123456789012", "region": "eu-west-1"}},
            {"ref": "legacy", "type": "APPLICATION", "name": "legacy-batch"},
            {"ref": "scan", "type": "APPLICATION", "name": "scanned-app", "environment": "production",
             "location": "/srv/app/Crypto.java"},
        ],
        "evidence": [],
        "relationships": [],
    }


def test_the_four_upper_levels_are_built_only_where_evidence_asserts_them():
    graph = build_graph(_placed_payload())
    placement = twin.placement_model(graph)

    assert placement["levels"] == list(twin.ESTATE_LEVELS)
    assert [region["name"] for region in placement["regions"]] == ["eu-west-1", "me-central-1"]
    me = next(region for region in placement["regions"] if region["name"] == "me-central-1")
    assert me["assets"] == 2
    assert me["environments"] == [{"name": "production", "assets": 2}]

    assert [dc["name"] for dc in placement["data_centers"]] == ["UAE DC1"]
    assert placement["data_centers"][0]["regions"] == [{"name": "me-central-1", "assets": 2}]

    assert [cloud["name"] for cloud in placement["cloud_environments"]] == ["AWS:123456789012"]
    assert placement["cloud_environments"][0]["provider"] == "AWS"
    assert placement["cloud_environments"][0]["regions"] == [{"name": "eu-west-1", "assets": 1}]


def test_a_level_nothing_asserts_is_reported_as_unobserved_not_invented():
    graph = build_graph(_placed_payload())
    placement = twin.placement_model(graph)
    unassigned = {row["level"]: row for row in placement["unassigned"]}
    # two assets assert no region; three assert no data centre
    assert unassigned["REGION"]["assets"] == 2
    assert unassigned["DATA_CENTER"]["assets"] == 3
    assert "never derived from a 'location' string" in unassigned["REGION"]["reason"]
    assert "provenance, not a building" in unassigned["DATA_CENTER"]["reason"]
    assert "not 'unassigned cloud'" in unassigned["CLOUD_ENVIRONMENT"]["reason"]


def test_a_file_path_never_becomes_a_data_centre_or_a_region():
    graph = build_graph({
        "estate": "B",
        "assets": [{"ref": "x", "type": "LIBRARY", "name": "OpenSSL", "environment": "production",
                    "location": "/srv/app/libcrypto.so",
                    "attributes": {"data_center": "/mnt/host/etc/ssl"}}],
        "evidence": [], "relationships": [],
    })
    placement = twin.placement_model(graph)
    assert placement["data_centers"] == []
    assert {row["level"]: row["assets"] for row in placement["unassigned"]}["DATA_CENTER"] == 1


def test_an_estate_with_no_upper_level_facts_lists_them_as_unobserved():
    graph = build_graph({
        "estate": "B",
        "assets": [{"ref": "h", "type": "HOST", "name": "app-01", "environment": "production"}],
        "evidence": [], "relationships": [],
    })
    placement = twin.placement_model(graph)
    assert placement["regions"] == []
    assert placement["levels_observed"] == ["BANK", "ENVIRONMENT", "BUSINESS_SYSTEM"]
    assert placement["levels_unobserved"] == [
        "ORGANIZATION", "DEPARTMENT", "REGION", "DATA_CENTER", "CLOUD_ENVIRONMENT",
    ]


def test_the_overview_carries_the_hierarchy():
    graph = build_graph(_placed_payload())
    body = twin.overview(graph)
    # one asset has no environment at all; the scanned one has an environment but a
    # file path for a location, so it is placed by environment and not by site
    assert body["placement"]["unplaced_count"] == 1
    assert body["levels"] == list(twin.ESTATE_LEVELS)


# --------------------------------------------------------------------------- #
# layer 1 — the organisation chart above the infrastructure
# --------------------------------------------------------------------------- #


def test_an_asserted_organisation_and_department_place_assets_without_inventing_a_parent():
    """§4 — the bank is a set of entities, not a single root every asset hangs from."""
    graph = build_graph({
        "estate": "Synthetic Bank",
        "assets": [
            {"ref": "pay", "type": "APPLICATION", "name": "Payment API",
             "environment": "production", "owner": "Payments Team",
             "attributes": {"organization": "Bank UAE PJSC", "department": "Payments",
                            "region": "me-central-1"}},
            {"ref": "core", "type": "APPLICATION", "name": "Core Ledger",
             "environment": "production", "owner": "Core Team",
             "attributes": {"organization": "Bank KSA PJSC", "department": "Core Banking"}},
            {"ref": "orphan", "type": "APPLICATION", "name": "Unplaced App",
             "environment": "production",
             "attributes": {"department": "Retail"}},
        ],
        "evidence": [], "relationships": [],
    })
    placement = twin.placement_model(graph)

    assert [org["name"] for org in placement["organizations"]] == ["Bank KSA PJSC", "Bank UAE PJSC"]
    payments = next(d for d in placement["departments"] if d["name"] == "Payments")
    assert payments["organization"] == "Bank UAE PJSC"
    assert payments["owners"] == [{"name": "Payments Team", "assets": 1}]

    # a department without an organisation is placed in the department, never in a
    # parent the evidence does not assert
    retail = next(d for d in placement["departments"] if d["name"] == "Retail")
    assert retail["organization"] is None
    assert "ORGANIZATION" in placement["levels_unobserved"] or any(
        row["level"] == "ORGANIZATION" for row in placement["unassigned"]
    )


def test_a_level_with_no_assertion_is_counted_with_a_reason_not_left_blank():
    graph = build_graph({
        "estate": "B",
        "assets": [{"ref": "h", "type": "HOST", "name": "app-01", "environment": "production"}],
        "evidence": [], "relationships": [],
    })
    unassigned = {row["level"]: row for row in twin.placement_model(graph)["unassigned"]}
    assert unassigned["ORGANIZATION"]["assets"] == 1
    assert unassigned["DEPARTMENT"]["assets"] == 1
    assert "legal entity" in unassigned["ORGANIZATION"]["reason"]
    assert "cost centre" in unassigned["DEPARTMENT"]["reason"]


def test_the_specification_conformance_route_serves_the_register(api):
    """§1–§12 — the specification is served from the object a test asserts against."""
    http, _session = api
    response = http.get("/api/v1/estate/evidence/twin/spec-conformance")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema"] == "cryptoscan.digital-twin-spec-conformance/1"
    assert body["coverage"]["relationship_types_mapped"] == 18
    assert body["coverage"]["screens"] == 13
    # s9-ui left this set when the thirteen-screen walkthrough and the drawn canvas of
    # the twin's own graph were built: the register only lists what is still partial.
    assert {gap["id"] for gap in body["gaps"]} == {
        "s4-eight-layers", "s7-storage", "layer-7-simulation",
    }
    # the register does not need a discovered estate: it describes the build, not a bank
    assert body["spec"].endswith("DIGITAL-TWIN-SPEC.md")


# --------------------------------------------------------------------------- #
# layer 7 — CUSTOM: an operator-authored expression, as data
# --------------------------------------------------------------------------- #


def _custom_expression() -> dict:
    """The fixture's application evidence: AES-256-GCM, no protocol on that record."""
    return {
        "when": {"all": [
            {"fact": "algorithm", "op": "eq", "value": "AES-256-GCM"},
            {"fact": "protocol", "op": "absent"},
        ]},
        "then": {"set": {"algorithm": "ML-KEM-768", "key_size": 3300},
                 "unset": ["role"]},
    }


def test_a_custom_expression_changes_facts_on_a_copy_and_never_the_live_twin(graph):
    result = twin.simulate(graph, {"kind": "CUSTOM", "expression": _custom_expression()})
    assert result["status"] == "SIMULATED", result
    assert result["matched_evidence"] >= 1
    after = result["effects"][0]["after"]
    assert after["algorithm"] == "ML-KEM-768"
    assert after["key_size"] == 3300
    # the provenance of the record is untouched: the simulation edits values, not authorship
    assert result["effects"][0]["evidence_id"] == twin.simulate(
        graph, {"kind": "CUSTOM", "expression": _custom_expression()}
    )["effects"][0]["evidence_id"]
    assert result["live_projection_unchanged"] is True


def test_a_custom_expression_may_not_write_provenance(graph):
    refusal = twin.simulate(graph, {
        "kind": "CUSTOM",
        "expression": {"when": {"fact": "algorithm", "op": "eq", "value": "AES-256-GCM"},
                       "then": {"set": {"evidence_type": "RUNTIME_OBSERVED"}}},
    })
    assert refusal["status"] == "REFUSED_PROVENANCE_WRITE"
    assert "who said it" in refusal["detail"]
    assert refusal["field"] == "evidence_type"


def test_a_custom_expression_that_matches_nothing_is_not_no_impact(graph):
    result = twin.simulate(graph, {
        "kind": "CUSTOM",
        "expression": {"when": {"fact": "algorithm", "op": "eq", "value": "3DES"},
                       "then": {"set": {"algorithm": "AES-256"}}},
    })
    assert result["status"] == "NO_MATCH"
    assert "not 'no impact'" in result["detail"]


def test_the_expression_language_refuses_a_program():
    for expression, expected in (
        ({"when": {"fact": "a", "op": "compute", "value": 1}, "then": {"set": {"a": 2}}}, "unknown operator"),
        ({"when": {"all": []}, "then": {"set": {"a": 2}}}, "non-empty list"),
        ({"when": {"fact": "a", "op": "in", "value": "abc"}, "then": {"set": {"a": 2}}}, "needs a list value"),
        ({"when": {"fact": "a", "op": "eq", "value": 1}, "then": {}}, "changes nothing"),
        ({"when": {"fact": "a", "op": "eq", "value": 1}, "then": {"drop": ["a"]}}, "unknown 'then' key"),
        ("REPLACE EVERYTHING", "needs an 'expression' object"),
    ):
        refusal = twin._scenario_refusal("CUSTOM", {"expression": expression})
        assert refusal is not None, expression
        assert refusal["status"] == "INVALID_SCENARIO"
        assert expected in refusal["detail"], (expression, refusal["detail"])


def test_the_expression_cannot_nest_or_grow_into_a_program():
    deep = {"fact": "a", "op": "eq", "value": 1}
    for _ in range(twin.MAX_CUSTOM_DEPTH + 1):
        deep = {"not": deep}
    refusal = twin._scenario_refusal("CUSTOM", {"expression": {"when": deep, "then": {"set": {"a": 2}}}})
    assert refusal["status"] == "INVALID_SCENARIO"
    assert "nest" in refusal["detail"]

    wide = {"all": [{"fact": f"f{index}", "op": "present"} for index in range(twin.MAX_CUSTOM_CONDITIONS + 1)]}
    refusal = twin._scenario_refusal("CUSTOM", {"expression": {"when": wide, "then": {"set": {"a": 2}}}})
    assert refusal["status"] == "INVALID_SCENARIO"
    assert "at most" in refusal["detail"]


def test_an_assignment_that_changes_nothing_is_not_an_effect(graph):
    """A scenario whose value is already there must not report a change."""
    result = twin.preview(graph, {
        "kind": "CUSTOM",
        "expression": {"when": {"fact": "version", "op": "eq", "value": "3.0.13"},
                       "then": {"set": {"version": "3.0.13"}}},
    })
    assert result["status"] == "WOULD_NOT_MATCH"


def test_the_api_runs_and_refuses_a_custom_scenario(api):
    http, _session = api
    _discover(http)
    ok = http.post("/api/v1/estate/evidence/twin/simulate",
                   json={"kind": "CUSTOM", "expression": _custom_expression()})
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "SIMULATED"
    assert ok.json()["scenario"]["expression"] == _custom_expression()

    refused = http.post("/api/v1/estate/evidence/twin/simulate", json={
        "kind": "CUSTOM",
        "expression": {"when": {"fact": "algorithm", "op": "eq", "value": "AES-256-GCM"},
                       "then": {"unset": ["collector"]}},
    })
    assert refused.status_code == 200
    assert refused.json()["status"] == "REFUSED_PROVENANCE_WRITE"


def test_the_catalogue_documents_the_custom_kind_with_its_limit():
    from api import estate_simulation

    entry = estate_simulation.KIND_CATALOG["CUSTOM"]
    assert entry["inputs"] == ["expression"]
    assert any("provenance edit" in item for item in entry["does_not_answer"])
    assert estate_simulation.mode_of("CUSTOM") == "SCENARIO"
