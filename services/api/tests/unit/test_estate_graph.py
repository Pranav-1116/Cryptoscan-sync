"""Estate evidence graph → six BOM projections (spec 93).

The properties under test are the ones that keep six BOMs from contradicting each
other:

* one identity per real thing, whatever plane discovered it;
* no relationship without a basis and evidence (`UNKNOWN`, never assumed);
* capability ≠ configured ≠ negotiated ≠ observed;
* layers never merge (a TLS suite is not the application cipher);
* coverage is attempted/expected, and a failed collector is `FAILED` with an
  impact statement, never "none";
* all six BOMs are stamped with the same snapshot id.
"""

from __future__ import annotations

import pytest

from shared_models.estate_graph import (
    BOM_KINDS,
    EstateGraph,
    asset_id,
    build_graph,
    collector_outcome,
    coverage_matrix,
    make_evidence,
)

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)


def _payload() -> dict:
    return {
        "estate": "payments-bank",
        "scope": "production",
        "assets": [
            {"ref": "sys", "type": "SYSTEM", "name": "Payment System"},
            {"ref": "api", "type": "APPLICATION", "name": "Payment API", "owner": "Payments Team"},
            {
                "ref": "pod",
                "type": "POD",
                "name": "payments-api-7d9f",
                "identity": {"namespace": "payments", "name": "payments-api-7d9f"},
            },
            {"ref": "lb", "type": "LOAD_BALANCER", "name": "ext-lb-01"},
            {
                "ref": "hsm",
                "type": "HSM",
                "name": "HSM-01",
                "identity": {"vendor": "VendorX", "serial_number": "SN-1"},
            },
            {
                "ref": "db",
                "type": "DATABASE",
                "name": "payments-db",
                "identity": {"host": "10.20.10.40", "port": 5432, "engine": "postgres"},
            },
            {"ref": "ossl", "type": "LIBRARY", "name": "OpenSSL", "identity": {"name": "OpenSSL", "version": "3.0.13"}},
            {"ref": "vendor", "type": "VENDOR", "name": "VendorX", "identity": {"name": "VendorX", "product": "HSM-X"}},
        ],
        "evidence": [
            {
                "evidence_id": "ev-rt",
                "source": "runtime-trace",
                "evidence_type": "RUNTIME_OBSERVED",
                "target": "api",
                "layer": "APPLICATION",
                "facts": {"algorithm": "AES", "key_size": 256, "mode": "GCM", "role": "bulk-encryption"},
            },
            {
                "evidence_id": "ev-tls",
                "source": "tls-probe",
                "evidence_type": "NETWORK_ACTIVE_OBSERVED",
                "target": "lb",
                "layer": "NETWORK_TRANSPORT",
                "facts": {"algorithm": "AES-256-GCM", "protocol": "TLS1.3", "role": "bulk-encryption"},
            },
            {
                "evidence_id": "ev-hsm",
                "source": "hsm-inventory",
                "evidence_type": "STATIC_OBSERVED",
                "target": "hsm",
                "layer": "HSM",
                "facts": {"algorithm": "RSA", "key_size": 2048, "role": "signature"},
            },
            {
                "evidence_id": "ev-vendor",
                "source": "vendor-datasheet",
                "evidence_type": "VENDOR_DECLARED",
                "target": "vendor",
                "layer": "HSM",
                "facts": {"algorithm": "AES", "key_size": 256, "role": "bulk-encryption", "product": "HSM-X"},
            },
        ],
        "relationships": [
            {"subject": "sys", "predicate": "contains", "object": "api", "basis": "APPROVED_MAPPING", "evidence_ids": ["ev-rt"]},
            {"subject": "api", "predicate": "runs_on", "object": "pod", "basis": "DEPLOYMENT_CONFIG", "evidence_ids": ["ev-rt"]},
            {"subject": "api", "predicate": "uses", "object": "hsm", "basis": "PKCS11_REFERENCE", "evidence_ids": ["ev-hsm"]},
            {"subject": "vendor", "predicate": "contains", "object": "hsm", "basis": "IMPORTED", "evidence_ids": ["ev-vendor"]},
        ],
        "collectors": [
            {"plane": "HSM", "status": "FAILED", "reason": "HSM API unavailable"},
            {"plane": "Kubernetes clusters", "status": "COMPLETE", "expected": 8, "collected": 8},
        ],
        "coverage": [
            {"target": "Linux hosts", "expected": 120, "collected": 118},
            {"target": "Network endpoints", "expected": 840, "collected": 821},
        ],
    }


# --------------------------------------------------------------------------- #
# identity
# --------------------------------------------------------------------------- #


def test_asset_ids_are_deterministic_and_case_insensitive():
    first = asset_id("HOST", {"hostname": "App-01.Bank.Local"})
    second = asset_id("HOST", {"hostname": "app-01.bank.local"})
    assert first == second
    assert first.startswith("host:")
    assert asset_id("HOST", {"hostname": "app-02.bank.local"}) != first


def test_the_same_host_from_two_planes_is_one_node():
    graph = EstateGraph(estate="e")
    first = graph.add_asset("HOST", "app-01", identity={"hostname": "app-01.bank.local"}, source="static-plane")
    second = graph.add_asset("HOST", "app-01", identity={"hostname": "app-01.bank.local"}, source="runtime-plane")
    assert first == second
    assert len(graph.assets()) == 1
    assert graph.merged_identities()[0]["asset_id"] == first


def test_evidence_for_an_undeclared_asset_is_refused():
    graph = EstateGraph(estate="e")
    with pytest.raises(ValueError, match="unknown asset"):
        graph.add_evidence(
            make_evidence(source="x", evidence_type="STATIC_OBSERVED", target="host:deadbeef", facts={})
        )


def test_unknown_evidence_and_layer_values_are_refused():
    with pytest.raises(ValueError, match="unknown evidence type"):
        make_evidence(source="x", evidence_type="LOOKS_LEGIT", target="host:1")
    with pytest.raises(ValueError, match="unknown layer"):
        make_evidence(source="x", evidence_type="STATIC_OBSERVED", target="host:1", layer="SOMEWHERE")


# --------------------------------------------------------------------------- #
# relationships
# --------------------------------------------------------------------------- #


def test_co_location_never_becomes_a_relationship():
    graph = build_graph(
        {
            "estate": "e",
            "assets": [
                {"ref": "api", "type": "APPLICATION", "name": "Payment API"},
                {"ref": "hsm", "type": "HSM", "name": "HSM-01", "identity": {"serial_number": "SN-1"}},
            ],
            "evidence": [
                {
                    "evidence_id": "ev-1",
                    "source": "inventory",
                    "evidence_type": "STATIC_OBSERVED",
                    "target": "api",
                    "facts": {},
                }
            ],
            # no basis, and the assets merely co-exist in one environment
            "relationships": [{"subject": "api", "predicate": "uses", "object": "hsm"}],
        }
    )
    assert graph.relationships() == []
    unresolved = graph.unresolved_relationships()
    assert len(unresolved) == 1
    assert unresolved[0]["status"] == "UNKNOWN"
    assert "no basis stated" in unresolved[0]["reason"]


def test_a_relationship_without_evidence_is_unresolved():
    graph = EstateGraph(estate="e")
    subject = graph.add_asset("APPLICATION", "Payment API")
    obj = graph.add_asset("HSM", "HSM-01", identity={"serial_number": "SN-1"})
    graph.assert_relationship(subject, "uses", obj, basis="PKCS11_REFERENCE")
    assert graph.relationships() == []
    assert "no evidence attached" in graph.unresolved_relationships()[0]["reason"]


def test_import_basis_cannot_establish_use_but_a_pkcs11_reference_can():
    graph = build_graph(_payload())
    uses = [edge for edge in graph.relationships() if edge["predicate"] == "uses"]
    assert [edge["basis"] for edge in uses] == ["PKCS11_REFERENCE"]
    refused = [edge for edge in graph.unresolved_relationships() if edge["predicate"] == "uses"]
    assert refused == []  # the imported edge in the fixture is `contains`, not `uses`

    second = EstateGraph(estate="e")
    api = second.add_asset("APPLICATION", "Payment API")
    hsm = second.add_asset("HSM", "HSM-01", identity={"serial_number": "SN-2"})
    ev = second.add_evidence(
        make_evidence(source="cmdb", evidence_type="IMPORTED", target=api, facts={})
    )
    second.assert_relationship(api, "uses", hsm, basis="IMPORTED", evidence_ids=[ev])
    assert second.relationships() == []
    assert "cannot establish *use*" in second.unresolved_relationships()[0]["reason"]


def test_unknown_predicate_is_refused():
    graph = EstateGraph(estate="e")
    a = graph.add_asset("APPLICATION", "A")
    b = graph.add_asset("HSM", "B", identity={"serial_number": "1"})
    with pytest.raises(ValueError, match="unknown predicate"):
        graph.assert_relationship(a, "trusts_blindly", b, basis="CONFIGURATION", evidence_ids=["ev"])


# --------------------------------------------------------------------------- #
# capability vs usage, layer separation
# --------------------------------------------------------------------------- #


def test_capability_is_not_usage():
    graph = build_graph(_payload())
    artifacts = {artifact["asset_name"]: artifact for artifact in graph.crypto_artifacts()}
    assert artifacts["Payment API"]["usage_state"] == "OBSERVED"
    assert artifacts["ext-lb-01"]["usage_state"] == "NEGOTIATED"
    assert artifacts["VendorX"]["usage_state"] == "SUPPORTED"
    assert artifacts["HSM-01"]["usage_state"] == "SUPPORTED"

    unknown = graph.unknown_inventory()
    assert unknown["by_usage_state"]["OBSERVED"] == 1
    assert unknown["capability_only"] >= 2
    assert "not observed usage" in unknown["capability_only_note"]


def test_layers_never_merge_in_the_cbom():
    graph = build_graph(_payload())
    cbom = graph.project("CBOM")
    layers = {component["algorithm"]: component["layer"] for component in cbom["components"] if component.get("layer")}
    assert layers["AES-256-GCM"] == "NETWORK_TRANSPORT"
    assert layers["AES"] in {"APPLICATION", "HSM"}
    # an application AES-256 and a TLS AES-256-GCM are two artefacts, not one merged fact
    assert cbom["by_layer"]["NETWORK_TRANSPORT"] == 1
    assert cbom["by_layer"]["APPLICATION"] == 1
    assert cbom["capability_only"] == cbom["by_usage_state"]["SUPPORTED"]


def test_artifacts_keep_every_supporting_evidence_id():
    graph = build_graph(_payload())
    hsm_source = [
        artifact for artifact in graph.crypto_artifacts() if artifact["asset_name"] == "VendorX"
    ][0]
    assert hsm_source["evidence_ids"] == ["ev-vendor"]
    assert hsm_source["confidence"] == "LOW"


# --------------------------------------------------------------------------- #
# six projections from one snapshot
# --------------------------------------------------------------------------- #


def test_all_six_boms_share_one_projection_id():
    graph = build_graph(_payload())
    projections = graph.project_all()
    ids = {projection["projection_id"] for projection in projections["boms"].values()}
    assert len(ids) == 1
    assert ids == {graph.fingerprint()}
    assert set(projections["boms"]) == set(BOM_KINDS)
    assert projections["consistency"]["all_boms_share_snapshot"] is True


def test_each_bom_answers_its_own_question():
    graph = build_graph(_payload())
    assert [item["name"] for item in graph.project("SBOM")["components"]] == ["OpenSSL"]
    assert [item["name"] for item in graph.project("NBOM")["components"]] == ["ext-lb-01", "payments-db"]
    assert [item["name"] for item in graph.project("VBOM")["components"]] == ["VendorX"]
    assert [item["name"] for item in graph.project("HBOM")["components"]] == []
    techbom_names = {item["name"] for item in graph.project("TECHBOM")["components"]}
    assert {"Payment System", "Payment API", "payments-api-7d9f", "HSM-01"} <= techbom_names
    assert graph.project("VBOM")["declared_capabilities"][0]["declared_not_observed"] is True


def test_projection_id_changes_when_evidence_changes_and_not_otherwise():
    graph = build_graph(_payload())
    before = graph.fingerprint()
    assert build_graph(_payload()).fingerprint() == before  # same evidence ⇒ same snapshot

    graph.add_evidence(
        make_evidence(
            source="scan",
            evidence_type="STATIC_OBSERVED",
            target=next(asset["asset_id"] for asset in graph.assets() if asset["name"] == "Payment API"),
            facts={"algorithm": "SHA1", "role": "hash"},
            layer="APPLICATION",
        )
    )
    assert graph.fingerprint() != before


# --------------------------------------------------------------------------- #
# conflicts, coverage, unknown inventory
# --------------------------------------------------------------------------- #


def test_disagreeing_sources_are_reported_not_resolved():
    graph = EstateGraph(estate="e")
    endpoint = graph.add_asset(
        "NETWORK_ENDPOINT", "payments.bank:443", identity={"host": "payments.bank", "port": 443, "protocol": "TLS"}
    )
    graph.add_evidence(
        make_evidence(
            source="probe-a",
            evidence_type="NETWORK_ACTIVE_OBSERVED",
            target=endpoint,
            facts={"tls_version": "TLSv1.3", "algorithm": "AES-256-GCM"},
            layer="NETWORK_TRANSPORT",
        )
    )
    graph.add_evidence(
        make_evidence(
            source="probe-b",
            evidence_type="NETWORK_ACTIVE_OBSERVED",
            target=endpoint,
            facts={"tls_version": "TLSv1.2", "algorithm": "AES-256-GCM"},
            layer="NETWORK_TRANSPORT",
        )
    )
    conflicts = graph.conflicts()
    assert len(conflicts) == 1
    assert conflicts[0]["field"] == "tls_version"
    assert {value["value"] for value in conflicts[0]["values"]} == {"TLSv1.3", "TLSv1.2"}
    assert "not silently" in conflicts[0]["reason"]


def test_coverage_is_attempted_not_discovered():
    matrix = coverage_matrix(
        [
            {"target": "Linux hosts", "expected": 120, "collected": 118},
            {"target": "Windows hosts", "expected": 80, "collected": 80},
            {"target": "HSMs", "expected": 6, "collected": 0, "status": "FAILED", "impact": "HBOM incomplete"},
        ]
    )
    by_target = {row["target"]: row for row in matrix["targets"]}
    assert by_target["Linux hosts"]["status"] == "PARTIAL"
    assert by_target["Windows hosts"]["status"] == "COMPLETE"
    assert by_target["HSMs"]["status"] == "FAILED"
    assert matrix["summary"]["coverage_percent"] == 96.1
    assert "NOT 'percent of crypto discovered'" in matrix["meaning"]
    assert set(matrix["not_observed"]) == {"Linux hosts", "HSMs"}


def test_failed_collector_is_unknown_with_an_impact_statement():
    outcome = collector_outcome("HSM", "FAILED", expected=6, collected=0, reason="HSM API unavailable")
    assert outcome["status"] == "FAILED"
    assert outcome["is_failure"] is True
    assert "UNKNOWN" in outcome["impact"]

    graph = build_graph(_payload())
    coverage = graph.coverage()
    planes = {row["target"]: row for row in coverage["targets"]}
    assert planes["HSM"]["status"] == "FAILED"
    assert "UNKNOWN" in planes["HSM"]["impact"]
    assert planes["Kubernetes clusters"]["status"] == "COMPLETE"
    assert coverage["collector_failures_are_unknown_not_empty"] is True
    assert graph.unknown_inventory()["failed_collectors"][0]["plane"] == "HSM"


def test_unknown_inventory_counts_assets_without_evidence():
    graph = build_graph(_payload())
    unknown = graph.unknown_inventory()
    assert unknown["schema"] == "cryptoscan.estate-unknown-inventory/1"
    assert unknown["assets"] == len(graph.assets())
    assert len(unknown["assets_without_evidence"]) == 4  # system, pod, database, library
    assert unknown["evidence_types"]["VENDOR_DECLARED"] == 1
    assert unknown["unknown_count"] >= len(unknown["assets_without_evidence"])


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


def test_discover_and_read_back_the_estate(api):
    http, _session = api
    created = http.post("/api/v1/estate/evidence/discover", json=_payload())
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["model"] == "cryptoscan.estate-discovery/1"
    assert body["run_id"]
    assert body["summary"]["assets"] == 8
    assert body["summary"]["relationships"] == 4
    assert body["unresolved_relationships"] == []
    assert set(body["boms"]) == set(BOM_KINDS)
    assert body["coverage"]["summary"]["by_status"]["FAILED"] == 1

    projection_ids = {projection["projection_id"] for projection in body["boms"].values()}
    assert projection_ids == {body["projection_id"]}

    summary = http.get("/api/v1/estate/evidence/summary").json()
    assert summary["summary"]["projection_id"] == body["projection_id"]

    graph = http.get("/api/v1/estate/evidence/graph").json()
    assert len(graph["nodes"]) == 8
    assert len(graph["edges"]) == 4

    coverage = http.get("/api/v1/estate/evidence/coverage").json()
    assert coverage["summary"]["expected"] > 0

    one = http.get("/api/v1/estate/evidence/boms?bom=CBOM").json()
    assert one["bom"] == "CBOM"
    assert one["projection_id"] == body["projection_id"]

    everything = http.get("/api/v1/estate/evidence/boms").json()
    assert set(everything["boms"]) == set(BOM_KINDS)
    assert everything["counts"]["CBOM"] >= 3


def test_discover_refuses_a_relationship_without_basis(api):
    http, _session = api
    payload = _payload()
    payload["relationships"] = [{"subject": "api", "predicate": "uses", "object": "hsm"}]
    response = http.post("/api/v1/estate/evidence/discover", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["unresolved_relationships"][0]["status"] == "UNKNOWN"
    assert body["summary"]["relationships"] == 0


def test_discover_rejects_evidence_for_an_undeclared_asset(api):
    http, _session = api
    payload = _payload()
    payload["evidence"].append(
        {
            "source": "x",
            "evidence_type": "STATIC_OBSERVED",
            "target": "host:not-declared",
            "facts": {"algorithm": "AES"},
        }
    )
    response = http.post("/api/v1/estate/evidence/discover", json=payload)
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "estate_payload_rejected"


def test_boms_without_a_discovery_say_not_observed(api):
    http, _session = api
    response = http.get("/api/v1/estate/evidence/boms")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "no_estate_discovery"
    assert "NOT_OBSERVED" in response.json()["detail"]["reason"]
