"""API surface for CBOM usage proof, conflict resolution and TLS hops."""

from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base


@pytest.fixture()
def client(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "operator"
    monkeypatch.setenv("CBOM_STORAGE_DIR", str(tmp_path / "cbom"))

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    application.state.db_session = session
    yield application
    application.dependency_overrides.clear()


def _post(client, path, body):
    async def go():
        async with ASGITransport(app=client) as transport:
            async with AsyncClient(transport=transport, base_url="http://test") as http:
                return await http.post(f"/api/v1/cbom{path}", json=body,
                                       headers={"Authorization": "Bearer test-token"})

    return asyncio.run(go())


ASSET = {"algorithm": "AES-256-GCM", "parameters": {"key_size": 256, "mode": "GCM"},
         "purpose": "TLS"}


def test_usage_keeps_capability_and_observation_apart(client):
    body = _post(client, "/usage", {
        "asset": ASSET,
        "evidence": [{"class": "IMPORTED", "evidence_id": "SBOM-1"}],
    }).json()
    profile = body["profile"]
    assert profile["capability"] is True
    assert profile["usage"] == "CANDIDATE_ONLY"
    assert profile["confidence"] == "LOW"
    assert profile["layers"]["runtime"]["observed"] is False


def test_runtime_and_network_reach_very_high(client):
    body = _post(client, "/usage", {
        "asset": ASSET,
        "evidence": [
            {"layer": "runtime", "evidence_id": "RUNTIME-92821"},
            {"layer": "network", "evidence_id": "NET-9281"},
        ],
    }).json()
    assert body["profile"]["confidence"] == "VERY_HIGH"
    assert body["profile"]["evidence_ids"] == ["NET-9281", "RUNTIME-92821"]


def test_an_observation_without_an_evidence_id_is_reported_as_refused(client):
    """One bad event does not fail the request: it is reported, not dropped."""
    body = _post(client, "/usage", {"asset": ASSET,
                                    "evidence": [{"layer": "runtime"}]}).json()
    assert body["profile"]["refused"]
    assert "evidence id" in body["profile"]["refused"][0]["reason"]


def test_an_asset_with_no_algorithm_is_422(client):
    resp = _post(client, "/usage", {"asset": {}, "evidence": []})
    assert resp.status_code == 422
    assert "algorithm" in resp.json()["detail"]


def test_an_imported_event_claiming_runtime_stays_imported(client):
    body = _post(client, "/usage", {
        "asset": ASSET,
        "evidence": [{"class": "IMPORTED", "layer": "runtime", "evidence_id": "X-1"}],
    }).json()
    assert body["profile"]["usage"] == "CANDIDATE_ONLY"


def test_candidates_are_never_usage(client):
    body = _post(client, "/usage", {
        "asset": ASSET, "evidence": [],
        "component": "openssl", "algorithms": ["AES-256", "RSA-2048"],
    }).json()
    assert {row["usage"] for row in body["candidates"]["candidates"]} == {"CANDIDATE_ONLY"}
    assert "not an application that calls it" in body["candidates"]["statement"]


def test_reconcile_keeps_every_source_and_names_the_conflict(client):
    body = _post(client, "/reconcile", {"claims": [
        {"field": "version", "fact": "3.0.13", "source": "sbom"},
        {"field": "version", "fact": "3.0.13", "source": "container", "evidence_id": "C-1"},
        {"field": "version", "fact": "3.0.11", "source": "runtime", "evidence_id": "R-1"},
    ]}).json()
    assert [row["class"] for row in body["rows"]] == ["IMPORTED", "OBSERVED",
                                                      "RUNTIME_OBSERVED"]
    assert body["conflicts"][0]["values"] == {"container": "3.0.13", "runtime": "3.0.11"}
    assert body["resolved"][0]["value"] is None
    assert body["schema"] == "cryptoscan.cbom-usage-evidence/1"


def test_tls_paths_report_each_termination(client):
    body = _post(client, "/tls-paths", {"hops": [
        {"from": "client", "to": "lb", "endpoint": "payments.bank.example:443",
         "observed_on": "External LB", "tls_version": "TLS1.3",
         "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-1"},
        {"from": "lb", "to": "gw", "endpoint": "10.0.0.5:443", "observed_on": "API Gateway",
         "tls_version": "TLS1.2", "cipher_suite": "TLS_ECDHE_RSA_AES_128_GCM_SHA256",
         "evidence_id": "NET-2"},
    ]}).json()
    assert [row["tls_version"] for row in body["paths"]] == ["TLS1.3", "TLS1.2"]
    assert "not to the application behind it" in body["statement"]


def test_tls_hop_without_evidence_is_refused_not_invented(client):
    body = _post(client, "/tls-paths", {"hops": [{"endpoint": "x:443"}]}).json()
    assert body["paths"] == [] and body["refused"]


PROBE = {
    "endpoint": "payments.bank.example:443", "status": "OK",
    "crypto": {"tls_version": "TLS1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
    "observed_on": "External LB", "scan_run_id": "run-7",
    "certificates": [{"serial_number": "cert-9281", "public_key_algorithm": "ECDSA",
                      "public_key_size": 256, "signature_algorithm": "ECDSA-SHA256"}],
}


def test_collect_turns_stored_rows_into_profiles(client):
    body = _post(client, "/usage/collect", {
        "probes": [PROBE],
        "assets": [{"algorithm": "AES-256-GCM", "key_size": 256, "mode": "GCM",
                    "file_path": "src/tls.py", "line_number": 12,
                    "evidence_ids": ["EVID-001"]},
                   {"algorithm": "RSA", "file_path": "src/legacy.py"}],
        "operations": [{"operation": "EVP_EncryptInit_ex", "algorithm": "AES-256-GCM",
                        "evidence_id": "RUNTIME-92821",
                        "observed_at": "2026-11-02T10:42:11Z"}],
    }).json()
    profile = next(row for row in body["profiles"]["profiles"]
                   if row["asset"]["algorithm"] == "AES-256-GCM")
    assert profile["confidence"] == "VERY_HIGH"
    assert "net:run-7:payments.bank.example:443" in profile["evidence_ids"]
    assert body["static"]["refused"][0]["algorithm"] == "RSA"
    assert body["network"]["certificates"][0]["application_operation_proven"] is False


def test_collect_reports_an_unprobed_endpoint_as_nothing(client):
    body = _post(client, "/usage/collect", {
        "probes": [{**PROBE, "status": "TIMEOUT"}],
    }).json()
    assert body["network"]["events"] == [] and body["network"]["refused"]
    assert body["profiles"]["profiles"] == []


def test_network_usage_reads_the_stored_scan_runs(client):
    from db.models.network_scan_run import NetworkScanRun

    session = client.state.db_session
    session.add(NetworkScanRun(scan_id="s-1", target_kind="hosts",
                               result={"probes": [PROBE]}))
    session.commit()

    async def go():
        async with ASGITransport(app=client) as transport:
            async with AsyncClient(transport=transport, base_url="http://test") as http:
                return await http.get("/api/v1/cbom/usage/network",
                                      headers={"Authorization": "Bearer test-token"})

    body = asyncio.run(go()).json()
    assert body["source"] == "live" and body["scan_runs"] == 1
    assert body["profiles"]["algorithms"] == ["AES-256-GCM", "SHA-384"]
    assert body["hops"]["paths"][0]["endpoint"] == "payments.bank.example:443"


def test_network_usage_is_empty_until_a_scan_ran(client):
    async def go():
        async with ASGITransport(app=client) as transport:
            async with AsyncClient(transport=transport, base_url="http://test") as http:
                return await http.get("/api/v1/cbom/usage/network",
                                      headers={"Authorization": "Bearer test-token"})

    body = asyncio.run(go()).json()
    assert body["source"] == "empty" and body["profiles"]["profiles"] == []


def test_the_graph_keeps_conflicts_as_edges(client):
    body = _post(client, "/usage/graph", {
        "system": "payments-api",
        "profiles": [{
            "asset": {"algorithm": "AES-256-GCM", "purpose": "TLS"},
            "observed_classes": ["RUNTIME_OBSERVED"], "evidence_ids": ["RUNTIME-92821"],
            "confidence": "HIGH", "usage": "OBSERVED"}],
        "reconciled": {"conflicts": [{
            "field": "version", "kind": "VERSION_CONFLICT",
            "values": {"container": "3.0.13", "runtime": "3.0.11"},
            "evidence": {"container": "C-1", "runtime": "R-1"},
            "statement": "version has 2 observed values"}]},
        "paths": {"paths": [{
            "endpoint": "payments.bank.example:443", "evidence_id": "NET-1",
            "class": "NETWORK_OBSERVED", "tls_version": "TLS1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384", "certificate_ref": "cert-9281"}]},
    }).json()
    conflicts = [edge for edge in body["edges"]["edges"] if edge["kind"] == "CONFLICTS_WITH"]
    assert conflicts and conflicts[0]["evidence_ids"] == ["C-1", "R-1"]
    assert body["applied"]["refused"] == []
    assert body["applied"]["by_provenance"]["OBSERVED"] >= 4
    labels = {edge["label"] for edge in body["graph"]["edges"]}
    assert {"USES_CRYPTO", "CONFLICTS_WITH", "NEGOTIATES"} <= labels


def test_the_graph_refuses_an_edge_without_evidence(client):
    body = _post(client, "/usage/graph", {
        "system": "payments-api",
        "profiles": [{"asset": {"algorithm": "AES-128"}, "evidence_ids": []}],
    }).json()
    assert body["edges"]["edges"] == []
    assert body["edges"]["undeclared"] == ["AES-128"]
    assert body["applied"]["written"] == 0


def test_the_graph_needs_a_subject(client):
    resp = _post(client, "/usage/graph", {"profiles": [{"asset": {"algorithm": "AES"}}]})
    assert resp.status_code == 422


def test_promotion_keeps_a_capability_out_of_the_document(client):
    body = _post(client, "/promote", {
        "components": [{"name": "openssl", "version": "3.0.13", "evidence_id": "SBOM-1",
                        "algorithms": ["AES-256-GCM", "RSA-2048"]}],
        "evidence": [{"class": "RUNTIME_OBSERVED", "evidence_id": "RUNTIME-1",
                      "algorithm": "AES-256-GCM", "parameters": {"key_size": 256}}],
        "document_name": "payments-api",
    }).json()
    assert [asset["algorithm"] for asset in body["promotion"]["assets"]] == ["AES-256-GCM"]
    assert [row["algorithm"] for row in body["promotion"]["candidates"]] == ["RSA-2048"]
    names = [component["name"] for component in body["document"]["components"]]
    assert names == ["AES-256-GCM"]
    assert body["inventory"]["algorithms"] == {"AES-256-GCM": ["RUNTIME"]}


def test_promotion_refuses_an_unattributable_component(client):
    body = _post(client, "/promote", {
        "components": [{"name": "openssl", "algorithms": ["AES-256-GCM"]}],
    }).json()
    assert body["promotion"]["refused"] and body["document"]["components"] == []
    assert "cannot be attributed" in body["promotion"]["refused"][0]["reason"]


def test_promotion_marks_verified_when_both_observers_agree(client):
    body = _post(client, "/promote", {
        "components": [{"name": "openssl", "evidence_id": "SBOM-1",
                        "algorithms": ["AES-256-GCM"]}],
        "evidence": [
            {"class": "RUNTIME_OBSERVED", "evidence_id": "R-1", "algorithm": "AES-256-GCM"},
            {"class": "NETWORK_OBSERVED", "evidence_id": "N-1", "algorithm": "AES-256-GCM"},
        ],
    }).json()
    assert body["promotion"]["assets"][0]["promotion_level"] == "VERIFIED"
    assert body["promotion"]["levels"] == {"VERIFIED": 1}


def test_hsm_capability_is_not_an_operation(client):
    capability = _post(client, "/hsm-evidence", {"kind": "CAPABILITY"}).json()
    assert capability["class"] == "VENDOR_DECLARED" and capability["observed"] is False
    operation = _post(client, "/hsm-evidence", {"kind": "OPERATION",
                                                "evidence_id": "HSM-1",
                                                "operation": "sign"}).json()
    assert operation["class"] == "RUNTIME_OBSERVED" and operation["operation"] == "SIGN"


def test_an_hsm_operation_without_evidence_is_422(client):
    assert _post(client, "/hsm-evidence", {"kind": "OPERATION"}).status_code == 422


KMS_ROW = {"provider": "AWS_KMS", "key_ref": "arn:aws:kms:eu:1:key/abc", "algorithm": "AES",
           "key_size": 256, "purpose": "TLS", "status": "ENABLED",
           "created_at": "2025-01-05", "evidence_id": "KMS-1"}


def test_kms_configured_key_and_operation_are_two_events(client):
    body = _post(client, "/kms/keys", {
        "rows": [KMS_ROW],
        "uses": [{"key_ref": KMS_ROW["key_ref"], "operation": "decrypt",
                  "evidence_id": "USE-1", "observed_at": "2026-01-01T10:00:00Z"}],
        "as_of": "2026-06-01",
    }).json()
    classes = [event["class"] for event in body["usage"]["events"]]
    assert classes == ["CONFIGURED", "RUNTIME_OBSERVED"]
    assert body["usage"]["configured"] == 1 and body["usage"]["operated"] == 1
    assert body["usage"]["events"][1]["operation"] == "DECRYPT"


def test_kms_an_unused_key_is_configured_not_used(client):
    body = _post(client, "/kms/keys", {"rows": [KMS_ROW], "as_of": "2026-06-01"}).json()
    assert body["usage"]["operated"] == 0
    assert "a configured key is not usage" in body["usage"]["statement"]


def test_kms_refuses_key_material_instead_of_sanitising_it(client):
    body = _post(client, "/kms/keys", {
        "rows": [{**KMS_ROW, "private_key": "-----BEGIN PRIVATE KEY-----"}],
        "as_of": "2026-06-01",
    }).json()
    assert body["keys"]["records"] == [] and body["keys"]["refused"]
    assert "never material" in body["keys"]["refused"][0]["reason"]


def test_kms_refuses_an_operation_on_an_uninventoried_key(client):
    body = _post(client, "/kms/keys", {
        "rows": [KMS_ROW],
        "uses": [{"key_ref": "arn:aws:kms:eu:1:key/other", "operation": "sign",
                  "evidence_id": "USE-9", "observed_at": "2026-01-01"}],
    }).json()
    assert body["usage"]["operated"] == 0
    assert "inventory is incomplete" in body["usage"]["refused"][0]["reason"]


def test_kms_posture_reports_rotation_against_the_policy(client):
    body = _post(client, "/kms/keys", {
        "rows": [KMS_ROW,
                 {**KMS_ROW, "key_ref": "old", "algorithm": "RSA", "key_size": 1024,
                  "created_at": "2019-01-01"}],
        "as_of": "2026-06-01",
        "max_age_days": 365,
    }).json()
    posture = body["posture"]
    assert posture["by_algorithm"] == {"AES": 1, "RSA": 1}
    assert [row["key_ref"] for row in posture["weak_keys"]] == ["old"]
    assert {row["key_ref"] for row in posture["rotation_overdue"]} == {KMS_ROW["key_ref"], "old"}
    assert posture["as_of"] == "2026-06-01"


def test_kms_rejects_an_unparseable_as_of(client):
    assert _post(client, "/kms/keys", {"rows": [], "as_of": "not-a-date"}).status_code == 422


def test_pqc_handoff_separates_status_from_priority(client):
    body = _post(client, "/pqc-handoff", {"assets": [
        {"algorithm": "RSA-2048", "key_size": 2048, "purpose": "TLS",
         "usage": "RUNTIME", "evidence_ids": ["RUNTIME-1"]},
        {"algorithm": "AES-256-GCM", "key_size": 256, "purpose": "DATA_AT_REST"},
    ]}).json()
    rows = {row["algorithm"]: row for row in body["rows"]}
    assert rows["RSA-2048"]["quantum_status"] == "QUANTUM_SENSITIVE"
    assert rows["RSA-2048"]["migration_priority"] == "IMMEDIATE"
    assert rows["AES-256-GCM"]["quantum_status"] == "CLASSICAL_ONLY"
    assert rows["AES-256-GCM"]["migration_priority"] == "NONE"
    assert body["summary"]["requiring_migration"] == 1


def test_pqc_handoff_never_invents_a_verdict_for_an_unknown_algorithm(client):
    body = _post(client, "/pqc-handoff", {"assets": [{"algorithm": "ACME-9"}]}).json()
    row = body["rows"][0]
    assert row["quantum_status"] == "UNKNOWN" and row["requires_review"] is True
    assert row["migration_priority"] == "UNKNOWN"


def test_pqc_handoff_reads_a_document_and_defaults_to_unobserved(client):
    body = _post(client, "/pqc-handoff", {"document": {"components": [
        {"bom-ref": "crypto/RSA-2048", "name": "RSA-2048",
         "cryptoProperties": {"algorithmProperties": {"algorithm": "RSA-2048"}}},
    ]}}).json()
    assert body["rows"][0]["usage"] is None
    assert body["rows"][0]["quantum_status"] == "QUANTUM_SENSITIVE"
    assert body["as_of"]



TRACE = {"application": "payments-api", "pid": 9182, "provider": "OpenSSL",
         "provider_version": "3.0.13", "operation": "EVP_EncryptInit_ex",
         "algorithm": "AES-256-GCM", "key_size": 256, "mode": "GCM",
         "observed_at": "2026-11-02T10:42:11Z", "evidence_id": "RUNTIME-92821"}


def test_runtime_traces_keep_the_whole_chain(client):
    body = _post(client, "/runtime-traces", {"operations": [TRACE]}).json()
    trace = body["traces"][0]
    assert trace["chain"]["process"] == "process:payments-api/9182"
    assert trace["chain"]["provider"] == "provider:OpenSSL@3.0.13"
    component = body["components"][0]
    assert component["name"] == "AES-256-GCM"
    assert {row["name"] for row in component["properties"]} >= {
        "cryptoscan:runtime_confirmed", "cryptoscan:process", "cryptoscan:operation"}
    kinds = {edge["kind"] for edge in body["graph"]["edges"]}
    assert {"RUNS_PROCESS", "LOADS_PROVIDER", "PERFORMS_OPERATION", "RESOLVES_TO",
            "USES_CRYPTO"} <= kinds


def test_a_chain_without_a_process_is_refused(client):
    body = _post(client, "/runtime-traces", {
        "operations": [{key: value for key, value in TRACE.items() if key != "pid"}],
    }).json()
    assert body["traces"] == [] and body["refused"]
    assert "pid" in body["refused"][0]["reason"]
    assert body["summary"]["refused"] == 1


def test_the_loaded_provider_version_is_correlated_not_resolved(client):
    body = _post(client, "/runtime-traces", {
        "operations": [TRACE],
        "declared": [{"name": "openssl", "version": "3.0.11", "evidence_id": "SBOM-1"}],
    }).json()
    row = body["correlations"][0]
    assert row["state"] == "VERSION_MISMATCH"
    assert row["runtime_version"] == "3.0.13" and row["declared_versions"] == ["3.0.11"]
    assert set(row["evidence_ids"]) == {"SBOM-1", "RUNTIME-92821"}


ESTATE = {
    "name": "bank-estate-2026-11",
    "components": [{"name": "openssl", "version": "3.0.13", "evidence_id": "SBOM-1",
                    "algorithms": ["AES-256-GCM", "RSA-2048"]}],
    "operations": [TRACE],
    "coverage": {"rollup": {"systems": 100, "with_cbom": 62}, "files_scanned": 900},
}


def test_estate_chain_returns_every_layer_and_holds(client):
    body = _post(client, "/estate-chain", {"estate": ESTATE}).json()
    assert [check["check"] for check in body["checks"]] == [
        "no_capability_is_documented_as_usage",
        "every_documented_asset_is_attributable",
        "promotion_level_matches_the_evidence",
        "conflicts_survive_to_the_graph",
        "a_disabled_key_never_produces_runtime_evidence",
        "coverage_travels_with_the_document",
        "emptiness_is_explained",
    ]
    assert body["summary"]["status"] == "HOLDS"
    assert body["document"]["components"]
    for layer in ("runtime", "keys", "evidence", "promotion", "handoff", "graph",
                  "conflicts", "coverage", "empty"):
        assert layer in body, layer


def test_estate_chain_documents_no_capability(client):
    body = _post(client, "/estate-chain", {"estate": {
        "name": "capabilities-only",
        "components": [{"name": "openssl", "version": "3.0.13", "evidence_id": "SBOM-1",
                        "algorithms": ["AES-256-GCM", "RSA-2048"]}],
    }}).json()
    assert body["document"]["components"] == []
    properties = {row["name"]: row["value"]
                  for row in body["document"]["metadata"]["properties"]}
    assert properties["cryptoscan:promoted_assets"] == "0"
    assert properties["cryptoscan:candidates_excluded"] == "2"
    assert properties["cryptoscan:empty_bom"] == "true"
    assert body["summary"]["documented_assets"] == 0


def test_estate_chain_rejects_an_estate_that_is_not_an_object(client):
    resp = _post(client, "/estate-chain", {"estate": ["not", "an", "estate"]})
    assert resp.status_code == 422


LB_HOP = {"from": "Internet", "to": "External LB",
          "endpoint": "payments.bank.example:443", "observed_on": "External LB",
          "cipher_suite": "TLS_AES_256_GCM_SHA384", "tls_version": "1.3",
          "evidence_id": "NET-9281"}
APP_HOP = {"from": "External LB", "to": "payments-api",
           "endpoint": "payments-api.internal:8443", "observed_on": "payments-api",
           "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "tls_version": "1.2",
           "evidence_id": "NET-9282"}


def test_network_assets_are_attributed_to_the_terminator(client):
    body = _post(client, "/network-assets", {
        "hops": [LB_HOP, APP_HOP], "applications": ["payments-api"]}).json()
    by_endpoint = {}
    for row in body["assets"]["assets"]:
        by_endpoint.setdefault(row["endpoint"], []).append(row)
    fronting = by_endpoint["payments.bank.example:443"]
    assert all(row["observed_on"] == "External LB" for row in fronting)
    assert all(row["interface_role"] == "LOAD_BALANCER" for row in fronting)
    assert all(row["application"] is None for row in fronting)
    assert all(row["application_inference"] == "NOT_PROVEN" for row in fronting)
    behind = by_endpoint["payments-api.internal:8443"]
    assert all(row["application"] == "payments-api" for row in behind)
    assert body["summary"]["attributed_to_an_application"] == len(behind)


def test_network_assets_audit_the_application_overclaim(client):
    body = _post(client, "/network-assets", {
        "hops": [LB_HOP],
        "applications": ["payments-api"],
        "graph": {"edges": [{"from": "application:payments-api", "kind": "USES_CRYPTO",
                             "to": "algorithm:AES-256-GCM",
                             "evidence_classes": ["NETWORK_OBSERVED"],
                             "evidence_ids": ["NET-9281"]}]},
    }).json()
    overclaim = body["audit"]["overclaims"][0]
    assert overclaim["subject"] == "application:payments-api"
    assert overclaim["terminated_at"] == ["External LB"]
    properties = {row["name"]: row["value"]
                  for row in body["components"]["components"][0]["properties"]}
    assert "cryptoscan:application" not in properties


def test_network_assets_refuse_a_hop_with_no_observer(client):
    body = _post(client, "/network-assets", {
        "hops": [{key: value for key, value in LB_HOP.items()
                  if key not in ("observed_on", "to")}],
        "applications": ["payments-api"]}).json()
    assert body["assets"]["assets"] == []
    assert body["assets"]["refused"]


def test_termination_paths_are_three_relationships(client):
    body = _post(client, "/termination-paths", {"hops": [
        {"from": "Client", "to": "External LB", "tls_version": "1.3",
         "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-1"},
        {"from": "External LB", "to": "API Gateway", "tls_version": "1.2",
         "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "evidence_id": "NET-2"},
        {"from": "API Gateway", "to": "Payments API", "tls_version": "1.3",
         "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-3"},
    ]}).json()
    relationships = body["paths"]["relationships"]
    assert [row["tls_version"] for row in relationships] == ["1.3", "1.2", "1.3"]
    assert body["summary"]["downgrades"] == 1
    assert body["paths"]["merged"]["refused"] is True
    assert body["paths"]["gaps"] == []


def test_termination_paths_do_not_bridge_a_gap(client):
    body = _post(client, "/termination-paths", {"hops": [
        {"from": "Client", "to": "External LB", "tls_version": "1.3",
         "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-1"},
        {"from": "Somewhere", "to": "Payments API", "tls_version": "1.3",
         "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-2"},
    ]}).json()
    assert body["summary"]["relationships"] == 2
    assert len(body["paths"]["gaps"]) == 2


def test_termination_paths_refuse_a_hop_with_no_suite(client):
    body = _post(client, "/termination-paths", {"hops": [
        {"from": "Client", "to": "External LB", "tls_version": "1.3",
         "evidence_id": "NET-1"}]}).json()
    assert body["paths"]["relationships"] == []
    assert "suite" in body["paths"]["refused"][0]["reason"]


def test_completeness_keeps_unmeasured_and_empty_apart(client):
    body = _post(client, "/completeness", {"components": [
        {"component": "payments", "tasks": [
            {"task": "semgrep-crypto", "status": "COMPLETE"}],
         "claims": [{"task": "semgrep-crypto", "algorithm": "AES-128-CBC",
                     "evidence_id": "EV-1"}]},
        {"component": "clean", "tasks": [
            {"task": "semgrep-crypto", "status": "COMPLETE"}], "claims": []},
        {"component": "unscanned", "tasks": [], "claims": []},
    ]}).json()
    states = {row["component"]: row["state"] for row in body["components"]}
    assert states == {"payments": "COMPLETE", "clean": "EMPTY", "unscanned": "UNMEASURED"}
    assert body["inventory"]["may_report_total"] is False
    assert body["inventory"]["unmeasurable"] == ["unscanned"]


def test_completeness_reports_a_contradiction_not_a_majority(client):
    body = _post(client, "/completeness", {"components": [
        {"component": "payments", "tasks": [
            {"task": "syft-sbom", "status": "COMPLETE", "found": False},
            {"task": "semgrep-crypto", "status": "COMPLETE"}],
         "claims": [{"task": "semgrep-crypto", "algorithm": "AES-128-CBC",
                     "evidence_id": "EV-1"}]},
    ]}).json()
    row = body["components"][0]
    assert row["state"] == "CONTRADICTED"
    assert row["contradictions"][0]["empty_from"] == "syft-sbom"
    assert row["quotable"] is False


def test_completeness_of_nothing_quotes_nothing(client):
    body = _post(client, "/completeness", {"components": []}).json()
    assert body["inventory"]["components"] == 0
    assert body["inventory"]["may_report_total"] is False


def test_the_twin_is_projected_from_the_document_not_rebuilt(client):
    body = _post(client, "/twin", {
        "estate": ESTATE,
        "policy": [{"algorithm": "AES-256-GCM", "key_size": 256}],
        "advisories": [{"id": "CVE-2024-0001", "component": "openssl",
                        "fixed_in": "3.0.14", "severity": "HIGH"}],
    }).json()
    kinds = {node["kind"] for node in body["twin"]["nodes"]}
    assert {"SYSTEM", "COMPONENT", "PROVIDER", "PROCESS", "ALGORITHM"} <= kinds
    assert body["twin"]["cbom"]["bomFormat"] == "CycloneDX"
    assert set(body["consumers"]["consumers"]) == {"drift", "pqc_migration",
                                                   "threat_intelligence"}
    assert body["consumers"]["claim_check"]["ok"] is True


def test_a_capability_never_leads_a_consumer_report(client):
    body = _post(client, "/twin", {"estate": ESTATE, "policy": []}).json()
    capability = [node for node in body["twin"]["nodes"]
                  if node["kind"] == "ALGORITHM" and node["claim_level"] == "CAPABILITY"]
    assert capability, "the library declares algorithms nothing observed"
    migration = {row["algorithm"] for row in body["consumers"]["consumers"]
                 ["pqc_migration"]["rows"]}
    assert not migration & {node["id"].split(":", 1)[1] for node in capability}


def test_a_twin_request_that_is_not_an_estate_is_refused(client):
    response = _post(client, "/twin", {"estate": ["not", "an", "estate"]})
    assert response.status_code == 422


TLS_FACTS = [
    {"endpoint": "payments.bank.example:443", "state": "NEGOTIATED", "tls_version": "1.3",
     "group": "X25519", "evidence_id": "NET-1"},
    {"endpoint": "payments.bank.example:443", "state": "SUPPORTED", "tls_version": "1.3",
     "evidence_id": "ENUM-1", "enumeration_complete": True},
    {"endpoint": "payments.bank.example:443", "state": "SUPPORTED", "tls_version": "1.2",
     "evidence_id": "ENUM-1", "enumeration_complete": True},
    {"endpoint": "payments.bank.example:443", "state": "CONFIGURED", "tls_version": "1.2",
     "evidence_id": "CFG-1"},
]


def test_tls_state_keeps_the_three_states_apart(client):
    body = _post(client, "/tls-state", {"observations": TLS_FACTS}).json()
    endpoint = body["endpoints"][0]
    assert endpoint["supported"]["versions"] == ["TLS1.2", "TLS1.3"]
    assert endpoint["configured"]["versions"] == ["TLS1.2"]
    assert endpoint["negotiated"]["versions"] == ["TLS1.3"]
    assert endpoint["negotiated"]["groups"] == ["X25519"]


def test_a_disabled_claim_needs_an_enumeration(client):
    body = _post(client, "/tls-state", {"observations": TLS_FACTS,
                                        "endpoint": "payments.bank.example:443",
                                        "version": "1.1"}).json()
    assert body["checks"]["disabled"]["state"] == "DISABLED_PROVEN"
    assert body["checks"]["minimum"]["basis"] == "CONFIGURED"

    partial = _post(client, "/tls-state", {
        "observations": [{"endpoint": "legacy:443", "state": "NEGOTIATED",
                          "tls_version": "1.2", "evidence_id": "NET-2"}],
        "endpoint": "legacy:443", "version": "1.1"}).json()
    assert partial["checks"]["disabled"]["state"] == "NOT_ENUMERATED"
    assert partial["checks"]["minimum"]["basis"] == "NEGOTIATED_ONLY"


def test_a_fact_with_no_state_is_refused_rather_than_guessed(client):
    body = _post(client, "/tls-state", {"observations": [
        {"endpoint": "a:443", "state": "MAYBE", "tls_version": "1.3",
         "evidence_id": "X-1"}]}).json()
    assert body["endpoints"] == []
    assert "cannot be sorted into one" in body["refused"][0]["reason"]


def test_history_compare_turns_a_downgrade_into_a_regression(client):
    from cbom import nbom_history as nh

    before = nh.snapshot([{"host": "payments.bank.example", "port": 443,
                           "tls_version": "1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384",
                           "evidence_id": "NET-1"}], taken_at="2026-11-01T00:00:00Z")
    after = nh.snapshot([{"host": "payments.bank.example", "port": 443,
                          "tls_version": "1.2",
                          "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256",
                          "evidence_id": "NET-9"}], taken_at="2026-11-02T00:00:00Z")
    body = _post(client, "/history/compare", {"before": before, "after": after,
                                              "systems": {"payments.bank.example:443":
                                                          ["Payments API"]}}).json()
    assert body["identical"] is False
    assert body["downgrades"] == 2
    finding = body["regression"]["findings"][0]
    assert finding["finding"] == "NETWORK_CRYPTO_REGRESSION"
    assert finding["severity"] == "HIGH"
    assert finding["evidence_before"] == ["NET-1"]
    assert finding["evidence_after"] == ["NET-9"]
    assert finding["affected_systems"] == ["Payments API"]
    assert "not a conclusion" in finding["statement"]
    assert body["summary"]["regressions"] == 1


def test_history_compare_keeps_ordinary_changes_out_of_the_finding(client):
    from cbom import nbom_history as nh

    before = nh.snapshot([{"host": "partner.bank.example", "port": 443,
                           "tls_version": "1.2", "evidence_id": "NET-2"}],
                         taken_at="2026-11-01T00:00:00Z")
    after = nh.snapshot([{"host": "partner.bank.example", "port": 443,
                          "tls_version": "1.3", "evidence_id": "NET-3"},
                         {"host": "new.bank.example", "port": 9443,
                          "tls_version": "1.3", "evidence_id": "NET-4"}],
                        taken_at="2026-11-02T00:00:00Z")
    body = _post(client, "/history/compare", {"before": before, "after": after}).json()
    assert {"TLS_VERSION_CHANGED", "ENDPOINT_ADDED"} <= set(body["counts"])
    assert body["regression"]["findings"] == []
    assert body["summary"]["worst"] is None


def test_history_compare_refuses_two_documents_that_are_not_snapshots(client):
    response = _post(client, "/history/compare", {"before": {"endpoints": []},
                                                  "after": {"endpoints": []}})
    assert response.status_code == 422
    assert "not a" in response.json()["detail"]


def test_network_identity_keeps_an_asset_across_an_address_change(client):
    lb = {"asset_id": "NET-001928", "type": "LOAD_BALANCER",
          "hostname": "ext-lb-prod-01", "ips": ["10.20.1.10", "10.20.1.11"],
          "environment": "PRODUCTION", "zone": "DMZ",
          "certificate": {"fingerprint_sha256": "CERT-9281"},
          "collector_source": "authorized-scanner", "evidence_id": "NET-1"}
    body = _post(client, "/network-identity", {"observations": [
        lb, {**lb, "ips": ["10.20.1.11", "10.20.1.12"], "collector_source": "cmdb-export",
             "evidence_id": "CMDB-1", "observed_at": "2026-11-02T00:00:00Z"}]}).json()
    asset = body["assets"][0]
    assert asset["asset_id"] == "NET-001928"
    assert asset["type"] == "LOAD_BALANCER" and asset["zone"] == "DMZ"
    assert asset["ip_history"][0]["ip"] == "10.20.1.10"
    assert asset["collector_sources"] == ["authorized-scanner", "cmdb-export"]
    assert asset["evidence_ids"] == ["CMDB-1", "NET-1"]
    assert body["summary"]["assets"] == 1


def test_network_identity_refuses_an_address_as_a_name(client):
    body = _post(client, "/network-identity", {"observations": [
        {"ip": "10.20.1.10", "port": 443, "evidence_id": "NET-1"}]}).json()
    assert body["assets"] == []
    assert "IP:port is not an identity" in body["refused"][0]["reason"]


def test_network_identity_never_names_an_application_without_a_mapping(client):
    waf = {"hostname": "ext-waf-prod-01", "type": "WAF", "ips": ["10.20.1.20"],
           "zone": "DMZ", "collector_source": "cmdb-export", "evidence_id": "CMDB-1"}
    unlinked = _post(client, "/network-identity", {"observations": [waf]}).json()
    assert unlinked["links"]["links"][0]["inference"] == "NOT_PROVEN"
    assert unlinked["links"]["links"][0]["applications"] == []

    linked = _post(client, "/network-identity", {
        "observations": [waf],
        "links": {unlinked["assets"][0]["asset_id"]: {
            "applications": ["Payments API"], "evidence_id": "CMDB-7",
            "source": "CMDB"}}}).json()
    assert linked["links"]["links"][0]["inference"] == "PROVEN"
    assert linked["links"]["links"][0]["evidence_id"] == "CMDB-7"


def test_history_correlate_calls_the_four_signals_one_suspicious_pattern(client):
    from cbom import nbom_history as nh

    before = nh.snapshot([{"host": "payments.bank.example", "port": 443,
                           "tls_version": "1.3",
                           "cipher_suite": "TLS_AES_256_GCM_SHA384",
                           "evidence_id": "NET-1",
                           "certificate": {"fingerprint_sha256": "aa11",
                                           "issuer": "BANK-ICA-01"}}],
                         taken_at="2026-11-01T00:00:00Z")
    after = nh.snapshot([
        {"host": "payments.bank.example", "port": 443, "tls_version": "1.2",
         "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "evidence_id": "NET-9",
         "certificate": {"fingerprint_sha256": "cc33", "issuer": "BANK-ICA-09"}},
        {"host": "new.bank.example", "port": 9443, "tls_version": "1.3",
         "evidence_id": "NET-10"}], taken_at="2026-11-02T00:00:00Z")
    body = _post(client, "/history/correlate", {
        "before": before, "after": after,
        "processes": [{"process": "/usr/local/bin/openssl", "pid": 9182,
                       "host": "payments.bank.example", "evidence_id": "RT-1",
                       "observed_at": "2026-11-02T00:00:00Z"}]}).json()
    assert {"TLS_DOWNGRADE", "CERTIFICATE_MUTATION", "NEW_ENDPOINT",
            "NEW_PROCESS"} <= {signal["signal"] for signal in body["signals"]}
    combined = [pattern for pattern in body["patterns"]
                if pattern["name"] == "CORRELATED_PATTERN"]
    assert combined and combined[0]["classification"] == "SUSPICIOUS_ACTIVITY"
    assert body["worst"] == "SUSPICIOUS_ACTIVITY"
    assert "SECURITY_INCIDENT" in body["never"]
    assert "not a finding of compromise" in body["statement"]


def test_history_correlate_never_reaches_an_incident_even_when_it_correlates(client):
    from cbom import nbom_history as nh

    before = nh.snapshot([{"host": "a.bank.example", "port": 443,
                           "tls_version": "1.3", "evidence_id": "NET-1"}],
                         taken_at="2026-11-01T00:00:00Z")
    after = nh.snapshot([{"host": "a.bank.example", "port": 443,
                          "tls_version": "1.2", "evidence_id": "NET-2"}],
                        taken_at="2026-11-02T00:00:00Z")
    body = _post(client, "/history/correlate",
                 {"before": before, "after": after}).json()
    assert body["patterns"]
    assert all(pattern["level"] <= 2 for pattern in body["patterns"])
    assert all(pattern["not_proven"] for pattern in body["patterns"])


def test_history_correlate_refuses_a_document_that_is_not_a_snapshot(client):
    response = _post(client, "/history/correlate", {"before": {}, "after": {}})
    assert response.status_code == 422


def test_cipher_suite_decomposition_names_where_each_dimension_came_from(client):
    body = _post(client, "/cipher-suite", {"handshakes": [
        {"endpoint": "payments.bank.example:443",
         "cipher_suite": "TLS_AES_256_GCM_SHA384", "tls_version": "1.3",
         "group": "X25519", "signature_algorithm": "ECDSA_SECP256R1_SHA256",
         "evidence_id": "NET-1"}]}).json()
    handshake = body["handshakes"][0]
    dimensions = handshake["dimensions"]
    assert dimensions["ENCRYPTION"]["evidence"] == "NAMED_IN_SUITE"
    assert dimensions["KEY_EXCHANGE"]["algorithm"] == "X25519"
    assert dimensions["KEY_EXCHANGE"]["evidence"] == "NEGOTIATED"
    assert dimensions["AUTHENTICATION"]["algorithm"] == "ECDSA-P256"
    assert body["dimensions"] == ["KEY_EXCHANGE", "AUTHENTICATION", "ENCRYPTION", "HASH"]
    assert {fact["role"] for fact in body["algorithms"]} == {
        "KEY_EXCHANGE", "SIGNATURE", "BULK", "HASH"}


def test_cipher_suite_decomposition_leaves_unnamed_dimensions_unknown(client):
    body = _post(client, "/cipher-suite", {
        "suite": "TLS_AES_256_GCM_SHA384"}).json()
    handshake = body["handshakes"][0]
    assert handshake["not_named"] == ["KEY_EXCHANGE", "AUTHENTICATION"]
    assert handshake["dimensions"]["KEY_EXCHANGE"]["algorithm"] is None
    assert "not RSA" in handshake["dimensions"]["KEY_EXCHANGE"]["note"]
    assert body["with_unknown_dimensions"] == 1
    assert len(body["algorithms"]) == 2


def test_cipher_suite_decomposition_refuses_a_handshake_with_no_suite(client):
    response = _post(client, "/cipher-suite", {"handshakes": [{"endpoint": "x:443"}]})
    assert response.status_code == 200
    assert response.json()["refused"][0]["reason"] == (
        "a decomposition needs a cipher suite")


def test_certificate_chain_assembles_a_path_and_never_calls_it_trusted(client):
    leaf = {"certificate_ref": "CERT-9281", "subject": "CN=payments.bank.example",
            "issuer": "CN=BANK-ICA-01", "not_after": "2027-01-01T00:00:00Z",
            "public_key_algorithm": "ECDSA", "key_size": 256,
            "signature_algorithm": "ECDSA-SHA256", "authority_key_id": "ski-ica",
            "san": ["payments.bank.example"], "endpoint": "payments.bank.example:443",
            "evidence_id": "CERT-E1", "source": "network-probe",
            "observed_at": "2026-11-01T00:00:00Z"}
    intermediate = {"certificate_ref": "CERT-ICA1", "subject": "CN=BANK-ICA-01",
                    "issuer": "CN=BANK-ROOT-01", "is_ca": True,
                    "not_after": "2030-01-01T00:00:00Z", "public_key_algorithm": "RSA",
                    "key_size": 4096, "signature_algorithm": "SHA256-RSA",
                    "subject_key_id": "ski-ica", "evidence_id": "CERT-E2",
                    "source": "pki-export"}
    root = {"certificate_ref": "CERT-ROOT", "subject": "CN=BANK-ROOT-01",
            "issuer": "CN=BANK-ROOT-01", "is_ca": True,
            "not_after": "2035-01-01T00:00:00Z", "public_key_algorithm": "RSA",
            "key_size": 4096, "signature_algorithm": "SHA256-RSA",
            "evidence_id": "CERT-E3", "source": "pki-export"}
    body = _post(client, "/certificate-chain", {
        "certificates": [leaf, intermediate, root],
        "anchors": ["CERT-ROOT"]}).json()
    path = next(row for row in body["paths"] if row["certificate_ref"] == "CERT-9281")
    assert path["resolution"] == "ANCHORED" and path["depth"] == 3
    assert path["matched_by"][0] == "AUTHORITY_KEY_ID"
    assert "TRUSTED" not in str(body)
    assert body["anchors_unconfirmed"] == []
    assert body["edges"]["counts"]["SIGNED_BY"] == 2
    assert body["summary"]["quantum_vulnerable"] == ["CERT-9281", "CERT-ICA1",
                                                     "CERT-ROOT"]


def test_certificate_chain_reports_a_missing_issuer_as_incomplete(client):
    leaf = {"certificate_ref": "CERT-ORPHAN", "subject": "CN=partner.bank.example",
            "issuer": "CN=PARTNER-CA-01", "not_after": "2027-01-01T00:00:00Z",
            "public_key_algorithm": "RSA", "key_size": 2048,
            "signature_algorithm": "SHA256-RSA", "evidence_id": "CERT-E4",
            "source": "network-probe", "observed_at": "2026-11-01T00:00:00Z"}
    body = _post(client, "/certificate-chain", {"certificates": [leaf]}).json()
    path = body["paths"][0]
    assert path["resolution"] == "INCOMPLETE"
    assert path["missing_issuer"] == "CN=PARTNER-CA-01"
    assert body["summary"]["incomplete"] == ["CERT-ORPHAN"]


def test_certificate_chain_refuses_a_certificate_it_cannot_name(client):
    body = _post(client, "/certificate-chain", {
        "certificates": [{"subject": "CN=x", "evidence_id": "E-1"}]}).json()
    assert body["certificates"] == {}
    assert "needs a reference" in body["refused"][0]["reason"]
