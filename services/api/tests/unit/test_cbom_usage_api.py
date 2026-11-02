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
