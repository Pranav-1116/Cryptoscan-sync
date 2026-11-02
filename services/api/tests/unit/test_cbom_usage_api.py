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


def test_hsm_capability_is_not_an_operation(client):
    capability = _post(client, "/hsm-evidence", {"kind": "CAPABILITY"}).json()
    assert capability["class"] == "VENDOR_DECLARED" and capability["observed"] is False
    operation = _post(client, "/hsm-evidence", {"kind": "OPERATION",
                                                "evidence_id": "HSM-1",
                                                "operation": "sign"}).json()
    assert operation["class"] == "RUNTIME_OBSERVED" and operation["operation"] == "SIGN"


def test_an_hsm_operation_without_evidence_is_422(client):
    assert _post(client, "/hsm-evidence", {"kind": "OPERATION"}).status_code == 422
