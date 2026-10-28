"""API contract for Cryptographic Network Intelligence observation (spec 67).

The scanner and the external admission/metering seams are controlled; the
FastAPI request path, scope storage and 409 refusal are real. No socket is
opened, and nothing here qualifies a live bank device.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session, get_tenant_context
from api.main import create_app
from db.connection.session import Base


@pytest.fixture()
def client(monkeypatch):
    import api.routers.network as network_router
    from network_scanner.core.scanner import NetworkTlsScanner

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "tester"
    app.dependency_overrides[get_db_session] = lambda: session
    app.dependency_overrides[get_tenant_context] = lambda: type("Ctx", (), {"tenant_id": None, "roles": ["superadmin"], "username": "tester"})()
    app.dependency_overrides[network_router.network_context] = lambda: None

    calls: list[dict] = []

    def fake_scan(self, hosts, **kwargs):
        calls.append({"hosts": list(hosts), "kwargs": kwargs})
        return {
            "scan_id": "scan-test",
            "findings": [
                {
                    "finding_id": "finding-1",
                    "endpoint": "10.20.10.15:443",
                    "ip_address": "10.20.10.15",
                    "status": "OK",
                    "crypto": {
                        "tls_version": "TLSv1.3",
                        "cipher_suite": "TLS_AES_256_GCM_SHA384",
                        "key_exchange_algorithm": "ECDHE",
                        "authentication_algorithm": "ECDSA",
                        "encryption_algorithm": "AES-256",
                        "encryption_mode": "GCM",
                        "key_algorithm": "ECDHE",
                    },
                    "certificates": [
                        {
                            "fingerprint_sha256": "sha256:abc",
                            "public_key_algorithm": "ECDSA",
                            "curve": "P-256",
                            "signature_algorithm": "ecdsa-with-SHA256",
                        }
                    ],
                    "chain_validation": {"structural_status": "OK", "trust_status": "NOT_VERIFIED"},
                    "policy_issues": [],
                    "metadata": {"confidence": "HIGH"},
                },
                {
                    "finding_id": "finding-2",
                    "endpoint": "10.20.10.16:443",
                    "status": "PORT_CLOSED",
                    "crypto": {},
                    "certificates": [],
                    "metadata": {"confidence": "LOW"},
                },
            ],
            "certificates": [],
            "probe_telemetry": {"status": "PARTIAL", "probed": len(hosts), "ok": 1},
        }

    monkeypatch.setattr(NetworkTlsScanner, "scan_hosts", fake_scan)
    monkeypatch.setattr(network_router, "admit_network", lambda targets, **kwargs: {"decision": "PERMITTED", "targets": list(targets)})
    monkeypatch.setattr(network_router, "meter_network", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        network_router,
        "persist_network",
        lambda db, result, run, **kwargs: {"job_id": "job-1", "run_id": "run-1", "durable": True},
    )

    def fake_run(db, **kwargs):
        from contextlib import contextmanager

        @contextmanager
        def _run():
            class Run:
                job_id = "job-1"
                run_id = "run-1"

                def plan(self, *_args, **_kwargs):
                    return None

                def succeed(self, **_kwargs):
                    return None

                def conclusions(self):
                    return {}

            yield Run()

        return _run()

    monkeypatch.setattr(network_router, "network_run", fake_run)
    monkeypatch.setattr(network_router, "network_coverage", lambda result: {})
    try:
        yield TestClient(app), session, calls
    finally:
        session.close()
        app.dependency_overrides.clear()


def put_scope(client, **overrides):
    body = {
        "name": "payments-prod",
        "destinations": ["10.20.10.15:443", "10.20.10.16:443"],
        "protocols": ["TLS"],
        "allowed_operations": ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"],
        "traffic_budget": {"max_connections": 20, "max_bytes": 10485760},
        "valid_until": (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat(),
        "inventory_id": "default",
    }
    body.update(overrides)
    return client.put("/api/v1/network/crypto-scope", json=body)


def test_scope_starts_unconfigured(client):
    http, _session, _calls = client
    response = http.get("/api/v1/network/crypto-scope")
    assert response.status_code == 200
    assert response.json()["status"]["state"] == "NOT_CONFIGURED"
    assert response.json()["scope"] is None


def test_scope_rejects_loopback_destination(client):
    http, _session, _calls = client
    response = put_scope(http, destinations=["127.0.0.1:443"])
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "invalid_destination"


def test_scope_rejects_past_validity(client):
    http, _session, _calls = client
    response = put_scope(http, valid_until="2020-01-01T00:00:00Z")
    assert response.status_code == 422


def test_observation_refused_without_scope_and_opens_no_socket(client):
    http, _session, calls = client
    response = http.post("/api/v1/network/crypto-observe", json={"endpoints": ["10.20.10.15:443"]})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "scope_not_configured"
    assert calls == []


def test_observation_refused_for_destination_outside_scope(client):
    http, _session, calls = client
    assert put_scope(http).status_code == 200
    response = http.post("/api/v1/network/crypto-observe", json={"endpoints": ["10.99.99.99:443"]})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "destination_outside_scope"
    assert calls == []


def test_observation_refused_after_scope_expiry(client):
    http, session, calls = client
    assert put_scope(http).status_code == 200
    # Expire it in storage exactly as a stale approval would.
    from db.models.app_setting import AppSetting

    key = "network:crypto-scope:default:default"
    row = session.query(AppSetting).filter(AppSetting.key == key).one()
    row.value = row.value.replace("+00:00", "+00:00")
    import json

    payload = json.loads(row.value)
    payload["valid_until"] = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    row.value = json.dumps(payload)
    session.commit()

    response = http.post("/api/v1/network/crypto-observe", json={"endpoints": ["10.20.10.15:443"]})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "scope_expired"
    assert calls == []


def test_observation_returns_spec_evidence_records(client):
    http, _session, calls = client
    assert put_scope(http).status_code == 200
    response = http.post("/api/v1/network/crypto-observe", json={"endpoints": ["10.20.10.15:443", "10.20.10.16:443"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["model"] == "cryptoscan.network-crypto-observation/1"
    assert body["scope"]["decision"] == "PERMITTED"
    assert calls and calls[0]["hosts"] == ["10.20.10.15:443", "10.20.10.16:443"]

    evidence = {record["target"]["endpoint"]: record for record in body["evidence"]}
    observed = evidence["10.20.10.15:443"]
    assert observed["evidence_type"] == "NETWORK_ACTIVE_OBSERVED"
    assert observed["decomposition"]["key_exchange"] == "ECDHE"
    assert observed["mutual_tls"] == "NOT_REQUIRED"

    unobserved = evidence["10.20.10.16:443"]
    assert unobserved["evidence_type"] == "UNKNOWN"
    assert unobserved["tls_version"] is None

    summary = body["summary"]
    assert summary["observed"] == 1
    assert summary["not_observed"] == 1
    assert summary["tls_versions"] == {"TLSv1.3": 1}


def test_evidence_and_cbom_read_back_from_stored_runs(client):
    http, session, _calls = client
    from db.repositories.scan_run_repository import ScanRunRepository
    from network_scanner.inventory.network_evidence import build_evidence

    record = build_evidence(
        {
            "finding_id": "stored-1",
            "endpoint": "10.20.10.15:443",
            "status": "OK",
            "ip_address": "10.20.10.15",
            "crypto": {
                "tls_version": "TLSv1.3",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "key_exchange_algorithm": "ECDHE",
                "encryption_algorithm": "AES-256",
                "encryption_mode": "GCM",
            },
            "certificates": [{"fingerprint_sha256": "sha256:abc", "public_key_algorithm": "ECDSA", "curve": "P-256"}],
            "metadata": {"confidence": "HIGH"},
        }
    )
    ScanRunRepository(session).create_run({"network_evidence": [record]}, target_kind="crypto-observe")
    session.commit()

    listing = http.get("/api/v1/network/crypto-evidence")
    assert listing.status_code == 200, listing.text
    body = listing.json()
    assert body["count"] == 1
    assert body["summary"]["observed"] == 1
    assert body["evidence"][0]["target"]["endpoint"] == "10.20.10.15:443"

    cbom = http.get("/api/v1/network/crypto-cbom")
    assert cbom.status_code == 200, cbom.text
    projection = cbom.json()
    assert projection["layer"] == "NETWORK_TRANSPORT"
    assert "AES-256" in projection["algorithms"]
    assert projection["asset_count"] > 0


def test_evidence_listing_is_empty_and_honest_before_any_run(client):
    http, _session, _calls = client
    body = http.get("/api/v1/network/crypto-evidence").json()
    assert body["count"] == 0
    assert "NOT_OBSERVED" in body["note"]


def test_crypto_path_requires_declared_hops(client):
    http, _session, _calls = client
    assert http.post("/api/v1/network/crypto-path", json={"hops": []}).status_code == 422


def test_crypto_path_marks_undeclared_hop_unknown(client):
    http, _session, _calls = client
    response = http.post(
        "/api/v1/network/crypto-path",
        json={"hops": [{"from": "10.20.10.15:443", "to": "api-gateway"}]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["edges"][0]["evidence_type"] == "UNKNOWN"
    assert body["complete"] is False


def test_ipsec_observation_refused_without_scope(client):
    http, _session, _calls = client
    response = http.post("/api/v1/network/ipsec-observe", json={"endpoints": ["10.20.10.99:500"]})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "scope_not_configured"


def test_ipsec_observation_refused_when_protocol_not_approved(client):
    http, _session, _calls = client
    assert put_scope(http).status_code == 200  # TLS-only scope
    response = http.post("/api/v1/network/ipsec-observe", json={"endpoints": ["10.20.10.15:443"]})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "protocol_not_allowed"


# --------------------------------------------------------------------------- #
# IPsec observation: IKEv1 reachable, ESP/PFS stated on a real basis (§13)
# --------------------------------------------------------------------------- #
def _ipsec_scope(http):
    return put_scope(
        http,
        destinations=["10.20.10.20:500"],
        protocols=["IPsec"],
        allowed_operations=["IKE_PROBE"],
    )


def _ipsec_probe(host, **kwargs):
    """A probe that answered over IKEv1, with the caller's declared ESP suite."""
    import network_scanner.probing.ipsec_probe as probe_module

    esp = (
        probe_module.esp_from_config(kwargs["esp_config"])
        if kwargs.get("esp_config")
        else probe_module.summarize_proposals([], ike_version=1)["esp"]
    )
    return {
        "endpoint": f"{host}:500",
        "status": "OK",
        "port": 500,
        "transport": "UDP",
        "ike_version": "IKEv1",
        "header": {"version": "IKEv1.0", "major": 1, "exchange": "MAIN_MODE"},
        "ike": {
            "protocol": "IKE", "version": "IKEv1", "encryption": "AES-CBC-256", "prf": "HMAC-SHA1",
            "integrity": None, "dh_group": "MODP-2048", "esn": False,
            "auth_methods_offered": ["PRE-SHARED-KEY"],
        },
        "esp": esp,
        "ke": None,
        "notifies": [],
        "proposals": [],
        "issues": [],
        "detail": None,
        "attempts": [
            {"version": "IKEv2", "port": 500, "status": "NO_RESPONSE"},
            {"version": "IKEv1", "port": 500, "status": "OK"},
        ],
    }


def test_ipsec_observe_accepts_an_ikev1_gateway_and_a_declared_esp_suite(client, monkeypatch):
    http, _session, _calls = client
    import network_scanner.probing.ipsec_probe as probe_module

    assert _ipsec_scope(http).status_code == 200
    seen: dict = {}

    def fake_probe(host, **kwargs):
        seen.update(kwargs)
        return _ipsec_probe(host, **kwargs)

    monkeypatch.setattr(probe_module, "probe_ike", fake_probe)
    response = http.post(
        "/api/v1/network/ipsec-observe",
        json={
            "endpoints": ["10.20.10.20:500"],
            "timeout": 1.0,
            "ike_versions": [2, 1],
            "esp_suite": {
                "encryption": "AES-CBC-256",
                "integrity": "HMAC-SHA2-256",
                "dh_group": "MODP-2048",
                "pfs": "ON",
                "reference": "cmdb:vpn-1",
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()

    # the probe was actually asked to speak both versions and was handed the suite
    assert seen["versions"] == (2, 1)
    assert seen["esp_config"]["reference"] == "cmdb:vpn-1"

    evidence = body["evidence"][0]
    assert evidence["ike"]["version"] == "IKEv1.0", "the responder's real version, not a hardcoded IKEv2"
    assert evidence["ike"]["auth_methods_offered"] == ["PRE-SHARED-KEY"]
    # ESP was declared, not negotiated: CONFIGURED with its reference, PFS on that basis
    assert evidence["esp"]["status"] == "CONFIGURED"
    assert evidence["esp"]["basis"] == "CONFIGURATION"
    assert evidence["esp"]["pfs_state"] == "ON"

    # the observation payload is returned flat
    assert body["esp_configured"] is True
    assert body["esp_observed"] is False
    assert body["ike_versions"] == ["IKEv1.0"]
    assert "Quick Mode" in body["boundary"]
    assert "CONFIGURATION" in body["boundary"]


def test_ipsec_observe_without_a_declared_suite_leaves_esp_unobserved(client, monkeypatch):
    http, _session, _calls = client
    import network_scanner.probing.ipsec_probe as probe_module

    assert _ipsec_scope(http).status_code == 200
    monkeypatch.setattr(probe_module, "probe_ike", _ipsec_probe)
    response = http.post(
        "/api/v1/network/ipsec-observe",
        json={"endpoints": ["10.20.10.20:500"], "timeout": 1.0},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    evidence = body["evidence"][0]
    assert evidence["esp"]["status"] == "NOT_OBSERVED"
    assert evidence["esp"]["basis"] == "NOT_OBSERVED"
    assert evidence["esp"]["pfs_state"] == "UNKNOWN"
    assert body["esp_configured"] is False
    assert body["esp_observed"] is False
    assert body["ike_versions"] == ["IKEv1.0"]
