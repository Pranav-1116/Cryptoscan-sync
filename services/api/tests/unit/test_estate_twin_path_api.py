"""The path endpoint: an evidence-backed chain, or the hop that stopped it.

`GET /estate/evidence/twin/path` is the only place the twin answers the vision's
actual question — *what does this application's crypto really rest on?* — from the
store rather than from a diagram. These tests pin the four things that make the
answer worth trusting:

* a hop with no evidence is not taken, and the path is not shortened to hide it;
* an ambiguous asset name is refused with candidates instead of guessed;
* the walk says whether the `uses` hops rest on runtime observation or on
  configuration ("installed ≠ executed");
* a snapshot that does not exist is a refusal, never an empty path.
"""

from __future__ import annotations

import pytest


def _payload() -> dict:
    """The vision's chain, one real estate: app → container → cluster → OpenSSL → AES,
    plus TLS terminated at a load balancer that uses an HSM."""
    return {
        "estate": "Payments Bank",
        "scope": "production",
        "assets": [
            {"ref": "api", "type": "APPLICATION", "name": "Payment API",
             "environment": "production", "identity": {"name": "payment-api"}},
            {"ref": "ctr", "type": "CONTAINER", "name": "payments-api-7d9f",
             "environment": "production", "identity": {"container_id": "7d9f"}},
            {"ref": "k8s", "type": "CLUSTER", "name": "k8s-payments-prod",
             "environment": "production", "identity": {"cluster": "k8s-payments-prod"}},
            {"ref": "ossl", "type": "LIBRARY", "name": "OpenSSL 3.0.13",
             "environment": "production", "identity": {"name": "openssl", "version": "3.0.13"}},
            {"ref": "aes", "type": "CRYPTO_ASSET", "name": "AES-256-GCM",
             "environment": "production", "identity": {"name": "AES-256-GCM"}},
            {"ref": "lb", "type": "LOAD_BALANCER", "name": "alb-payments-01",
             "environment": "production", "identity": {"management_address": "10.0.0.9"}},
            {"ref": "hsm", "type": "HSM", "name": "hsm-01",
             "environment": "production", "identity": {"vendor": "Thales", "serial_number": "SN-1"}},
        ],
        "evidence": [
            {"evidence_id": "ev-k8s", "source": "kubernetes", "evidence_type": "CONFIGURED",
             "target": "api", "layer": "APPLICATION",
             "facts": {"deployment": "payments-api", "namespace": "payments"}},
            {"evidence_id": "ev-run", "source": "ld-preload", "evidence_type": "RUNTIME_OBSERVED",
             "target": "k8s", "layer": "APPLICATION",
             "facts": {"library": "OpenSSL 3.0.13", "calls": 1421}},
            {"evidence_id": "ev-tls", "source": "tls-probe", "evidence_type": "NETWORK_ACTIVE_OBSERVED",
             "target": "lb", "layer": "NETWORK_TRANSPORT",
             "facts": {"port": 443, "protocol": "TLSv1.3"}},
            {"evidence_id": "ev-p11", "source": "/etc/pkcs11.conf", "collector": "linux-static",
             "evidence_type": "CONFIGURED", "target": "hsm", "layer": "HSM",
             "facts": {"slot": 0, "mechanism": "CKM_AES_GCM"}},
        ],
        "relationships": [
            {"subject": "api", "predicate": "runs_on", "object": "ctr",
             "basis": "DEPLOYMENT_CONFIG", "evidence_ids": ["ev-k8s"]},
            {"subject": "ctr", "predicate": "runs_on", "object": "k8s",
             "basis": "DEPLOYMENT_CONFIG", "evidence_ids": ["ev-k8s"]},
            {"subject": "k8s", "predicate": "uses_crypto_library", "object": "ossl",
             "basis": "RUNTIME_OBSERVATION", "evidence_ids": ["ev-run"]},
            {"subject": "ossl", "predicate": "uses_algorithm", "object": "aes",
             "basis": "RUNTIME_OBSERVATION", "evidence_ids": ["ev-run"]},
            {"subject": "api", "predicate": "terminates_tls_for", "object": "lb",
             "basis": "NETWORK_OBSERVATION", "evidence_ids": ["ev-tls"]},
            {"subject": "lb", "predicate": "uses", "object": "hsm",
             "basis": "PKCS11_REFERENCE", "evidence_ids": ["ev-p11"]},
        ],
        "collectors": [
            {"plane": "KUBERNETES", "status": "COMPLETE", "expected": 1, "collected": 1},
        ],
    }


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/path.db")
    monkeypatch.setenv("NEO4J_URI", "")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c


def _headers(client):
    token = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}
    ).json()["token"]
    return {"Authorization": f"Bearer {token}"}


PATH = "/api/v1/estate/evidence/twin/path"


def _discover(client) -> dict:
    headers = _headers(client)
    created = client.post("/api/v1/estate/evidence/discover", json=_payload(), headers=headers)
    assert created.status_code == 200, created.text
    return headers


def test_path_requires_auth(client):
    assert client.get(PATH, params={"asset": "Payment API"}).status_code == 401


def test_path_refuses_without_a_snapshot(client):
    """No discovery is a refusal — an empty path would read as an empty estate."""
    response = client.get(PATH, params={"asset": "Payment API"}, headers=_headers(client))
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "no_estate_discovery"


def test_the_vision_chain_is_served_from_the_store(client):
    headers = _discover(client)
    response = client.get(PATH, params={"asset": "Payment API"}, headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "COMPLETE", body
    assert body["complete"] is True
    assert [hop["to_type"] for hop in body["hops"]] == [
        "CONTAINER", "CLUSTER", "LIBRARY", "CRYPTO_ASSET", "LOAD_BALANCER", "HSM",
    ]
    for hop in body["hops"]:
        assert hop["evidence_ids"], f"hop {hop['index']} reached the API with no evidence"
    # the HSM link is a PKCS#11 *reference*: configuration, not observation
    assert body["unobserved_hop_indexes"] == [6]
    assert body["requires_runtime_observation"] is True
    assert body["weakest_confidence"] == "MEDIUM"
    assert body["run_id"]


def test_the_path_can_be_asked_by_id_or_by_name(client):
    headers = _discover(client)
    by_name = client.get(PATH, params={"asset": "Payment API"}, headers=headers).json()
    by_id = client.get(PATH, params={"asset": by_name["start"]}, headers=headers).json()
    assert by_id["hops"] == by_name["hops"]


def test_an_unknown_asset_is_refused_without_guessing(client):
    headers = _discover(client)
    response = client.get(PATH, params={"asset": "Nonexistent App"}, headers=headers)
    assert response.status_code == 404
    detail = response.json()["detail"]
    assert detail["error"] == "asset_not_resolved"
    assert detail["candidates"] == []


def test_a_hop_without_evidence_stops_the_path_where_it_stops(client):
    """Ask for a hop the estate cannot carry and the answer is the stop, not a short path."""
    headers = _discover(client)
    response = client.get(
        PATH,
        params={"asset": "Payment API", "pattern": "runs_on:CONTAINER,uses:DATABASE"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["complete"] is False
    assert body["status"] == "NO_EDGE"
    assert body["hop_count"] == 1
    assert body["stop"]["predicate"] == "uses"
    assert body["stop"]["to_type"] == "DATABASE"
    assert "no established edge" in body["stop"]["reason"]


def test_an_impossible_pattern_is_a_400_not_an_empty_answer(client):
    headers = _discover(client)
    bad_predicate = client.get(
        PATH, params={"asset": "Payment API", "pattern": "frobnicates:CONTAINER"}, headers=headers
    )
    assert bad_predicate.status_code == 400
    assert "unknown predicate" in bad_predicate.json()["detail"]["reason"]

    bad_type = client.get(
        PATH, params={"asset": "Payment API", "pattern": "runs_on:SPACESHIP"}, headers=headers
    )
    assert bad_type.status_code == 400
    assert "unknown asset type" in bad_type.json()["detail"]["reason"]


def test_the_path_says_whether_use_was_observed_or_only_configured(client):
    """A complete path is not automatically an executed one.

    The k8s→OpenSSL hop rests on a `RUNTIME_OBSERVED` record and is not flagged; the
    load balancer→HSM hop rests on a PKCS#11 *reference*, which says the HSM will be
    used, not that it was, and must be flagged.
    """
    headers = _discover(client)

    observed = client.get(
        PATH,
        params={"asset": "k8s-payments-prod", "pattern": "uses_crypto_library:LIBRARY"},
        headers=headers,
    ).json()
    assert observed["complete"] is True
    assert observed["requires_runtime_observation"] is False
    assert observed["unobserved_hop_indexes"] == []

    configured = client.get(
        PATH, params={"asset": "alb-payments-01", "pattern": "uses:HSM"}, headers=headers
    ).json()
    assert configured["complete"] is True
    assert configured["hops"][0]["basis"] == "PKCS11_REFERENCE"
    assert configured["requires_runtime_observation"] is True, (
        "a PKCS#11 reference is a configuration claim; presenting it as observed use "
        "is exactly the 'installed != executed' error this flag exists to prevent"
    )
    assert configured["unobserved_hop_indexes"] == [1]
