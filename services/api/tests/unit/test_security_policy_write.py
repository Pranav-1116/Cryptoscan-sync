"""Scanning & Security Policy write contract (PUT /api/v1/security/policy).

The endpoint persists an organisation-wide policy, so a write must carry both
halves of the document. Before this contract an empty body (``{}``) was
accepted and silently persisted the built defaults while answering
``updated: true`` — an accidental reset of a configured policy. These tests pin
the refusal, the round-trip and the fail-closed guardrails.
"""

from __future__ import annotations

import pytest

PATH = "/api/v1/security/policy"


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/policy.db")
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


def test_requires_auth(client):
    assert client.put(PATH, json={}).status_code == 401


def test_empty_or_half_body_is_refused(client):
    h = _headers(client)
    # An empty body must not be read as "reset to defaults".
    assert client.put(PATH, json={}, headers=h).status_code == 422
    # Half a document must not reset the other half.
    assert client.put(PATH, json={"scan": {"mode": "read-only"}}, headers=h).status_code == 422
    assert client.put(PATH, json={"privacy": {"collect_pii": False}}, headers=h).status_code == 422
    # Non-object halves are refused rather than coerced.
    assert client.put(PATH, json={"scan": "read-only", "privacy": {}}, headers=h).status_code == 422


def test_roundtrip_persists_normalised_policy(client):
    h = _headers(client)
    current = client.get(PATH, headers=h).json()
    assert current["source"] == "security_policy"
    policy = current["policy"]

    policy["scan"]["rate_limit_qps"] = 7
    policy["privacy"]["retention_days"] = 30
    put = client.put(PATH, json=policy, headers=h)
    assert put.status_code == 200
    body = put.json()
    assert body["updated"] is True
    assert body["policy"]["scan"]["rate_limit_qps"] == 7
    assert body["policy"]["privacy"]["retention_days"] == 30

    # The stored value — not the request echo — is what the next read returns.
    again = client.get(PATH, headers=h).json()["policy"]
    assert again["scan"]["rate_limit_qps"] == 7
    assert again["privacy"]["retention_days"] == 30


def test_guardrails_never_loosen(client):
    h = _headers(client)
    policy = client.get(PATH, headers=h).json()["policy"]

    loosened_privacy = {**policy, "privacy": {**policy["privacy"], "collect_secrets": True}}
    assert client.put(PATH, json=loosened_privacy, headers=h).status_code == 422

    loosened_scan = {**policy, "scan": {**policy["scan"], "mode": "active"}}
    assert client.put(PATH, json=loosened_scan, headers=h).status_code == 422

    hot = {**policy, "scan": {**policy["scan"], "intensity": "high"}}
    assert client.put(PATH, json=hot, headers=h).status_code == 422
