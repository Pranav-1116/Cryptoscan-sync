"""API tests: ABAC enforcement middleware + real outbound SIEM/ITSM delivery."""

from __future__ import annotations

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/enf.db")
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.setenv("ABAC_ENFORCED", "true")
    from api.config.settings import get_settings
    get_settings.cache_clear()
    from db.connection import engine as engine_mod
    engine_mod._ENGINE = None
    from api.events.bus import reset_event_bus
    reset_event_bus()
    from api.middleware.abac_middleware import reset_abac_cache
    reset_abac_cache()
    # Delivery tests point webhooks at `*.example` hosts (fake HTTP layer is
    # injected) — stub DNS so the SSRF guard treats them as public receivers.

    def _fake_getaddrinfo(host, port, *a, **k):
        return [(2, 1, 6, "", ("8.8.8.8", port or 443))]  # public resolver range → passes guard

    import socket as _socket

    monkeypatch.setattr(_socket, "getaddrinfo", _fake_getaddrinfo)

    from api.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c
    reset_abac_cache()


def _h(c):
    t = c.post("/api/v1/auth/login",
               json={"username": "admin", "password": "cryptoscan"}).json()["token"]
    return {"Authorization": f"Bearer {t}"}


def _grant(c, h, **fields):
    body = {"subject": "admin", "subject_type": "user", "actions": ["*"],
            "effect": "allow"}
    body.update(fields)
    return c.post("/api/v1/control/grants", headers=h, json=body)


# ----------------------------------------------------------------- ABAC
def test_abac_denies_without_grant_when_enforced(client):
    h = _h(client)
    # No grants provisioned -> middleware permissive (greenfield), so seed one
    # grant for a *different* region; enforcement then becomes fail-closed.
    assert _grant(client, h, region="apac").status_code == 201
    # Request scoped to a region the single grant does NOT cover -> 403.
    r = client.get("/api/v1/stats/summary?region=eu", headers=h)
    assert r.status_code == 403
    assert r.json()["error_code"] == "ABAC_DENIED"


def test_abac_allows_within_granted_scope(client):
    h = _h(client)
    _grant(client, h, region="eu")
    r = client.get("/api/v1/stats/summary?region=eu", headers=h)
    assert r.status_code == 200


def test_abac_explicit_deny_overrides_wildcard(client):
    h = _h(client)
    _grant(client, h, region="eu")  # wildcard allow on eu
    deny = client.post("/api/v1/control/grants", headers=h, json={
        "subject": "admin", "subject_type": "user", "actions": ["*"],
        "effect": "deny", "region": "eu", "environment": "prod"})
    assert deny.status_code == 201
    r = client.get("/api/v1/stats/summary?region=eu&environment=prod", headers=h)
    assert r.status_code == 403
    r2 = client.get("/api/v1/stats/summary?region=eu&environment=dev", headers=h)
    assert r2.status_code == 200


def test_me_grants_reports_effective_surface(client):
    h = _h(client)
    _grant(client, h, region="eu", business_unit="payments")
    r = client.get("/api/v1/control/me/grants", headers=h)
    assert r.status_code == 200
    data = r.json()
    assert data["principal"] == "admin"
    assert any(g["region"] == "eu" for g in data["grants"])


# ------------------------------------------------------------- delivery
def _register_siem(client, h, endpoint):
    return client.post("/api/v1/enterprise/integrations", headers=h, json={
        "kind": "siem", "provider": "webhook", "name": "soc-test",
        "endpoint": endpoint})


def test_siem_export_records_failed_delivery_when_endpoint_errors(client, monkeypatch):
    # Receiver answers 5xx every time: delivery is attempted over HTTP, retried,
    # then recorded as failed (and audited) — never fabricated as delivered.
    import control_plane.delivery as dmod

    def flaky(post, endpoint, *, content=None, headers=None, timeout=None):
        return 503, "unavailable"

    monkeypatch.setattr(dmod, "_http_post", flaky)
    h = _h(client)
    reg = _register_siem(client, h, "http://soc.example/hook")
    assert reg.status_code == 201
    r = client.post("/api/v1/enterprise/integrations/siem/export", headers=h, json={
        "provider": "webhook",
        "events": [{"category": "finding", "name": "weak-tls", "severity": "high",
                    "asset": "h1", "detail": "TLS1.0"}]})
    assert r.status_code == 200
    deliveries = r.json().get("deliveries", [])
    assert deliveries and deliveries[0]["status"] in ("failed", "skipped")

    logs = client.get("/api/v1/control/deliveries", headers=h).json()
    assert logs["count"] >= 1
    assert "failed" in logs["stats"] or "skipped" in logs["stats"]


def test_integration_test_endpoint_uses_injected_post(client, monkeypatch):
    monkeypatch.setenv("ZELNX_WEBHOOK_SECRET", "test-signing-secret")
    h = _h(client)
    _register_siem(client, h, "https://soc.example/hook")

    # Patch the real HTTP POST to simulate a 200 receiver — exercises signing,
    # payload shaping and the audit path without network.
    import control_plane.delivery as dmod

    captured = {}

    def fake_http_post(post, endpoint, *, content=None, headers=None, timeout=None):
        captured["url"] = endpoint
        captured["headers"] = headers
        captured["content"] = content
        return 200, "accepted"

    monkeypatch.setattr(dmod, "_http_post", fake_http_post)
    integ_id = client.get("/api/v1/enterprise/integrations", headers=h).json()["integrations"][0]["id"]
    r = client.post(f"/api/v1/enterprise/integrations/{integ_id}/test", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "delivered" and body["http_status"] == 200
    assert captured["url"] == "https://soc.example/hook"
    assert captured["headers"]["X-ZELNX-Signature"].startswith("sha256=")


def test_flush_delivers_queued_siem_event(client, monkeypatch):
    h = _h(client)
    _register_siem(client, h, "https://soc.example/hook")
    import control_plane.delivery as dmod

    def fake_http_post(post, endpoint, *, content=None, headers=None, timeout=None):
        return 202, "queued"

    monkeypatch.setattr(dmod, "_http_post", fake_http_post)

    # Enqueue a siem event directly via the repository.
    from db.connection.session import SessionLocal
    from db.repositories.control_plane_repository import ControlPlaneRepository
    with SessionLocal() as s:
        ControlPlaneRepository(s).enqueue(
            event_type="siem.finding",
            payload={"severity": "critical", "asset": "h1", "detail": "RSA-1024"},
            source="test")
        s.commit()

    r = client.post("/api/v1/control/deliveries/flush", headers=h, json={"limit": 10})
    assert r.status_code == 200
    body = r.json()
    assert body["events_flushed"] >= 1
    assert body["delivered"] >= 1
