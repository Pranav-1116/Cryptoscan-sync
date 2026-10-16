"""The outward notification channel consumer (§5, round 77).

The routing matrix's webhook/SIEM columns were stored but never consumed:
the delivery engine only fans siem.*/itsm.*/ticket.* prefixed events, so a
verification outcome routed to SIEM never reached a SOC. POST
/notifications/dispatch is the missing consumer — it drains NEW journal
events past a stored cursor, keeps only classes routed to webhook/siem,
and fans each to the registered integrations its channel claims over REAL
signed HTTP (fake transport injected here), recording every attempt in the
integrations delivery audit. Email routing is counted, never claimed sent.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "notif-dispatch-" + "z" * 18)
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/disp.db")
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.setenv("ZELNX_WEBHOOK_SECRET", "dispatch-signing-secret")
    from api.config.settings import get_settings
    get_settings.cache_clear()
    from db.connection import engine as engine_mod
    engine_mod._ENGINE = None
    from api.events.bus import reset_event_bus
    reset_event_bus()
    from api.middleware.abac_middleware import reset_abac_cache
    reset_abac_cache()

    # Delivery targets `*.example` hosts with the fake HTTP layer injected —
    # stub DNS so the SSRF guard treats them as public receivers.
    def _fake_getaddrinfo(host, port, *a, **k):
        return [(2, 1, 6, "", ("8.8.8.8", port or 443))]

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


def _seed_events(count=1):
    """Append journal rows directly (outside a request: no tenant stamp)."""
    from db.connection.session import SessionLocal
    from db.models.monitor import MonitorEvent

    now = datetime.now(timezone.utc)
    with SessionLocal() as s:
        for i in range(count):
            s.add(MonitorEvent(
                event_type="remediation.task_verified", target_name="remediation",
                detail=f"Remediation task t-{i} verification: VERIFIED",
                payload={"task_id": f"t-{i}", "result": "VERIFIED"}, created_at=now))
        s.commit()


def _seed_unrouted_and_unmapped():
    from db.connection.session import SessionLocal
    from db.models.monitor import MonitorEvent

    now = datetime.now(timezone.utc)
    with SessionLocal() as s:
        # class routed in-app ONLY (remediation_task: outward channels off)
        s.add(MonitorEvent(
            event_type="remediation.task_created", target_name="remediation",
            detail="Remediation task t-99 created", payload={}, created_at=now))
        # emitted platform type with NO catalog mapping — never force-fit
        s.add(MonitorEvent(
            event_type="graph.updated", target_name="graph",
            detail="Graph rebuilt", payload={}, created_at=now))
        s.commit()


def test_dispatch_delivers_routed_classes_over_signed_http_once(client, monkeypatch):
    import control_plane.delivery as dmod

    h = _h(client)
    # one SIEM/SOAR receiver (siem channel) + one ITSM receiver (webhook channel)
    reg_siem = client.post("/api/v1/enterprise/integrations", headers=h, json={
        "kind": "siem", "provider": "webhook", "name": "soc",
        "endpoint": "https://soc.example/hook"})
    assert reg_siem.status_code == 201
    assert client.post("/api/v1/enterprise/integrations", headers=h, json={
        "kind": "itsm", "provider": "webhook", "name": "ops",
        "endpoint": "http://ops.example/hook"}).status_code == 201

    captured: list[tuple[str, object]] = []

    def fake_http_post(post, endpoint, *, content=None, headers=None, timeout=None):
        captured.append((endpoint, content))
        # the SIEM receiver accepts, the ITSM receiver errors — per-target
        # honest outcomes, never a fabricated "delivered"
        return (200, "ok") if "soc.example" in endpoint else (503, "unavailable")

    monkeypatch.setattr(dmod, "_http_post", fake_http_post)

    _seed_events(count=1)  # remediation_verification: siem+webhook ON (defaults)
    _seed_unrouted_and_unmapped()

    r = client.post("/api/v1/notifications/dispatch", headers=h, json={"limit": 50})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["window"] >= 3
    assert body["examined"] == 1  # only the verification outcome is routed outward
    assert body["dispatched"] == 1
    assert body["delivered"] == 1 and body["failed"] == 1
    assert body["integrations"] == {"siem": 1, "webhook": 1}
    # email routing counted, never claimed sent
    assert body["email_routed"] == 1
    assert "no SMTP transport" in body["note"]

    # the envelope is notification.<class>, carrying the real detail; the
    # SIEM receiver got one POST, the erroring ITSM receiver one + its retry
    assert len([1 for url, _ in captured if "soc.example" in url]) == 1
    assert len([1 for url, _ in captured if "ops.example" in url]) == 2
    (att,) = body["attempts"]
    assert att["event_class"] == "remediation_verification"
    assert set(att["channels"]) == {"siem", "webhook"}
    soc_bodies = [c for url, c in captured if "soc.example" in url]
    assert "notification.remediation_verification" in str(soc_bodies[0])
    assert "VERIFIED" in str(soc_bodies[0])

    # every attempt audited in the integrations delivery log
    logs = client.get("/api/v1/enterprise/integrations/deliveries", headers=h).json()
    assert len(logs["deliveries"]) >= 2
    assert logs["stats"].get("delivered", 0) >= 1
    assert logs["stats"].get("failed", 0) >= 1

    # ONCE per tenant: the dispatch registry retains the event id, so a
    # second drain finds nothing new to send
    r2 = client.post("/api/v1/notifications/dispatch", headers=h, json={"limit": 50})
    body2 = r2.json()
    assert body2["dispatched"] == 0 and body2["examined"] == 0
    assert body2["registry_size"] == body["registry_size"]


def test_outward_routing_is_load_bearing(client, monkeypatch):
    """Switching a class's outward channels off in the matrix actually stops
    its delivery — the routing is not write-only configuration."""
    import control_plane.delivery as dmod

    monkeypatch.setattr(dmod, "_http_post",
                        lambda post, endpoint, *, content=None, headers=None, timeout=None:
                        (200, "ok"))
    h = _h(client)
    client.post("/api/v1/enterprise/integrations", headers=h, json={
        "kind": "siem", "provider": "webhook", "name": "soc",
        "endpoint": "https://soc.example/hook"})

    # route remediation_verification to in-app ONLY
    routing = client.get("/api/v1/notifications/routing", headers=h).json()["routing"]
    for item in routing:
        if item["id"] == "remediation_verification":
            item["channels"] = {"inApp": True, "email": False,
                                "webhook": False, "siem": False}
    put = client.put("/api/v1/notifications/routing", headers=h,
                     json={"routing": routing})
    assert put.status_code == 200

    _seed_events(count=1)
    r = client.post("/api/v1/notifications/dispatch", headers=h, json={"limit": 50})
    body = r.json()
    # in the window but dispatched nowhere — the outward toggle binds
    assert body["window"] >= 1
    assert body["dispatched"] == 0
    assert body["delivered"] == 0

    # re-enabling the siem channel delivers what accumulated while it was
    # off (the first event was never outward-dispatched, so it was never
    # registered) PLUS the new one — each still exactly once
    for item in routing:
        if item["id"] == "remediation_verification":
            item["channels"]["siem"] = True
    client.put("/api/v1/notifications/routing", headers=h, json={"routing": routing})
    _seed_events(count=1)
    r2 = client.post("/api/v1/notifications/dispatch", headers=h, json={"limit": 50})
    body2 = r2.json()
    assert body2["dispatched"] == 2
    assert body2["delivered"] == 2
    # and a third drain adds nothing — the registry now holds both
    r3 = client.post("/api/v1/notifications/dispatch", headers=h, json={"limit": 50})
    assert r3.json()["dispatched"] == 0


def test_air_gap_integration_is_skipped_never_fabricated(client, monkeypatch):
    """An integration with no endpoint (air-gap doctrine) keeps the event as
    outbox-queued: the attempt is recorded as skipped, and nothing claims
    delivery. Email-routed classes are counted the same honest way."""
    h = _h(client)
    client.post("/api/v1/enterprise/integrations", headers=h, json={
        "kind": "siem", "provider": "webhook", "name": "airgap-soc",
        "endpoint": None})

    _seed_events(count=1)
    r = client.post("/api/v1/notifications/dispatch", headers=h, json={"limit": 50})
    assert r.status_code == 200
    body = r.json()
    assert body["examined"] == 1
    assert body["dispatched"] == 1
    assert body["skipped"] == 1 and body["delivered"] == 0
    (att,) = body["attempts"]
    (res,) = att["results"]
    assert res["status"] == "skipped"
    assert "no endpoint" in (res["error"] or "")
    # the email channel stays count-only: routed, but never claimed sent
    assert body["email_routed"] == 1
