"""Actual authenticated SSE, polling and metadata; drive ASGI without buffering."""

import asyncio
import contextlib
import json
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from api.main import create_app
from api.middleware.tenant_scope import TenantScopeMiddleware
from api.events.bus import reset_event_bus
from db.models.tenant import Tenant, TenantMembership
from db.repositories.api_key_repository import ApiKeyRepository
from db.repositories.user_repository import UserRepository
from test_software_supply_chain_api import banks as banks
from test_events_stream import ASGIStream


@pytest.fixture
def streams(banks, monkeypatch):
    clients, db, _ = banks
    bus = reset_event_bus()
    monkeypatch.setattr("api.routers.events.AUTH_RECHECK_SECONDS", 0.04)
    for who, owner in [("bank_a", "a"), ("bank_b", "b"), ("platform_admin", None)]:
        bus.publish("scan.own", {"private": who}, tenant_id=owner)
    yield clients, db, bus
    reset_event_bus()


def headers(client):
    return {"Cookie": "cryptoscan_session=" + client.cookies.get("cryptoscan_session")}


async def event(lines, kind):
    current = None

    async def find():
        nonlocal current
        async for line in lines:
            if line.startswith("event: "):
                current = line[7:]
            if line.startswith("data: ") and current == kind:
                return json.loads(line[6:])
        raise AssertionError("Stream ended before expected event " + kind)

    return await asyncio.wait_for(find(), 5)


@pytest.mark.asyncio
@pytest.mark.parametrize("middleware", [False, True])
@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
async def test_sse_exact_replay_live_prequeue_and_estate_watermark(streams, middleware, who):
    clients, _, bus = streams
    app = create_app()
    if middleware:
        app.add_middleware(TenantScopeMiddleware)
    owner = {"bank_a": "a", "bank_b": "b", "platform_admin": None}[who]
    async with ASGIStream(app, "/api/v1/events/stream", headers=headers(clients[who])) as stream:
        assert stream.status == 200
        lines = stream.lines()
        assert (await event(lines, "scan.own"))["payload"] == {"private": who}
        checkpoint = await event(lines, "events.checkpoint")
        assert checkpoint["latest_sequence"] == 1
        sub = bus._subs[-1]
        for _ in range(600):
            bus.publish("scan.foreign", {"secret": "b"}, tenant_id="z")
        assert sub.queue.empty() and sub.dropped == 0
        bus.publish("scan.live", {"private": "new"}, tenant_id=owner)
        assert (await event(lines, "scan.live"))["payload"] == {"private": "new"}
    assert bus.subscriber_count() == 0


@pytest.mark.parametrize("middleware", [False, True])
@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
def test_recent_and_stats_have_no_global_counts_and_no_foreign_starvation(streams, who, middleware):
    clients, _, bus = streams
    for _ in range(700):
        bus.publish("foreign", {"secret": "foreign"}, tenant_id="z")
    app = create_app()
    if middleware:
        app.add_middleware(TenantScopeMiddleware)
    with TestClient(app) as client:
        client.cookies.update(clients[who].cookies)
        recent = client.get("/api/v1/events/recent?limit=1")
        assert recent.status_code == 200, recent.text
        page = recent.json()
        assert [e["payload"] for e in page["events"]] == [{"private": who}]
        assert page["latest_sequence"] == 1 and page["oldest_sequence"] == 1
        stats = client.get("/api/v1/events/stats").json()
        assert stats["latest_sequence"] == 1 and stats["coverage"] == "RETAINED_ESTATE_SNAPSHOT"
        assert not {
            "latest_id",
            "oldest_replayable_id",
            "subscribers",
            "published_total",
            "remote_publish_failures",
            "tailer_running",
        }.intersection(stats)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["membership", "suspend", "session", "roles", "disabled", "deleted", "expired"])
async def test_open_sse_refuses_revoked_authority_before_next_payload(streams, change):
    clients, db, bus = streams
    app = create_app()
    async with ASGIStream(app, "/api/v1/events/stream", headers=headers(clients["bank_a"])) as stream:
        lines = stream.lines()
        await event(lines, "scan.own")
        await event(lines, "events.checkpoint")
        repo = UserRepository(db)
        if change == "membership":
            db.query(TenantMembership).filter_by(username="bank_a").delete()
        elif change == "suspend":
            db.get(Tenant, "a").status = "SUSPENDED"
        elif change in ("session", "expired"):
            session = repo.get_session(clients["bank_a"].cookies.get("cryptoscan_session"))
            if change == "session":
                session.revoked_at = datetime.now(timezone.utc)
            else:
                session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        else:
            user = repo.get_by_username("bank_a")
            if change == "roles":
                user.roles = "scanner"
            elif change == "disabled":
                user.is_active = False
            else:
                db.delete(user)
        db.commit()
        bus.publish("scan.secret", {"private": "after-revocation"}, tenant_id="a")
        refused = await event(lines, "events.refused")
        assert "reauthenticate" in refused["advice"]
    assert bus.subscriber_count() == 0


def test_cursor_bound_to_selected_estate_and_platform_selection(streams):
    clients, _, _ = streams
    cursor = clients["bank_a"].get("/api/v1/events/recent").json()["next_cursor"]
    assert clients["bank_b"].get("/api/v1/events/recent", params={"cursor": cursor}).status_code == 409
    selected = clients["platform_admin"].get("/api/v1/events/recent", headers={"X-Tenant-ID": "a"})
    assert selected.status_code == 200
    assert selected.json()["events"][0]["payload"] == {"private": "bank_a"}
    assert clients["bank_a"].get("/api/v1/events/recent", headers={"X-Tenant-ID": "b"}).status_code in (403, 404)


@pytest.mark.parametrize("fault", ["malformed", "numeric", "backend"])
def test_preheader_replay_failure_cleans_subscription(streams, fault, monkeypatch):
    clients, _, bus = streams
    params = {}
    if fault == "backend":

        def fail(*args):
            raise ConnectionError("secret backend endpoint")

        monkeypatch.setattr(bus, "estate_page", fail)
    else:
        params["last_event_id"] = "broken" if fault == "malformed" else "1"
    response = clients["bank_a"].get("/api/v1/events/stream", params=params)
    assert response.status_code == (503 if fault == "backend" else 409)
    assert "secret backend" not in response.text
    assert bus.subscriber_count() == 0


def mint_key(db, owner="a", **kwargs):
    row, raw = ApiKeyRepository(db).create(
        name="events-reader", created_by="operator", tenant_id=owner, roles=["auditor"], **kwargs
    )
    db.commit()
    return row, raw


@pytest.mark.parametrize("option", ["scope", "method", "ip", "role", "expired", "foreign", "null-key"])
def test_http_event_key_policy_is_not_weaker_than_socket(streams, option):
    clients, db, _ = streams
    row, raw = mint_key(db, owner=None if option == "null-key" else "a")
    if option == "scope":
        row.scopes = "/scans"
    if option == "method":
        row.allowed_methods = "POST"
    if option == "ip":
        row.allowed_ips = "192.0.2.0/24"
    if option == "role":
        row.roles = "scanner"
    if option == "expired":
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    extra = {"X-Tenant-ID": "b"} if option == "foreign" else ({"X-Tenant-ID": "a"} if option == "null-key" else {})
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/events/recent", headers={"X-API-Key": raw, **extra})
        assert response.status_code in (401, 403, 404), response.text


@pytest.mark.asyncio
async def test_sse_key_quota_once_and_policy_changes_disconnect(streams):
    _, db, bus = streams
    row, raw = mint_key(db, rate_per_minute=1)
    app = create_app()
    async with ASGIStream(app, "/api/v1/events/stream", headers={"X-API-Key": raw}) as stream:
        assert stream.status == 200
        lines = stream.lines()
        await event(lines, "scan.own")
        await event(lines, "events.checkpoint")
        bus.publish("scan.live", {}, tenant_id="a")
        await event(lines, "scan.live")
        await event(lines, "events.checkpoint")
        row.scopes = "/scans"
        db.commit()
        bus.publish("scan.secret", {}, tenant_id="a")
        await event(lines, "events.refused")
    assert bus.subscriber_count() == 0


def test_backend_failure_never_returns_local_fallback(streams):
    clients, _, bus = streams

    def fail(*args):
        raise ConnectionError("down")

    bus.set_estate_history(fail)
    for suffix in ("recent", "stats"):
        assert clients["bank_a"].get("/api/v1/events/" + suffix).status_code == 503


@pytest.mark.asyncio
async def test_cbom_sse_is_pinned_and_rechecks_membership_without_middleware(streams, monkeypatch, tmp_path):
    from api.routers import stream as router

    clients, db, _ = streams
    monkeypatch.setenv("STREAM_LOG_DIR", str(tmp_path / "streams"))
    monkeypatch.setenv("CBOM_STORE_DIR", str(tmp_path / "cboms"))
    router.reset_stream_singletons()
    app = create_app()
    with TestClient(app) as a, TestClient(app) as b:
        a.cookies.update(clients["bank_a"].cookies)
        b.cookies.update(clients["bank_b"].cookies)
        payload = {
            "kind": "tls_finding",
            "system": "same-system",
            "endpoint": "core.bank:443",
            "crypto": {"tls_version": "TLSv1.3"},
        }
        assert a.post("/api/v1/stream/ingest", json={"payload": payload}).status_code == 200
        assert a.get("/api/v1/cbom/live/same-system").status_code == 200
        assert b.get("/api/v1/cbom/live/same-system").status_code == 404
    async with asyncio.timeout(10):
        async with ASGIStream(app, "/api/v1/cbom/stream/same-system", headers=headers(clients["bank_a"])) as stream:
            assert stream.status == 200
            lines = stream.lines()
            assert await asyncio.wait_for(anext(lines), 5) == ": connected"
            db.query(TenantMembership).filter_by(username="bank_a").delete()
            db.commit()
            await event(lines, "events.refused")
    router.reset_stream_singletons()


@pytest.mark.parametrize("who", ["bank_a", "platform_admin"])
def test_mixed_source_posture_sse_refused_in_multi_estate_install(streams, who):
    clients, _, _ = streams
    assert clients[who].get("/api/v1/security/posture/stream").status_code in (403, 409)


@pytest.mark.asyncio
async def test_replay_live_handoff_and_queue_overflow_recover_from_journal(streams, monkeypatch):
    clients, _, bus = streams
    original = bus.estate_page
    first = True

    def racing_page(*args, **kwargs):
        nonlocal first
        page = original(*args, **kwargs)
        if first:
            first = False
            for n in range(280):
                bus.publish("scan.race", {"n": n}, tenant_id="a")
        return page

    monkeypatch.setattr(bus, "estate_page", racing_page)
    async with ASGIStream(create_app(), "/api/v1/events/stream", headers=headers(clients["bank_a"])) as stream:
        assert stream.status == 200
        lines = stream.lines()
        await event(lines, "scan.own")
        seen = [(await event(lines, "scan.race"))["payload"]["n"] for _ in range(280)]
        assert seen == list(range(280))
    assert bus.subscriber_count() == 0


@pytest.mark.asyncio
async def test_platform_telemetry_does_not_disclose_foreign_activity(streams, monkeypatch):
    from api.routers.events import publish_telemetry

    _, _, bus = streams
    for _ in range(250):
        bus.publish("foreign", {}, tenant_id="a")
    task = asyncio.create_task(publish_telemetry(0.02))
    try:
        await asyncio.sleep(0.06)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    page = bus.estate_page(None)
    telemetry = [e for e in page["events"] if e["type"] == "telemetry.snapshot"]
    assert telemetry
    for item in telemetry:
        assert item["payload"]["scope"] == "PLATFORM_ESTATE_ONLY"
        assert item["payload"]["latest_sequence"] < 10
        assert "subscribers" not in item["payload"] and "published_total" not in item["payload"]


@pytest.mark.asyncio
async def test_open_sse_auth_store_outage_is_unavailable_not_payload_or_success(streams, monkeypatch):
    clients, _, bus = streams
    async with ASGIStream(create_app(), "/api/v1/events/stream", headers=headers(clients["bank_a"])) as stream:
        lines = stream.lines()
        await event(lines, "scan.own")
        await event(lines, "events.checkpoint")

        def fail(*args):
            raise RuntimeError("private-auth-store-address")

        monkeypatch.setattr(UserRepository, "get_session", fail)
        bus.publish("scan.secret", {"secret": "must-not-send"}, tenant_id="a")
        body = await event(lines, "events.unavailable")
        assert "private-auth-store" not in str(body)
    assert bus.subscriber_count() == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["backend-failure", "revoked-during-read"])
async def test_cbom_sse_refuses_storage_failure_or_revocation_before_notification(streams, monkeypatch, fault):
    from api.routers import stream as router
    from db.connection.session import SessionLocal

    clients, _, _ = streams

    class Store:
        calls = 0

        def current(self, system):
            self.calls += 1
            if self.calls > 1:
                if fault == "backend-failure":
                    raise OSError("private-store-path")
                with SessionLocal() as session:
                    UserRepository(session).get_by_username("bank_a").is_active = False
                    session.commit()
            return {"version_no": self.calls, "version_hash": "must-not-notify-after-revocation"}

    store = Store()
    monkeypatch.setattr(router, "_cbom_service", lambda: store)
    async with ASGIStream(create_app(), "/api/v1/cbom/stream/system", headers=headers(clients["bank_a"])) as stream:
        assert stream.status == 200
        name = "events.unavailable" if fault == "backend-failure" else "events.refused"
        body = await event(stream.lines(), name)
        assert "private-store-path" not in str(body)
        assert "must-not-notify" not in str(body)


def test_cbom_sse_initial_storage_failure_is_explicit_503(streams, monkeypatch):
    from api.routers import stream as router

    clients, _, _ = streams

    class Store:
        def current(self, system):
            raise OSError("private-store-path")

    monkeypatch.setattr(router, "_cbom_service", Store)
    response = clients["bank_a"].get("/api/v1/cbom/stream/system")
    assert response.status_code == 503 and "private-store-path" not in response.text
