"""Authenticated WebSocket estate boundaries and between-frame revocation."""

import json

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from db.models.scan_job import ScanJob
from db.models.tenant import Tenant, TenantMembership
from db.repositories.api_key_repository import ApiKeyRepository
from test_software_supply_chain_api import banks as banks


def receive(socket):
    message = socket.receive()
    if message.get("text") and json.loads(message["text"]).get("type") == "checkpoint":
        return receive(socket)
    if message["type"] == "websocket.close":
        return {"type": "close", "code": message["code"]}
    return json.loads(message["text"])


@pytest.fixture
def sockets(banks, monkeypatch):
    from api.events.bus import reset_event_bus

    clients, db, _ = banks
    bus = reset_event_bus()
    monkeypatch.setattr("api.routers.ws.AUTH_RECHECK_SECONDS", 0.05, raising=False)
    monkeypatch.setattr("api.routers.ws.PING_SECONDS", 0.05)
    rows = {}
    for who, owner in [("bank_a", "a"), ("bank_b", "b"), ("platform_admin", None)]:
        row = ScanJob(
            tenant_id=owner,
            job_type="BINARY",
            target_repo=f"private-{who}",
            triggered_by=who,
            status="COMPLETED",
            progress={"current_stage": "secret-" + who},
        )
        db.add(row)
        rows[who] = row
        bus.publish("scan.progress", {"private": who}, tenant_id=owner)
    db.commit()
    yield clients, db, bus, rows
    reset_event_bus()


@pytest.mark.parametrize("middleware", [False, True])
@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
def test_only_selected_estate_job_has_snapshot(sockets, middleware, who):
    from api.main import create_app
    from api.middleware.tenant_scope import TenantScopeMiddleware

    clients, _, _, rows = sockets
    app = create_app()
    if middleware:
        app.add_middleware(TenantScopeMiddleware)
    with TestClient(app) as client:
        client.cookies.update(clients[who].cookies)
        for owner, row in rows.items():
            with client.websocket_connect(f"/api/v1/ws/binary/jobs/{row.id}") as socket:
                assert receive(socket)["type"] == "hello"
                frame = receive(socket)
                if owner == who:
                    assert frame["type"] == "snapshot" and frame["job"]["target"] == f"private-{who}"
                else:
                    assert frame["type"] == "error" and "private-" not in str(frame)
                    assert receive(socket) == {"type": "close", "code": 4404}


@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
def test_event_replay_live_topic_queue_and_watermarks_are_private(sockets, who):
    clients, _, bus, _ = sockets
    owner = {"bank_a": "a", "bank_b": "b", "platform_admin": None}[who]
    with clients[who].websocket_connect("/api/v1/ws/events?topics=scan.") as socket:
        hello = receive(socket)
        assert hello["replayed"] == 1
        frame = receive(socket)
        assert frame["payload"] == {"private": who}
        assert hello["latest_id"] == frame["id"]
        subscription = bus._subs[-1]
        for foreign in ("a", "b", None):
            if foreign != owner:
                bus.publish("scan.progress", {"secret": "foreign"}, tenant_id=foreign)
        bus.publish("runtime.other", {"private": who}, tenant_id=owner)
        bus.publish("scan.live", {"private": "live"}, tenant_id=owner)
        live = receive(socket)
        assert live["type"] == "event" and live["payload"] == {"private": "live"}
        assert subscription.dropped == 0
    assert bus.subscriber_count() == 0


@pytest.mark.parametrize("change", ["membership", "suspend", "session", "roles"])
@pytest.mark.parametrize("kind", ["job", "events"])
def test_existing_socket_stops_after_authority_change(sockets, change, kind):
    from db.models.user import UserSession
    from db.repositories.user_repository import UserRepository

    clients, db, bus, rows = sockets
    row = rows["bank_a"]
    row.status = "RUNNING"
    db.commit()
    url = f"/api/v1/ws/binary/jobs/{row.id}?interval=0.25" if kind == "job" else "/api/v1/ws/events"
    with clients["bank_a"].websocket_connect(url) as socket:
        assert receive(socket)["type"] == "hello"
        assert receive(socket)["type"] in ("snapshot", "event")
        if change == "membership":
            db.query(TenantMembership).filter_by(username="bank_a").delete()
        elif change == "suspend":
            db.get(Tenant, "a").status = "SUSPENDED"
        elif change == "session":
            db.query(UserSession).filter_by(username="bank_a").delete()
        else:
            UserRepository(db).get_by_username("bank_a").roles = "scanner"
        db.commit()
        if kind == "events":
            bus.publish("scan.live", {"secret": "must-not-send"}, tenant_id="a")
        frame = receive(socket)
        # A previously authorized heartbeat may already be queued; no new data.
        while frame["type"] == "ping":
            frame = receive(socket)
        assert frame == {"type": "close", "code": 1008}
    assert bus.subscriber_count() == 0


@pytest.mark.parametrize("kind", ["job", "events"])
def test_forged_selection_is_refused_without_middleware(sockets, kind):
    from api.main import create_app

    clients, _, _, rows = sockets
    with TestClient(create_app()) as client:
        client.cookies.update(clients["bank_b"].cookies)
        path = f"/api/v1/ws/binary/jobs/{rows['bank_a'].id}" if kind == "job" else "/api/v1/ws/events"
        with pytest.raises(WebSocketDisconnect) as error:
            with client.websocket_connect(path + "?tenant=a"):
                pass
        assert error.value.code == 1008


def key(db, owner="a", **options):
    row, raw = ApiKeyRepository(db).create(
        name="reader-key", created_by="operator", tenant_id=owner, roles=["auditor"], **options
    )
    db.commit()
    return row, raw


@pytest.mark.parametrize(
    "policy", [{"scopes": ["/findings"]}, {"allowed_methods": ["POST"]}, {"allowed_ips": ["10.0.0.0/8"]}]
)
def test_machine_key_restrictions_apply_to_upgrade(sockets, policy):
    clients, db, _, _ = sockets
    _, raw = key(db, **policy)
    with pytest.raises(WebSocketDisconnect) as error:
        with clients["bank_a"].websocket_connect(f"/api/v1/ws/events?api_key={raw}"):
            pass
    assert error.value.code == 1008


def test_key_bound_estate_revocation_and_one_quota_charge_per_connection(sockets):
    from db.models.api_key_quota_window import ApiKeyQuotaWindow

    clients, db, bus, _ = sockets
    row, raw = key(db, rate_per_minute=1, scopes=["/ws/events"], allowed_methods=["GET"])
    with clients["bank_b"].websocket_connect(f"/api/v1/ws/events?api_key={raw}") as socket:
        assert receive(socket)["replayed"] == 1
        assert receive(socket)["payload"] == {"private": "bank_a"}
        bus.publish("scan.live", {"private": "a"}, tenant_id="a")
        assert receive(socket)["type"] == "event"
        assert db.query(ApiKeyQuotaWindow).one().hit_count == 1
        ApiKeyRepository(db).revoke(row.id)
        db.commit()
        bus.publish("scan.live", {"secret": "revoked"}, tenant_id="a")
        frame = receive(socket)
        while frame["type"] == "ping":
            frame = receive(socket)
        assert frame == {"type": "close", "code": 1008}


def test_conflicting_event_owner_metadata_cannot_promote_payload_tenant(sockets):
    clients, _, bus, _ = sockets
    from api.security.socket_history import visible_event

    assert not visible_event({"tenant_id": None, "payload": {"tenant_id": "a"}}, "a")
    assert not visible_event({"tenant_id": "a", "payload": {"tenant_id": "b"}}, "a")
    with clients["bank_a"].websocket_connect("/api/v1/ws/events") as socket:
        assert receive(socket)["replayed"] == 1
        assert receive(socket)["payload"] == {"private": "bank_a"}


def test_explicit_platform_selection_does_not_widen_next_socket(sockets):
    clients, _, _, rows = sockets
    client = clients["platform_admin"]
    with client.websocket_connect(f"/api/v1/ws/binary/jobs/{rows['bank_a'].id}?tenant=a") as socket:
        assert receive(socket)["type"] == "hello"
        assert receive(socket)["type"] == "snapshot"
    with client.websocket_connect(f"/api/v1/ws/binary/jobs/{rows['bank_a'].id}") as socket:
        assert receive(socket)["type"] == "hello"
        assert receive(socket)["type"] == "error"


@pytest.mark.parametrize("change", ["scope", "method", "ip", "roles", "expiry", "suspend"])
@pytest.mark.parametrize("kind", ["job", "events"])
def test_machine_key_policy_and_authority_are_rechecked(sockets, change, kind):
    from datetime import datetime, timedelta, timezone

    clients, db, bus, rows = sockets
    row, raw = key(db)
    rows["bank_a"].status = "RUNNING"
    db.commit()
    path = f"/api/v1/ws/binary/jobs/{rows['bank_a'].id}?interval=0.25&" if kind == "job" else "/api/v1/ws/events?"
    with clients["bank_b"].websocket_connect(path + "api_key=" + raw) as socket:
        assert receive(socket)["type"] == "hello"
        assert receive(socket)["type"] in ("snapshot", "event")
        if change == "scope":
            row.scopes = "/findings"
        elif change == "method":
            row.allowed_methods = "POST"
        elif change == "ip":
            row.allowed_ips = "10.0.0.0/8"
        elif change == "roles":
            row.roles = "scanner"
        elif change == "expiry":
            row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        else:
            db.get(Tenant, "a").status = "SUSPENDED"
        db.commit()
        if kind == "events":
            bus.publish("scan.live", {"secret": "changed-policy"}, tenant_id="a")
        frame = receive(socket)
        while frame["type"] == "ping":
            frame = receive(socket)
        assert frame == {"type": "close", "code": 1008}


@pytest.mark.parametrize("kind", ["job", "events"])
@pytest.mark.parametrize("stage", ["upgrade", "connected"])
def test_session_store_outage_closes_without_private_diagnostics(sockets, monkeypatch, kind, stage):
    from api.main import create_app
    from db.repositories.user_repository import UserRepository

    clients, db, _, rows = sockets
    rows["bank_a"].status = "RUNNING"
    db.commit()

    def fail(*args):
        raise RuntimeError("private-database-secret")

    path = f"/api/v1/ws/binary/jobs/{rows['bank_a'].id}?interval=0.25" if kind == "job" else "/api/v1/ws/events"
    with TestClient(create_app()) as client:
        client.cookies.update(clients["bank_a"].cookies)
        if stage == "upgrade":
            monkeypatch.setattr(UserRepository, "get_session", fail)
            with pytest.raises(WebSocketDisconnect) as refused:
                with client.websocket_connect(path):
                    pass
            assert refused.value.code == 1011 and "private-database" not in refused.value.reason
        else:
            with client.websocket_connect(path) as socket:
                assert receive(socket)["type"] == "hello"
                assert receive(socket)["type"] in ("snapshot", "event")
                monkeypatch.setattr(UserRepository, "get_session", fail)
                frame = receive(socket)
                while frame["type"] == "ping":
                    frame = receive(socket)
                assert frame == {"type": "close", "code": 1011}


def test_foreign_burst_never_queues_or_increments_drop_warning(sockets):
    clients, _, bus, _ = sockets
    with clients["bank_a"].websocket_connect("/api/v1/ws/events?topics=scan.") as socket:
        assert receive(socket)["replayed"] == 1
        baseline = receive(socket)["id"]
        subscription = bus._subs[-1]
        for _ in range(1000):
            bus.publish("scan.foreign", {"secret": "bank-b"}, tenant_id="b")
        assert subscription.queue.empty() and subscription.dropped == 0
        frame = receive(socket)
        assert frame == {"type": "ping", "latest_id": baseline}


def test_upgrade_rate_limit_is_not_a_per_frame_charge(sockets):
    clients, db, _, _ = sockets
    _, raw = key(db, rate_per_minute=1)
    path = "/api/v1/ws/events?api_key=" + raw
    with clients["bank_a"].websocket_connect(path) as socket:
        assert receive(socket)["type"] == "hello"
        assert receive(socket)["type"] == "event"
        with pytest.raises(WebSocketDisconnect) as refused:
            with clients["bank_a"].websocket_connect(path):
                pass
        assert refused.value.code == 1008


def test_replay_failure_closes_and_unsubscribes(sockets, monkeypatch):
    clients, _, bus, _ = sockets

    def fail(*args, **kwargs):
        raise RuntimeError("private-durable-backend")

    monkeypatch.setattr(bus, "estate_page", fail)
    with clients["bank_a"].websocket_connect("/api/v1/ws/events") as socket:
        assert receive(socket) == {"type": "close", "code": 1011}
    assert bus.subscriber_count() == 0


@pytest.mark.parametrize("fault", ["deleted", "disabled", "roleless"])
def test_missing_or_disabled_identity_never_becomes_platform_admin(sockets, fault):
    from api.main import create_app
    from db.repositories.user_repository import UserRepository

    clients, db, _, _ = sockets
    user = UserRepository(db).get_by_username("bank_a")
    if fault == "deleted":
        db.delete(user)
    elif fault == "disabled":
        user.is_active = False
    else:
        user.roles = ""
    db.commit()
    with TestClient(create_app()) as client:
        client.cookies.update(clients["bank_a"].cookies)
        with pytest.raises(WebSocketDisconnect) as refused:
            with client.websocket_connect("/api/v1/ws/events"):
                pass
        assert refused.value.code == 1008


@pytest.mark.parametrize("middleware", [False, True])
def test_explicit_bearer_wins_query_and_cookie_consistently(sockets, middleware):
    from api.main import create_app
    from api.middleware.tenant_scope import TenantScopeMiddleware

    clients, _, _, rows = sockets
    app = create_app()
    if middleware:
        app.add_middleware(TenantScopeMiddleware)
    token_b = clients["bank_b"].cookies.get("cryptoscan_session")
    token_a = clients["bank_a"].cookies.get("cryptoscan_session")
    with TestClient(app) as client:
        client.cookies.update(clients["bank_a"].cookies)
        with client.websocket_connect(
            f"/api/v1/ws/binary/jobs/{rows['bank_b'].id}?token={token_a}",
            headers={"Authorization": "Bearer " + token_b},
        ) as socket:
            assert receive(socket)["type"] == "hello"
            assert receive(socket)["job"]["target"] == "private-bank_b"


def test_platform_machine_key_cannot_select_a_bank(sockets):
    clients, db, _, _ = sockets
    _, raw = key(db, owner=None)
    with pytest.raises(WebSocketDisconnect) as refused:
        with clients["bank_a"].websocket_connect(f"/api/v1/ws/events?api_key={raw}&tenant=a"):
            pass
    assert refused.value.code == 1008


def test_socket_replays_all_retained_estate_pages_despite_foreign_burst(sockets):
    clients, _, bus, _ = sockets
    for n in range(350):
        bus.publish("scan.large", {"n": n}, tenant_id="a")
    for n in range(700):
        bus.publish("scan.foreign", {"secret": n}, tenant_id="b")
    with clients["bank_a"].websocket_connect("/api/v1/ws/events?topics=scan.large") as socket:
        assert receive(socket)["type"] == "hello"
        events = [receive(socket) for _ in range(350)]
        assert [e["payload"]["n"] for e in events] == list(range(350))
        cursor = events[-1]["replay_cursor"]
    with clients["bank_a"].websocket_connect("/api/v1/ws/events?cursor=" + cursor) as socket:
        assert receive(socket)["replayed"] == 0
        bus.publish("scan.new", {"new": True}, tenant_id="a")
        frame = receive(socket)
        while frame["type"] == "ping":
            frame = receive(socket)
        assert frame["payload"] == {"new": True}
    assert bus.subscriber_count() == 0


def test_socket_foreign_replay_cursor_is_not_an_access_grant(sockets):
    clients, _, bus, _ = sockets
    cursor = bus.estate_page("b")["next_cursor"]
    with clients["bank_a"].websocket_connect("/api/v1/ws/events?cursor=" + cursor) as socket:
        assert receive(socket) == {"type": "close", "code": 1008}
    assert bus.subscriber_count() == 0
