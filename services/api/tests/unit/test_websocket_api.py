"""The two sockets: live job progress and the platform event stream.

These tests drive a real ASGI socket through ``TestClient`` rather than calling
the handlers, because almost everything worth asserting here lives in the
handshake: who is refused, with which close code, and what the first frame says
about how the data actually arrives.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.websockets import WebSocketDisconnect

from api.main import create_app
from api.security.session_manager import SessionManager
from db.connection.session import Base, SessionLocal, configure_session
from db.repositories.api_key_repository import ApiKeyRepository
from db.repositories.job_repository import JobRepository
from db.repositories.user_repository import UserRepository


@pytest.fixture()
def ws_db(monkeypatch):
    """An in-memory database bound the way the socket reads it.

    ``/ws/binary/jobs/{id}`` reads through the app's own session factory (the
    socket is not a dependency-injected route), so the factory is pointed at this
    engine for the test — the same binding a worker process has.
    """
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    prior = SessionLocal.kw.get("bind")
    configure_session(engine)
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", "/tmp")
    try:
        yield session
    finally:
        session.close()
        if prior is not None:
            configure_session(prior)
        else:
            SessionLocal.configure(bind=None)


# Standalone NULL-owned job/event fixtures require platform identities. The
# tenant-isolation case below retains ordinary member identities/memberships.
def _session_token(session, username: str, roles: list[str]) -> str:
    UserRepository(session).create_user(username, "x", roles)
    token = SessionManager().create_session(username, roles=roles)
    UserRepository(session).create_session(token, username,
                                           datetime.now(timezone.utc) + timedelta(hours=1))
    session.commit()
    return token


def _recv(socket) -> dict:
    """The next frame, with the close handshake turned into a frame of its own.

    ``TestClient`` ends the session on close rather than raising, so the close
    code — the part of the protocol a client actually branches on — is read here.
    """
    message = socket.receive()
    if message.get("type") == "websocket.close":
        return {"type": "__close__", "code": message.get("code"), "reason": message.get("reason")}
    return json.loads(message.get("text") or "{}")


def _job(session, **progress):
    row = JobRepository(session).create(job_id="job-" + str(progress.get("n", 1)),
                                        job_type="BINARY", target_repo="/images/app.bin",
                                        triggered_by="tester", status="RUNNING")
    row.progress = progress.get("body") or {"current_stage": "binary_scan", "percent": 40,
                                            "scan_options": {"target": "/images/app.bin"}}
    session.commit()
    return row.id


# ------------------------------------------------------------- refusals ---- #

def test_a_socket_without_credentials_is_closed_1008(ws_db):
    client = TestClient(create_app())
    with pytest.raises(WebSocketDisconnect) as refused:
        with client.websocket_connect("/api/v1/ws/binary/jobs/whatever") as socket:
            socket.receive_text()
    assert refused.value.code == 1008
    assert "api key" in refused.value.reason.lower() or "session" in refused.value.reason.lower()


def test_an_unknown_api_key_is_refused_before_any_frame(ws_db):
    client = TestClient(create_app())
    with pytest.raises(WebSocketDisconnect) as refused:
        with client.websocket_connect("/api/v1/ws/events?api_key=csk_not-a-real-key-000000000"):
            pass
    assert refused.value.code == 1008


def test_a_query_token_can_authenticate_the_upgrade(ws_db):
    token = _session_token(ws_db, "watcher", ["superadmin"])
    client = TestClient(create_app())
    with client.websocket_connect(f"/api/v1/ws/events?token={token}") as socket:
        hello = json.loads(socket.receive_text())
    assert hello["type"] == "hello"
    assert hello["since"] == 0
    assert "in-process" in hello["note"]


def test_an_api_key_without_reader_roles_is_refused(ws_db):
    """A machine key for the scanner may *run* scans; watching the bus is a read.

    Key roles are explicit by design — unlike a legacy session with no roles, a
    key that lists none of the reader roles does not inherit the admin fallback.
    """
    repo = ApiKeyRepository(ws_db)
    _row, raw = repo.create(name="scanner-bot", created_by="admin", roles=["scanner"])
    ws_db.commit()
    client = TestClient(create_app())
    with pytest.raises(WebSocketDisconnect) as refused:
        with client.websocket_connect("/api/v1/ws/events", headers={"X-API-Key": raw}):
            pass
    assert refused.value.code == 1008
    assert "scanner" in refused.value.reason  # the reason names the roles it saw


# --------------------------------------------------------- job progress --- #

def test_an_unknown_job_says_so_and_closes_4404(ws_db):
    token = _session_token(ws_db, "auditor1", ["superadmin"])
    client = TestClient(create_app())
    with client.websocket_connect(f"/api/v1/ws/binary/jobs/nope?token={token}") as socket:
        hello = _recv(socket)
        error = _recv(socket)
        close = _recv(socket)
    assert hello["type"] == "hello"
    assert "poll" in hello["mechanism"]  # the socket says how its data arrives
    assert error["type"] == "error"
    assert "no job with that id" in error["message"]
    assert close["type"] == "__close__" and close["code"] == 4404  # "gone", not a generic 1000


def test_a_running_job_streams_a_snapshot_then_its_final_frame(ws_db):
    """The socket reports the row's own vocabulary, then closes on COMPLETED.

    The worker is a separate process, so the test plays the worker: it writes the
    same row the pipeline writes (status + progress payload) and the socket is
    expected to notice, frame it, and close.
    """
    token = _session_token(ws_db, "auditor2", ["superadmin"])
    job_id = _job(ws_db, n=2)
    client = TestClient(create_app())
    frames: list[dict] = []
    with client.websocket_connect(
            f"/api/v1/ws/binary/jobs/{job_id}?token={token}&interval=0.25") as socket:
        hello = _recv(socket)
        assert hello["type"] == "hello" and hello["poll_seconds"] == 0.25
        snapshot = _recv(socket)
        assert snapshot["type"] == "snapshot"
        assert snapshot["job_id"] == job_id
        assert snapshot["job"]["jobId"] == job_id
        assert snapshot["job"]["status"] == "RUNNING"
        assert snapshot["job"]["stage"] == "binary_scan"
        assert snapshot["job"]["percent"] == 40
        assert snapshot["job"]["terminal"] is False

        # the "worker" finishes the job
        JobRepository(ws_db).update_status(job_id, "COMPLETED", progress={
            "current_stage": "binary_ingest", "percent": 100, "stages_complete": 5,
            "total_stages": 5, "scan_options": {"target": "/images/app.bin"},
            "binary": {"artifact_id": "11111111-2222-3333-4444-555555555555",
                       "binaries_scanned": 1, "findings": 3, "yara_matches": 1}})
        ws_db.commit()

        while True:  # the socket keeps the connection until it goes terminal
            frame = _recv(socket)
            frames.append(frame)
            if frame["type"] == "final":
                frames.append(_recv(socket))  # the close handshake that follows it
                break
    update = next(frame for frame in frames if frame["type"] == "update")
    final = next(frame for frame in frames if frame["type"] == "final")
    close = frames[-1]
    assert close["type"] == "__close__" and close["code"] == 1000  # finished cleanly
    assert update["job"]["percent"] == 100
    assert final["job"]["terminal"] is True
    assert final["job"]["artifactId"] == "11111111-2222-3333-4444-555555555555"
    assert final["job"]["reportUrl"].startswith("/api/v1/devsecops/sbom/")
    assert final["job"]["stagesComplete"] == final["job"]["totalStages"] == 5


def test_the_poll_interval_is_clamped(ws_db):
    token = _session_token(ws_db, "auditor3", ["superadmin"])
    _job_id = _job(ws_db, n=3)
    client = TestClient(create_app())
    with client.websocket_connect(
            f"/api/v1/ws/binary/jobs/{_job_id}?token={token}&interval=999") as socket:
        hello = json.loads(socket.receive_text())
    assert hello["poll_seconds"] == 10.0  # clamped to the ceiling, announced as such


# ------------------------------------------------------- the event stream -- #

def _publish(count: int, topic: str = "scan.progress") -> None:
    from api.events.bus import get_event_bus

    for index in range(count):
        get_event_bus().publish(topic, {"i": index})


def test_the_event_socket_replays_then_streams(ws_db):
    from api.events.bus import reset_event_bus

    reset_event_bus()
    token = _session_token(ws_db, "streamer", ["superadmin"])
    _publish(2)
    client = TestClient(create_app())
    with client.websocket_connect(f"/api/v1/ws/events?token={token}") as socket:
        hello = json.loads(socket.receive_text())
        replay = [json.loads(socket.receive_text()) for _ in range(2)]
    assert hello["type"] == "hello" and hello["replayed"] == 2
    assert [frame["type"] for frame in replay] == ["event", "event"]
    assert [frame["event_type"] for frame in replay] == ["scan.progress", "scan.progress"]
    assert [frame["id"] for frame in replay] == [1, 2]
    assert replay[0]["payload"] == {"i": 0}


def test_topics_filter_by_prefix_and_since_resumes(ws_db):
    from api.events.bus import get_event_bus, reset_event_bus

    reset_event_bus()
    token = _session_token(ws_db, "streamer2", ["superadmin"])
    _publish(1, "scan.progress")
    marker = get_event_bus().latest_id()
    _publish(1, "binary.queued")
    _publish(1, "runtime.finding")
    client = TestClient(create_app())
    with client.websocket_connect(
            f"/api/v1/ws/events?token={token}&topics=binary.,runtime.&since={marker}") as socket:
        hello = json.loads(socket.receive_text())
        frames = [json.loads(socket.receive_text()) for _ in range(2)]
    assert hello["topics"] == ["binary.", "runtime."]
    assert hello["since"] == marker and hello["replayed"] == 2
    assert [frame["event_type"] for frame in frames] == ["binary.queued", "runtime.finding"]


def test_a_live_event_reaches_a_connected_socket(ws_db):
    from api.events.bus import reset_event_bus

    reset_event_bus()
    token = _session_token(ws_db, "streamer3", ["superadmin"])
    client = TestClient(create_app())
    with client.websocket_connect(f"/api/v1/ws/events?token={token}&topics=scan.") as socket:
        hello = json.loads(socket.receive_text())
        assert hello["type"] == "hello"
        _publish(1, "scan.queued")
        _publish(1, "binary.queued")  # filtered out: the socket only asked for scan.
        frame = json.loads(socket.receive_text())
    assert frame["type"] == "event"
    assert frame["event_type"] == "scan.queued"
    assert frame["id"] > 0
    assert frame["source"] == "api"


# --------------------------------------------------------- tenant scoping ---- #

def test_job_socket_reads_are_tenant_scoped(ws_db):
    """The socket used to open its own UNscoped session: any authenticated
    principal could watch any tenant's job by id. The tenant middleware now
    scopes the whole websocket (query-param credentials are routed into the
    same membership-validated resolution HTTP uses)."""
    from api.middleware.tenant_scope import TenantScopeMiddleware
    from db.models.scan_job import ScanJob
    from db.models.tenant import Tenant, TenantMembership

    ws_db.add_all([
        Tenant(id="t-a", name="Tenant A", slug="ta"),
        Tenant(id="t-b", name="Tenant B", slug="tb"),
    ])
    # _session_token creates the users; memberships bind them to tenants
    token_a = _session_token(ws_db, "user-a", ["viewer"])
    token_b = _session_token(ws_db, "user-b", ["viewer"])
    ws_db.add_all([
        TenantMembership(tenant_id="t-a", username="user-a", tenant_role="member"),
        TenantMembership(tenant_id="t-b", username="user-b", tenant_role="member"),
    ])
    job_a = ScanJob(id="job-acme-1", job_type="BINARY", target_repo="/images/a.bin",
                    target_branch="main", triggered_by="tester", status="RUNNING",
                    tenant_id="t-a",
                    progress={"current_stage": "binary_scan", "percent": 40})
    ws_db.add(job_a)
    ws_db.commit()

    app = create_app()
    app.add_middleware(TenantScopeMiddleware)
    client = TestClient(app)

    # the owning tenant's member sees the job: hello + snapshot frames
    with client.websocket_connect(
        f"/api/v1/ws/binary/jobs/job-acme-1?token={token_a}"
    ) as socket:
        hello = _recv(socket)
        assert hello["type"] == "hello"
        snapshot = _recv(socket)
        assert snapshot["type"] == "snapshot"
        assert snapshot.get("job_id") == "job-acme-1"

    # another tenant's member must NOT watch it: scoped read finds no such
    # job -> the socket's own honest not-found refusal, not a leak
    with client.websocket_connect(
        f"/api/v1/ws/binary/jobs/job-acme-1?token={token_b}"
    ) as socket:
        assert _recv(socket)["type"] == "hello"  # handshake frame, no data yet
        frame = _recv(socket)
        assert frame["type"] == "error"
        assert "no job with that id" in frame["message"]
        closed = _recv(socket)
        assert closed["type"] == "__close__"

    # and a query-param tenant the caller is NOT a member of is refused at
    # the handshake (1008), exactly like a forged X-Tenant-ID on HTTP
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            f"/api/v1/ws/binary/jobs/job-acme-1?token={token_b}&tenant=t-a"
        ) as socket:
            socket.receive_text()
