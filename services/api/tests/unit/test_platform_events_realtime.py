"""Realtime platform events: control-plane operations publish deterministic
events to the SSE bus AND persist them to the durable monitor_events log;
the stream seeds its backlog from the DB when the in-memory bus is empty
(e.g. right after an API restart)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.pool import StaticPool

from api.events.bus import reset_event_bus
from api.events.platform_events import (
    emit_platform_event,
    published_event_ids,
)
from api.main import create_app
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, SessionLocal, configure_session
from db.models.monitor import MonitorEvent, MonitorTarget
from db.repositories.monitor_repository import MonitorRepository
from db.repositories.user_repository import UserRepository


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    configure_session(engine)
    reset_event_bus()
    s = SessionLocal()
    yield s
    s.close()
    # detach the global bind so later tests are not left pointing at this
    # test's closed in-memory database
    SessionLocal.configure(bind=None)


def _mint_session(db, username: str, roles: list[str]) -> str:
    manager = SessionManager()
    token = manager.create_session(username, roles=roles)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    UserRepository(db).create_session(token, username, expires, ip="127.0.0.1")
    db.commit()
    return token


@pytest.fixture()
def admin_client(db):
    repo = UserRepository(db)
    repo.create_user("admin", hash_password("x"), ["admin"])
    db.commit()
    app = create_app()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", _mint_session(db, "admin", ["admin"]))
    return client


def test_platform_discover_publishes_event_and_persists(admin_client, db):
    resp = admin_client.post(
        "/api/v1/platform/discover",
        json={"domains": {"crypto": {}, "network": {}}},
    )
    assert resp.status_code == 200

    recent = admin_client.get("/api/v1/events/recent").json()
    kinds = [e["type"] for e in recent["events"]]
    assert any(t.startswith("platform.platform_discovery_completed") for t in kinds), kinds

    session = SessionLocal()
    try:
        count = session.execute(select(func.count()).select_from(MonitorEvent)).scalar()
        assert count and count >= 1
        row = session.execute(
            select(MonitorEvent).order_by(MonitorEvent.created_at.desc())
        ).scalars().first()
        assert row.event_type == "PLATFORM_DISCOVERY_COMPLETED"
        assert row.target_name == "platform"
        assert row.payload["asset_count"] == 0
    finally:
        session.close()


def test_emit_platform_event_persists_and_publishes(admin_client, db):
    event = emit_platform_event(
        "PLATFORM_DRIFT_EVALUATED",
        "drift detected (1 change)",
        {"drift_detected": True, "total_changes": 1},
    )
    assert event is not None
    assert event["source"] == "platform"
    assert event["type"] == "platform.platform_drift_evaluated"
    assert event["payload"]["row_id"] is not None  # durable row id travels with the event

    session = SessionLocal()
    try:
        repo = MonitorRepository(session)
        rows = repo.list_events(limit=10)
        assert any(r.event_type == "PLATFORM_DRIFT_EVALUATED" for r in rows)
        assert any(r.id == event["payload"]["row_id"] for r in rows)
    finally:
        session.close()

    # the row id is registered so the DB tailer never double-delivers
    assert event["payload"]["row_id"] in published_event_ids()


def test_recent_seeds_from_db_when_bus_empty(admin_client, db):
    session = SessionLocal()
    try:
        repo = MonitorRepository(session)
        repo.add_event(target=None, event_type="SCAN_OK", detail="seed row",
                       payload={"target": "seed"})
        session.commit()
    finally:
        session.close()

    body = admin_client.get("/api/v1/events/recent").json()
    assert body["events"], "DB backlog should seed an empty bus"
    assert body["events"][0]["source"] == "monitor"
    assert body["events"][0]["type"].startswith("monitor.")


def test_platform_drift_and_whatif_emit_events(admin_client, db):
    resp = admin_client.post(
        "/api/v1/platform/drift",
        json={
            "baseline": {"crypto": ["RSA-2048"]},
            "live": {"crypto": ["RSA-2048", "ML-KEM-768"]},
        },
    )
    assert resp.status_code == 200
    resp = admin_client.post(
        "/api/v1/platform/whatif",
        json={"current": "RSA-2048", "target": "ML-KEM-768"},
    )
    assert resp.status_code == 200

    kinds = [e["type"] for e in admin_client.get("/api/v1/events/recent").json()["events"]]
    assert any(t.startswith("platform.platform_drift_evaluated") for t in kinds), kinds
    assert any(t.startswith("platform.platform_whatif_analyzed") for t in kinds), kinds

    session = SessionLocal()
    try:
        types = set(session.execute(select(MonitorEvent.event_type)).scalars().all())
        assert {"PLATFORM_DRIFT_EVALUATED", "PLATFORM_WHATIF_ANALYZED"} <= types
    finally:
        session.close()


def test_monitor_events_endpoint_returns_the_platform_journal(admin_client, db):
    """Round 81: the journal was durable and still invisible to its own owner.

    ``GET /monitor/events`` answered ``{"events": []}`` against a database
    holding rows, because the repository scoped through the watch-list target
    join and a platform journal row has no target behind it. The remediation
    lifecycle — ``task_created`` through ``task_verified`` — was readable only
    through ``/events/recent`` and the SSE stream, so the operator surface that
    names itself after the journal did not carry it.
    """
    for event_type in ("remediation.task_created", "remediation.task_verified"):
        emitted = emit_platform_event(
            event_type, f"{event_type} for task t-1", {"task_id": "t-1"},
            target_name="remediation", session=db,
        )
        assert emitted is not None
    db.commit()

    # Both rows are on disk, and no watch-list target exists to hang them off —
    # the exact shape the old filter could not express.
    session = SessionLocal()
    try:
        assert session.execute(select(func.count()).select_from(MonitorEvent)).scalar() == 2
        assert session.execute(select(func.count()).select_from(MonitorTarget)).scalar() == 0
    finally:
        session.close()

    events = admin_client.get("/api/v1/monitor/events", params={"limit": 50}).json()["events"]
    assert [e["event_type"] for e in events] == [
        "remediation.task_verified", "remediation.task_created"]
    assert all(e["scope"] == "platform" for e in events)
    assert all(e["target_id"] is None and e["target_name"] == "remediation" for e in events)
    assert events[0]["payload"]["task_id"] == "t-1"


def test_bus_stats_expose_published_total(admin_client, db):
    emit_platform_event("PLATFORM_RISK_SCORED", "estate risk 58.2 (MEDIUM)",
                        {"score": 58.2, "level": "MEDIUM"})
    body = admin_client.get("/api/v1/events/stats").json()
    assert body["published_total"] >= 1
    assert body["events_buffered"] >= 1


def test_persist_platform_event_durable_only_and_dedup(admin_client, db):
    """persist_platform_event is the durable half: it writes the DB row and
    registers it as already-delivered (so the tailer won't double-deliver),
    but it does NOT itself publish to the in-process bus — the caller (the
    live-scan runner) does that with the exact SSE event type."""
    from api.events.bus import get_event_bus
    from api.events.platform_events import persist_platform_event

    bus = get_event_bus()
    before = bus.published_total()

    row_id = persist_platform_event(
        "live_scan.completed", "manual",
        {"ok": 2, "failed": 0, "elapsed_s": 1.1},
        target_name="live-scan",
    )
    assert row_id is not None
    # no extra in-process publish from the persist-only helper
    assert bus.published_total() == before

    session = SessionLocal()
    try:
        rows = MonitorRepository(session).list_events(limit=10)
        live = [r for r in rows if r.event_type == "live_scan.completed"]
        assert live and live[0].id == row_id
        assert live[0].target_name == "live-scan"
    finally:
        session.close()

    # marked delivered so the cross-worker tailer skips it on this process
    assert row_id in published_event_ids()
