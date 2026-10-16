"""The in-app notification feed (§5, round 76).

The routing matrix used to persist channel preferences nothing consumed,
and verification outcomes raised no notifications. The feed endpoint
makes the in-app routing LOAD-BEARING: monitor-journal events mapped to
a catalog class appear only while that class is routed to in-app, and
emitted types with no honest mapping are never force-fit.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.monitor import MonitorEvent

NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "notif-feed-" + "z" * 21)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "auditor"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed(session) -> None:
    session.add(MonitorEvent(
        event_type="remediation.task_verified", target_name="remediation",
        detail="Remediation task t-1 verification: VERIFIED",
        payload={"task_id": "t-1", "result": "VERIFIED"}, created_at=NOW))
    session.add(MonitorEvent(
        event_type="remediation.task_created", target_name="remediation",
        detail="Remediation task t-2 created for evidence ev-9",
        payload={"task_id": "t-2"}, created_at=NOW))
    session.add(MonitorEvent(
        event_type="evidence.chain_broken", target_name="evidence",
        detail="Scan s-1 chain verification FAILED at position 3",
        payload={"scan_id": "s-1"}, created_at=NOW))
    # emitted platform types with NO honest catalog mapping — must never
    # be force-fit into the feed
    session.add(MonitorEvent(
        event_type="graph.updated", target_name="graph",
        detail="Graph rebuilt", payload={}, created_at=NOW))
    session.add(MonitorEvent(
        event_type="digital_twin.snapshot", target_name="digital_twin",
        detail="Snapshot taken", payload={}, created_at=NOW))
    session.commit()


@pytest.mark.asyncio
async def test_feed_delivers_mapped_classes_routed_in_app():
    app, session, engine = _make_app()
    _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/notifications/feed")
        assert r.status_code == 200, r.text
        body = r.json()
        classes = [n["event_class"] for n in body["notifications"]]
        # verification outcome + task lifecycle + compliance failure all
        # deliver (default routing has inApp on for all three)
        assert set(classes) == {"remediation_verification", "remediation_task",
                                "compliance_failure"}
        # unmapped emitted types never appear
        details = " ".join(str(n["detail"]) for n in body["notifications"])
        assert "Graph rebuilt" not in details
        assert "Snapshot taken" not in details
        # the verification notification carries its class name + severity
        (ver,) = [n for n in body["notifications"]
                  if n["event_class"] == "remediation_verification"]
        assert ver["class_name"] == "Remediation verification outcome"
        assert ver["severity"] == "HIGH"
        assert "VERIFIED" in ver["detail"]
        # honest scope note — in-app is THIS feed; other channels are
        # integrations-side
        assert "in-app channel delivery" in body["note"]
        assert "remediation_verification" in body["routed_classes"]
    engine.dispose()


@pytest.mark.asyncio
async def test_routing_toggle_is_load_bearing():
    app, session, engine = _make_app()
    _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        # switch remediation_verification OFF for the in-app channel
        catalog = (await c.get("/api/v1/notifications/catalog")).json()["catalog"]
        routing = [
            {"id": e["id"], "name": e["name"], "severity": e["severity"],
             "channels": {**e["channels"],
                          **({"inApp": False} if e["id"] == "remediation_verification" else {})}}
            for e in catalog
        ]
        put = await c.put("/api/v1/notifications/routing", json={"routing": routing})
        assert put.status_code == 200, put.text

        r = await c.get("/api/v1/notifications/feed")
        body = r.json()
        classes = [n["event_class"] for n in body["notifications"]]
        # the toggle REMOVED verification outcomes from the feed
        assert "remediation_verification" not in classes
        assert "remediation_verification" not in body["routed_classes"]
        # the other mapped classes still deliver
        assert "remediation_task" in classes
        assert "compliance_failure" in classes

        # switching it back on restores delivery
        routing[0] = {**routing[0], "channels": {**routing[0]["channels"], "inApp": True}} \
            if routing[0]["id"] == "remediation_verification" else routing[0]
        for entry in routing:
            if entry["id"] == "remediation_verification":
                entry["channels"]["inApp"] = True
        await c.put("/api/v1/notifications/routing", json={"routing": routing})
        again = (await c.get("/api/v1/notifications/feed")).json()
        assert "remediation_verification" in [n["event_class"] for n in again["notifications"]]
    engine.dispose()


@pytest.mark.asyncio
async def test_feed_empty_is_honest_and_limit_binds():
    app, session, engine = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        empty = await c.get("/api/v1/notifications/feed")
        assert empty.status_code == 200
        assert empty.json()["notifications"] == []
        assert empty.json()["count"] == 0
        # the note still explains what the feed is
        assert "in-app channel delivery" in empty.json()["note"]
    engine.dispose()

    _app2, session2, engine2 = _make_app()
    for i in range(8):
        session2.add(MonitorEvent(
            event_type="remediation.task_verified", target_name="remediation",
            detail=f"task t-{i} verification: VERIFIED", payload={},
            created_at=NOW))
    session2.commit()
    async with AsyncClient(transport=ASGITransport(app=_app2), base_url="http://t") as c:
        limited = await c.get("/api/v1/notifications/feed", params={"limit": 3})
        assert limited.json()["count"] == 3
    engine2.dispose()
