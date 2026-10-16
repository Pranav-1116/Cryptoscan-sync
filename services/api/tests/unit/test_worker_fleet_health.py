"""The worker-fleet independent health probe (§5, round 78).

The console reported "Not measured" for the queue / worker pool because the
only available signal was API liveness — which is not evidence that anything
consumes the queues. GET /health/worker-fleet measures the real observed
state from the durable records: scan-job status counts, oldest queued age,
STUCK running jobs, the control-plane event queue (depth, stale leases,
dead letters), and the worker tier's monitor leader lease. Drain evidence
is completions in the last hour or a live lease — never API liveness — and
an idle fleet with no heartbeat reports Not measured, not Operational.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.control_plane import QueuedEvent
from db.models.scan_job import ScanJob

def _now() -> datetime:
    """The endpoint measures against the real wall clock — seeds must be
    relative to it, never a fixed timestamp (ages are the signal)."""
    return datetime.now(timezone.utc)



def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "fleet-health-" + "z" * 19)
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


def _job(status: str, *, created=None, updated=None, completed=None) -> ScanJob:
    return ScanJob(job_type="MANUAL", target_repo="r", status=status,
                   triggered_by="t", created_at=created, updated_at=updated,
                   completed_at=completed)


def _lease(session, *, expires_at, updated_at):
    session.execute(text(
        "CREATE TABLE IF NOT EXISTS monitor_leases ("
        "id VARCHAR(36) PRIMARY KEY, name VARCHAR(50) UNIQUE NOT NULL, holder VARCHAR(200), "
        "expires_at TIMESTAMP, created_at TIMESTAMP, updated_at TIMESTAMP)"))
    session.execute(text(
        "INSERT INTO monitor_leases (id, name, holder, expires_at, updated_at) "
        "VALUES ('l1', 'monitor', 'worker-1', :exp, :upd)"),
        {"exp": expires_at, "upd": updated_at})
    session.commit()


async def _get(app, path="/api/v1/health/worker-fleet"):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.get(path)


@pytest.mark.asyncio
async def test_empty_estate_is_honestly_not_measured():
    app, session, engine = _make_app()
    r = await _get(app)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "Not measured"
    assert "nothing to measure" in body["detail"]
    assert body["jobs"]["total"] == 0 and body["event_queue"]["total"] == 0
    assert body["worker_heartbeat"]["measured"] is False


@pytest.mark.asyncio
async def test_drain_evidence_and_live_lease_is_operational():
    app, session, engine = _make_app()
    # a completion within the hour (jobs) + one on the event queue
    session.add(_job("COMPLETED", created=_now() - timedelta(minutes=30),
                     updated=_now() - timedelta(minutes=25),
                     completed=_now() - timedelta(minutes=25)))
    session.add(QueuedEvent(event_type="siem.finding", payload={}, source="test",
                            status="completed", available_at=_now() - timedelta(minutes=40),
                            completed_at=_now() - timedelta(minutes=20)))
    session.add(_job("QUEUED", created=_now() - timedelta(minutes=2)))
    session.commit()
    _lease(session, expires_at=_now() + timedelta(seconds=60),
           updated_at=_now() - timedelta(seconds=5))

    r = await _get(app)
    body = r.json()
    assert body["status"] == "Operational"
    assert "drain observed" in body["detail"]
    assert body["drain_evidence"] == {"completions_last_hour": 2, "lease_live": True}
    assert body["jobs"]["by_status"] == {"COMPLETED": 1, "QUEUED": 1}
    assert body["jobs"]["oldest_queued_s"] is not None and body["jobs"]["oldest_queued_s"] < 300
    assert body["jobs"]["stuck_running"] == 0
    hb = body["worker_heartbeat"]
    assert hb["measured"] is True and hb["lease_live"] is True
    assert hb["holder"] == "worker-1"


@pytest.mark.asyncio
async def test_stuck_running_job_and_stale_lease_are_degraded():
    app, session, engine = _make_app()
    # RUNNING with no update for 40 min -> stuck (surfaced as stuck, not failed)
    session.add(_job("RUNNING", created=_now() - timedelta(minutes=45),
                     updated=_now() - timedelta(minutes=40)))
    # an event leased 30 min ago and never completed -> stale lease
    session.add(QueuedEvent(event_type="siem.finding", payload={}, source="test",
                            status="leased", leased_by="worker-9",
                            leased_at=_now() - timedelta(minutes=30),
                            available_at=_now() - timedelta(minutes=35)))
    session.commit()

    r = await _get(app)
    body = r.json()
    assert body["status"] == "Degraded"
    assert "1 running job(s) stuck" in body["detail"]
    assert "1 stale event lease(s)" in body["detail"]
    assert body["jobs"]["stuck_running"] == 1
    assert body["event_queue"]["stale_leases"] == 1


@pytest.mark.asyncio
async def test_backlog_without_drain_is_degraded():
    app, session, engine = _make_app()
    # work waiting 2h, nothing completed in the last hour, no lease source
    session.add(_job("QUEUED", created=_now() - timedelta(hours=2)))
    session.add(QueuedEvent(event_type="siem.finding", payload={}, source="test",
                            status="queued", available_at=_now() - timedelta(hours=1)))
    session.commit()

    r = await _get(app)
    body = r.json()
    assert body["status"] == "Degraded"
    assert "no drain observed" in body["detail"]
    assert body["jobs"]["oldest_queued_s"] >= 7200
    assert body["event_queue"]["oldest_queued_s"] >= 3600


@pytest.mark.asyncio
async def test_idle_fleet_without_heartbeat_is_not_measured():
    app, session, engine = _make_app()
    # everything completed long ago, nothing waiting, no live lease
    session.add(_job("COMPLETED", created=_now() - timedelta(hours=3),
                     updated=_now() - timedelta(hours=3),
                     completed=_now() - timedelta(hours=3)))
    session.commit()

    r = await _get(app)
    body = r.json()
    assert body["status"] == "Not measured"
    assert "idle" in body["detail"]
    assert body["drain_evidence"]["completions_last_hour"] == 0


@pytest.mark.asyncio
async def test_expired_lease_alone_is_not_drain_evidence():
    app, session, engine = _make_app()
    session.add(_job("QUEUED", created=_now() - timedelta(minutes=2)))
    session.commit()
    _lease(session, expires_at=_now() - timedelta(seconds=30),
           updated_at=_now() - timedelta(seconds=90))

    r = await _get(app)
    body = r.json()
    # work waiting (fresh, under the backlog threshold) + expired lease:
    # no drain evidence at all — the fleet is not measurable right now
    assert body["worker_heartbeat"]["lease_live"] is False
    assert body["drain_evidence"]["lease_live"] is False
    assert body["status"] == "Not measured"
