"""Round 23 (report 31 §5/§6 + §2.9, 88 GAP-011): drift SLA metrics with
honest ack timestamps, and clean-scan baseline proposals that never
self-activate."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.baseline import Baseline
from db.models.drift_event import DriftEvent
from db.models.scan import Scan
from db.models.user import User

SECRET = "r23-sla-secret-" + "w" * 21
NOW = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine, expire_on_commit=False)
    s = TestSession()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()


def _drift(session, *, severity, detected, acked=None, resolved=None, status="OPEN"):
    row = DriftEvent(
        current_scan_id="scan-x",
        detected_at=detected,
        drift_type="ALGORITHM_ADDED",
        severity=severity,
        resolution_status=status,
    )
    if acked is not None:
        row.acknowledged_at = acked
        row.acknowledged_by = "auditor"
    if resolved is not None:
        row.resolved_at = resolved
        row.resolved_by = "auditor"
    session.add(row)
    return row


# --------------------------------------------------------------------- #
# Repository: acknowledge ≠ resolve
# --------------------------------------------------------------------- #

def test_acknowledge_stamps_ack_not_resolve(session):
    from db.repositories.drift_repository import DriftRepository

    created = _drift(session, severity="HIGH", detected=NOW - timedelta(hours=3))
    session.commit()
    drift_id = created.id
    repo = DriftRepository(session)
    row = repo.acknowledge(drift_id, "alice", notes="looking into it")
    assert row is not None and row.acknowledged_at is not None
    assert row.acknowledged_by == "alice"
    assert row.resolution_status == "ACKNOWLEDGED"
    assert row.resolved_at is None  # ack is not resolution
    assert "looking into it" in (row.resolution_notes or "")

    # resolving afterwards keeps the ack stamp
    row = repo.resolve(drift_id, "bob")
    assert row.resolution_status == "RESOLVED"
    assert row.resolved_at is not None
    assert row.acknowledged_at is not None


def test_sla_summary_math_and_honesty(session):
    from db.repositories.drift_repository import DriftRepository

    # CRITICAL acked in 30min (within 1h target), resolved in 10h (within 24h)
    _drift(session, severity="CRITICAL",
           detected=NOW - timedelta(hours=10),
           acked=NOW - timedelta(hours=9.5),
           resolved=NOW - timedelta(hours=0), status="RESOLVED")
    # HIGH acked after 6h (breaches the 4h target), still open -> resolve breach
    _drift(session, severity="HIGH",
           detected=NOW - timedelta(hours=30),
           acked=NOW - timedelta(hours=24))
    # MEDIUM open for 40 days -> resolve breach (30d target)
    _drift(session, severity="MEDIUM", detected=NOW - timedelta(days=40))
    # historical: ACKNOWLEDGED before the column existed (no ack stamp)
    _drift(session, severity="LOW", detected=NOW - timedelta(days=5),
           status="ACKNOWLEDGED")
    session.commit()

    summary = DriftRepository(session).sla_summary(now=NOW)
    assert summary["events_considered"] == 4
    assert summary["truncated"] is False
    # MTTA over the two events with ack stamps: 0.5h and 6h
    assert summary["mtta_hours"] == pytest.approx(3.25, abs=0.01)
    # MTTR over the single resolved event: 10h
    assert summary["mttr_hours"] == pytest.approx(10.0, abs=0.01)
    # the historical ack is counted as unknown, never imputed
    assert summary["acknowledge_time_unknown"] == 1

    critical = summary["per_severity"]["CRITICAL"]
    assert critical["sla"]["acknowledge_breaches"] == 0
    assert critical["sla"]["resolve_breaches"] == 0
    high = summary["per_severity"]["HIGH"]
    assert high["sla"]["acknowledge_breaches"] == 1   # acked at 6h > 4h target
    assert high["sla"]["resolve_breaches"] == 0       # open 30h < 7d window
    medium = summary["per_severity"]["MEDIUM"]
    assert medium["open"] == 1
    assert medium["oldest_open_hours"] == pytest.approx(960.0, abs=1.0)
    assert medium["sla"]["resolve_breaches"] == 1  # 40 days > 30-day window


# --------------------------------------------------------------------- #
# API surface
# --------------------------------------------------------------------- #

@pytest.fixture()
def app_db(monkeypatch):
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", SECRET)
    get_settings.cache_clear()
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine, expire_on_commit=False)
    with TestSession() as db:
        db.add(User(username="aud", roles="auditor", password_hash="x"))
        db.add(
            Scan(id="scan-clean", scan_start=NOW, target_location="https://x/repo.git",
                 target_type="GIT_REPOSITORY", status="COMPLETED")
        )
        db.commit()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "aud"
    app.dependency_overrides[require_auditor] = lambda: "aud"
    app.dependency_overrides[get_db_session] = lambda: (yield TestSession())
    return app, TestSession


@pytest.mark.asyncio
async def test_drift_sla_endpoint(app_db):
    app, TestSession = app_db
    real_now = datetime.now(timezone.utc)
    with TestSession() as db:
        # seeded relative to wall-clock now — the endpoint computes against it
        _drift(db, severity="CRITICAL", detected=real_now - timedelta(hours=2))
        db.commit()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/drift/sla")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["per_severity"]["CRITICAL"]["open"] == 1
    # open for 2h with no ack -> the 1h acknowledge target is breached
    assert body["per_severity"]["CRITICAL"]["sla"]["acknowledge_breaches"] == 1
    assert "never imputed" in body["targets_note"] or "report 31" in body["targets_note"]


@pytest.mark.asyncio
async def test_acknowledge_endpoint_returns_ack_fields(app_db):
    app, TestSession = app_db
    with TestSession() as db:
        row = _drift(db, severity="HIGH", detected=NOW - timedelta(hours=1))
        db.commit()
        drift_id = row.id
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            f"/api/v1/drift/{drift_id}/acknowledge", json={"notes": "on it"}
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["acknowledged_at"] is not None
    assert body["acknowledged_by"] == "aud"
    assert body["resolution_status"] == "ACKNOWLEDGED"


@pytest.mark.asyncio
async def test_baseline_proposal_lifecycle(app_db):
    app, TestSession = app_db
    with TestSession() as db:
        db.add(
            Baseline(
                system_identifier="https://x/repo.git",
                environment="default",
                approved_scan_id="scan-clean",
                approved_by="system:clean-scan-proposal",
                approved_at=NOW,
                status="PROPOSED",
                notes="auto",
            )
        )
        db.commit()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # auditor sees the proposal
        resp = await client.get("/api/v1/baselines/proposed")
        assert resp.status_code == 200
        proposals = resp.json()
        assert len(proposals) == 1
        assert proposals[0]["proposed_by"] == "system:clean-scan-proposal"
        baseline_id = proposals[0]["baseline_id"]

        # a proposal is not active: drift detection ignores it
        resp = await client.get("/api/v1/baselines")
        statuses = {b["baseline_id"]: b["status"] for b in resp.json()}
        assert statuses[baseline_id] == "PROPOSED"

        # approving activates it
        resp = await client.post(
            f"/api/v1/baselines/{baseline_id}/approve-proposed", json={"notes": "ok"}
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "ACTIVE"

        # it cannot be approved twice
        resp = await client.post(
            f"/api/v1/baselines/{baseline_id}/approve-proposed"
        )
        assert resp.status_code == 404
