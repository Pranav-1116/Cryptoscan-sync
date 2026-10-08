"""Estate due-scan endpoints: preview (any user) + run (auditor+)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session, get_job_repository, require_auditor
from api.main import create_app
from api.routers.estate import require_auditor as estate_require_auditor
from db.connection.session import Base
from db.models.system import System


@pytest.fixture()
def app_due():
    from sqlalchemy.pool import StaticPool

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    # Bind the global SessionLocal to this test's engine: the scan-admission
    # seam (round 9) opens the global factory, and run-due passes through the
    # gate — without this the answer depended on whichever test file
    # configured the factory earlier in the process (unbound → 503).
    from db.connection.session import configure_session

    configure_session(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"
    application.dependency_overrides[require_auditor] = lambda: "testuser"
    application.dependency_overrides[estate_require_auditor] = lambda: "testuser"
    created: list[dict] = []

    def _create(**kwargs):
        created.append(kwargs)
        return SimpleNamespace(job_id=f"job-{len(created)}")

    # Bound under another name: a class body that assigns `session = session`
    # shadows the name before reading it, so the enclosing local is invisible
    # and the lookup raises NameError.
    _request_session = session

    class FakeRepo:
        # enqueue_scan_job commits through the repository's own session and
        # turns any failure into 503 ("no job was accepted"), so a double
        # without one reports the queue as down rather than exercising the
        # route. The real repository shares the request session, so this does
        # too.
        session = _request_session

        def create(self, **kwargs):
            return _create(**kwargs)

    application.dependency_overrides[get_job_repository] = lambda: FakeRepo()

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session

    now = datetime.now(timezone.utc)
    session.add_all(
        [
            System(id="sys-stale", name="stale-api", scan_target="https://git/bank/stale.git",
                   scan_branch="main", last_scanned_at=now - timedelta(days=30)),
            System(id="sys-fresh", name="fresh-api", scan_target="https://git/bank/fresh.git",
                   scan_branch="main", last_scanned_at=now - timedelta(days=1)),
            System(id="sys-cloud", name="aws-acct", scan_target="cloud://aws/111122223333",
                   cloud_provider="aws", last_scanned_at=now - timedelta(days=30)),
        ]
    )
    try:
        yield application, created
    finally:
        session.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_due_preview_lists_overdue_without_queueing(app_due):
    app, created = app_due
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/estate/scans/due", params={"interval_days": 7})
    assert response.status_code == 200
    body = response.json()
    assert body["dry_run"] is True
    assert body["due"] == 2 and body["fresh"] == 1
    assert {row["system_id"] for row in body["jobs"]} == {"sys-stale", "sys-cloud"}
    assert created == []  # preview never queues


@pytest.mark.asyncio
async def test_run_due_queues_jobs_as_scheduler(app_due):
    app, created = app_due
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/estate/scans/run-due", params={"interval_days": 7})
    assert response.status_code == 200
    body = response.json()
    assert body["queued"] == 2 and body["dry_run"] is False
    assert body["triggered_by"].startswith("scheduler:")
    assert {item["job_type"] for item in body["jobs"]} == {"SYSTEM", "CLOUD"}
    assert len(created) == 2
    assert all(job["triggered_by"].startswith("scheduler:") for job in created)
    assert body["message"].startswith("Queued 2 overdue re-scans")


@pytest.mark.asyncio
async def test_run_due_dry_run_queues_nothing(app_due):
    app, created = app_due
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/estate/scans/run-due", params={"dry_run": "true"})
    assert response.status_code == 200
    assert response.json()["queued"] == 0
    assert created == []
