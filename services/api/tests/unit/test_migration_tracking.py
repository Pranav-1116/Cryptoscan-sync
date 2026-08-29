"""Migration tracking (W53-54): tasks, auto-creation, progress, forecast, sync."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "planner"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed_scan(session, scan_id="scan-mig", findings=None):
    findings = findings if findings is not None else [
        ("DES", "ENCRYPTION", "FAIL", "src/Old.java", 11),
        ("MD5", "HASHING", "FAIL", "src/Hash.java", 22),
        ("AES-256-GCM", "ENCRYPTION", "PASS", "src/New.java", 33),
    ]
    session.add(
        Scan(id=scan_id, scan_start=datetime(2026, 8, 29, tzinfo=timezone.utc),
             target_location="https://github.com/org/payments.git", target_type="GIT_REPOSITORY",
             status="COMPLETED", statistics={})
    )
    for index, (algo, purpose, status, path, line) in enumerate(findings):
        session.add(
            EvidenceRecord(
                scan_id=scan_id, content_hash=f"{index}" * 64, chain_hash=f"{index}" + "0" * 63,
                chain_position=index, previous_hash=None, algorithm=algo, confidence="HIGH",
                purpose=purpose, mode=None, key_size=None, file_path=path, line_number=line,
                finding_data={"scanner_id": "s"}, compliance_status=status,
            )
        )
    session.flush()


@pytest.mark.asyncio
async def test_auto_project_from_scan_creates_prioritized_tasks():
    app, session, engine = _make_app()
    _seed_scan(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = (await client.post("/api/v1/migrations/from-scan", json={"scan_id": "scan-mig"})).json()
        assert created["tasks_created"] == 2  # DES + MD5 fail; AES-256-GCM passes
        assert created["by_priority"]["P0"] >= 1
        project_id = created["project"]["id"]
        assert "payments.git" in created["project"]["name"]

        tasks = (await client.get(f"/api/v1/migrations/{project_id}/tasks")).json()["tasks"]
        assert len(tasks) == 2
        assert all(task["source"] == "AUTO" for task in tasks)
        assert any("DES" in task["title"] and "AES" in task["algorithm_to"] for task in tasks)
        # evidence linkage preserved for traceability
        assert all(task["evidence_id"] for task in tasks)

        missing = await client.post("/api/v1/migrations/from-scan", json={"scan_id": "nope"})
        assert missing.status_code == 404


@pytest.mark.asyncio
async def test_progress_recomputed_from_tasks():
    app, session, engine = _make_app()
    _seed_scan(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = (await client.post("/api/v1/migrations/from-scan", json={"scan_id": "scan-mig"})).json()
        project_id = created["project"]["id"]
        tasks = (await client.get(f"/api/v1/migrations/{project_id}/tasks")).json()["tasks"]

        first = (await client.patch(f"/api/v1/migrations/tasks/{tasks[0]['id']}", json={"status": "DONE"})).json()
        assert first["status"] == "DONE" and first["completed_at"]

        progress = (await client.get(f"/api/v1/migrations/{project_id}/progress")).json()
        assert progress["tasks_total"] == 2 and progress["tasks_done"] == 1
        assert progress["task_progress_pct"] == 50.0

        listing = (await client.get("/api/v1/migrations")).json()["projects"]
        mine = next(row for row in listing if row["id"] == project_id)
        assert mine["progress"] == 50.0  # derived automatically, not hand-set
        assert mine["status"] == "IN_PROGRESS"

        skipped = (await client.patch(f"/api/v1/migrations/tasks/{tasks[1]['id']}", json={"status": "SKIPPED"})).json()
        assert skipped["status"] == "SKIPPED"
        final = (await client.get(f"/api/v1/migrations/{project_id}/progress")).json()
        assert final["task_progress_pct"] == 100.0  # skipped excluded from denominator


@pytest.mark.asyncio
async def test_blocked_tasks_require_reason_and_surface_as_roadblocks():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        project = (await client.post("/api/v1/migrations", json={"name": "RSA to PQC"})).json()
        pid = project["id"]
        task = (await client.post(f"/api/v1/migrations/{pid}/tasks", json={"title": "Migrate payment HSM"})).json()

        no_reason = await client.patch(f"/api/v1/migrations/tasks/{task['id']}", json={"status": "BLOCKED"})
        assert no_reason.status_code == 400

        blocked = (await client.patch(
            f"/api/v1/migrations/tasks/{task['id']}",
            json={"status": "BLOCKED", "blocked_reason": "vendor HSM does not support ML-KEM yet"},
        )).json()
        assert blocked["blocked_reason"]

        progress = (await client.get(f"/api/v1/migrations/{pid}/progress")).json()
        assert progress["roadblocks"] == [{
            "task_id": task["id"], "title": "Migrate payment HSM",
            "reason": "vendor HSM does not support ML-KEM yet", "owner": None, "priority": "P2",
        }]


@pytest.mark.asyncio
async def test_forecast_detects_at_risk_and_recommends():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = (await client.post("/api/v1/migrations", json={"name": "Big bang"})).json()
        pid = created["id"]
        task_ids = []
        for index in range(10):
            task = (await client.post(f"/api/v1/migrations/{pid}/tasks", json={"title": f"task {index}"})).json()
            task_ids.append(task["id"])

        # simulate history: one task done 3 weeks ago, one 2 weeks ago —
        # a slow measured pace (~1.75 tasks/week over an 8-day window)
        from db.models.migration_project import MigrationTask
        history = [datetime.now(timezone.utc) - timedelta(days=21), datetime.now(timezone.utc) - timedelta(days=14)]
        for task_id, completed_at in zip(task_ids[:2], history):
            row = session.get(MigrationTask, task_id)
            row.status = "DONE"
            row.completed_at = completed_at
        session.flush()

        # target 2 weeks out: 8 remaining at 0.67 tasks/week = ~12 weeks -> late
        target = datetime.now(timezone.utc) + timedelta(days=14)
        await client.post(f"/api/v1/migrations/{pid}/milestones", json={"name": "DORA wave 1", "target_date": target.isoformat()})

        forecast = (await client.get(f"/api/v1/migrations/{pid}/forecast")).json()
        assert forecast["status"] == "AT_RISK"
        assert forecast["tasks_remaining"] == 8
        assert "late" in forecast["recommendation"] and "tasks/week" in forecast["recommendation"]
        assert forecast["target_date"]  # picked up from the milestone

        milestones = (await client.get(f"/api/v1/migrations/{pid}/milestones")).json()["milestones"]
        assert milestones[0]["status"] == "AT_RISK"  # milestone mirrors the forecast


@pytest.mark.asyncio
async def test_external_sync_and_issue_export():
    app, session, engine = _make_app()
    _seed_scan(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = (await client.post("/api/v1/migrations/from-scan", json={"scan_id": "scan-mig"})).json()
        pid = created["project"]["id"]
        tasks = (await client.get(f"/api/v1/migrations/{pid}/tasks")).json()["tasks"]

        # attach external refs the way an export-import round trip would
        for index, task in enumerate(tasks):
            await client.patch(f"/api/v1/migrations/tasks/{task['id']}", json={"external_ref": f"ISSUE-{index + 1}"})

        export = (await client.get(f"/api/v1/migrations/{pid}/export/github-issues")).json()
        assert export["issue_count"] == 2
        first = export["issues"][0]
        assert first["title"] and "cryptoscan" in first["labels"]
        assert "deterministically" in first["body"]

        # the external tracker marks its issues done -> push sync back
        sync = (await client.post(f"/api/v1/migrations/{pid}/sync", json={
            "updates": [
                {"external_ref": "ISSUE-1", "status": "DONE"},
                {"external_ref": "ISSUE-999", "status": "DONE"},   # unknown -> reported
                {"external_ref": "ISSUE-2", "status": "WAT"},      # invalid -> reported
            ]
        })).json()
        assert sync["applied"] == 1 and sync["unknown_refs"] == ["ISSUE-999"]
        assert sync["invalid"][0]["status"] == "WAT"

        progress = (await client.get(f"/api/v1/migrations/{pid}/progress")).json()
        assert progress["tasks_done"] == 1  # external completion landed


@pytest.mark.asyncio
async def test_milestone_lifecycle():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        project = (await client.post("/api/v1/migrations", json={"name": "Wave 1"})).json()
        pid = project["id"]
        task = (await client.post(f"/api/v1/migrations/{pid}/tasks", json={"title": "only task"})).json()

        overdue = datetime.now(timezone.utc) - timedelta(days=5)
        await client.post(f"/api/v1/migrations/{pid}/milestones", json={"name": "Q3 target", "target_date": overdue.isoformat()})
        milestones = (await client.get(f"/api/v1/migrations/{pid}/milestones")).json()["milestones"]
        assert milestones[0]["status"] == "MISSED"  # past target, incomplete

        await client.patch(f"/api/v1/migrations/tasks/{task['id']}", json={"status": "DONE"})
        milestones = (await client.get(f"/api/v1/migrations/{pid}/milestones")).json()["milestones"]
        assert milestones[0]["status"] == "MISSED"  # achieved late stays MISSED

        future = datetime.now(timezone.utc) + timedelta(days=30)
        await client.post(f"/api/v1/migrations/{pid}/milestones", json={"name": "Q4 target", "target_date": future.isoformat()})
        milestones = (await client.get(f"/api/v1/migrations/{pid}/milestones")).json()["milestones"]
        by_name = {row["name"]: row["status"] for row in milestones}
        assert by_name["Q4 target"] == "ACHIEVED"  # complete before target
