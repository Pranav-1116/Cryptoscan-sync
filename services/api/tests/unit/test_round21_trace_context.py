"""Round 21 (report 02 P2#7): trace-context propagation across the queue.

The API already correlates requests (RequestIDMiddleware + trace.py);
this pins the missing half — the request's trace id travels with the job
payload and the job row, and the worker binds it into the pipeline
context where stage logs and scan statistics can see it.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.user import User

SECRET = "r21-trace-secret-" + "x" * 19


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", SECRET)
    get_settings.cache_clear()
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add(User(username="op-user", roles="developer", password_hash="x"))
    session.commit()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "op-user"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


@pytest.mark.asyncio
async def test_inbound_trace_id_echoed_on_response():
    app, session, engine = _make_app()
    try:
        client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        resp = await client.get("/healthz", headers={"X-Trace-Id": "trace-abc-123"})
        assert resp.status_code == 200
        assert resp.headers.get("x-trace-id") == "trace-abc-123"
    finally:
        engine.dispose()


def test_enqueue_payload_carries_active_trace(monkeypatch):
    """enqueue_scan_job puts the request's trace id on the queue payload."""
    from api.middleware.trace import push_trace
    from api.routers import trigger

    captured: dict = {}

    from datetime import datetime, timezone

    class _Job:
        job_id = "job-1"
        created_at = datetime(2026, 10, 10, tzinfo=timezone.utc)
        tenant_id = None
        progress = None

    class _Repo:
        session = type("S", (), {"commit": lambda self: None, "rollback": lambda self: None})()
        progress_defaults = None

        def create(self, **kwargs):
            job = _Job()
            job.progress = dict(kwargs.get("progress") or {})
            return job

    def _publish(payload):
        captured.update(payload)

    # admit_scan / is_cloud_target are function-local imports: patch at source
    import api.security.scan_admission as admission
    import cloud_scanner.estate as estate

    monkeypatch.setattr(admission, "admit_scan", lambda **_: None)
    monkeypatch.setattr(estate, "is_cloud_target", lambda _: False)
    monkeypatch.setattr(trigger, "_resolve_sector", lambda sector, repo: "generic")
    monkeypatch.setattr(trigger, "_publish_job", _publish)
    monkeypatch.setattr(trigger, "_run_inline", _publish)

    push_trace("trace-xyz-999", "span-1")
    try:
        from api.schemas.job_schemas import TriggerScanResponse  # noqa: F401

        result = trigger.enqueue_scan_job(
            _Repo(),
            _BackgroundTasksStub(),
            repo_url="https://github.com/org/repo.git",
            triggered_by="tester",
        )
        assert result is not None
        assert captured.get("trace_id") == "trace-xyz-999"
    finally:
        from api.middleware.trace import reset_trace

        reset_trace()


class _BackgroundTasksStub:
    def add_task(self, fn, *args, **kwargs):
        fn(*args, **kwargs)


def test_trace_id_from_job_row():
    from worker.pipeline.pipeline_runner import trace_id_from_job

    class Job:
        progress = {"sector": "finance", "trace_id": "trace-from-row"}
        raw = None

    assert trace_id_from_job(Job()) == "trace-from-row"

    class RawJob:
        progress = None
        raw = {"trace_id": "trace-from-payload"}

    assert trace_id_from_job(RawJob()) == "trace-from-payload"

    class Plain:
        progress = None
        raw = None

    assert trace_id_from_job(Plain()) is None


def test_pipeline_context_binds_trace_id():
    from worker.pipeline.pipeline_runner import PipelineContext

    ctx = PipelineContext(
        job_id="j1", target_repo="r", target_branch="main", triggered_by="t",
        workspace_dir="/tmp", scan_id="s1", trace_id="trace-ctx-1",
    )
    assert ctx.trace_id == "trace-ctx-1"
    assert ctx.scan_meta["trace_id"] == "trace-ctx-1"
