"""Job progress must be readable WHILE the job runs, not only after it.

BaseRepository.update only flushes, and PipelineRunner.run() commits its
own session once, after the final stage. Every progress update therefore
sat in an uncommitted transaction no other connection could read: the API
reported QUEUED with started_at NULL for an entire nine-minute scan and
then jumped to COMPLETED, because that was when the work became visible
rather than when it happened. A long scan was indistinguishable from a
wedged one.

The fix cannot be an inline commit on the pipeline session -- that would
also commit the half-built scan and evidence rows it carries, and the
evidence load is deliberately atomic. Status travels on its own
short-lived session instead. These tests pin that split: a reader on a
different connection sees progress while the pipeline transaction is
still open, and the pipeline's own uncommitted data stays invisible.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.models.base import Base
from db.models.scan import Scan
from db.models.scan_job import ScanJob


@pytest.fixture
def shared_db(tmp_path, monkeypatch):
    """A file-backed SQLite database two connections can genuinely share.

    An in-memory database gives each connection its own private copy, which
    would make this test pass no matter what the code did.
    """
    url = f"sqlite:///{tmp_path / 'jobs.db'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    Factory = sessionmaker(bind=engine)

    import db.connection.session as session_module

    monkeypatch.setattr(session_module, "SessionLocal", Factory, raising=False)
    yield Factory
    engine.dispose()


@pytest.fixture
def postgres_db(monkeypatch):
    """Fresh isolated database; skip rather than substituting SQLite."""
    from db.testing import drop_engine, estate_engine

    engine = estate_engine("postgresql")
    if engine is None:
        pytest.skip("no PostgreSQL test server available")
    # If telemetry ever waits on the pipeline's job-row lock, fail promptly.
    # This database was created by estate_engine, never the configured live DB.
    url = engine.url
    engine.dispose()
    engine = create_engine(url, connect_args={"options": "-c lock_timeout=1000"})
    try:
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        import db.connection.session as session_module

        monkeypatch.setattr(session_module, "SessionLocal", factory, raising=False)
        yield factory
    finally:
        drop_engine(engine)


def _queued_job(factory) -> str:
    job_id = str(uuid.uuid4())
    s = factory()
    s.add(ScanJob(
        id=job_id,
        target_repo="local:///tmp/example",
        target_branch="main",
        triggered_by="test",
        status="QUEUED",
        created_at=datetime.now(timezone.utc),
    ))
    s.commit()
    s.close()
    return job_id


def _runner():
    from worker.pipeline.pipeline_runner import PipelineRunner

    return PipelineRunner.__new__(PipelineRunner)


def test_running_status_is_visible_from_another_connection(shared_db):
    job_id = _queued_job(shared_db)

    # The pipeline's own session, mid-run and deliberately not committed.
    pipeline_session = shared_db()
    _runner()._set_job_status(pipeline_session, job_id, "RUNNING")

    reader = shared_db()
    job = reader.query(ScanJob).filter_by(id=job_id).one()
    assert job.status == "RUNNING", "progress is invisible until the pipeline commits"
    assert job.started_at is not None, "started_at never set, so elapsed time is unknowable"
    reader.close()
    pipeline_session.rollback()
    pipeline_session.close()


def test_running_stage_updates_preserve_initial_started_at(shared_db, monkeypatch):
    """Elapsed time starts with the first RUNNING transition, not the last stage."""
    from db.repositories import job_repository

    job_id = _queued_job(shared_db)
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    later = datetime(2026, 1, 2, tzinfo=timezone.utc)
    times = iter((started, later, later))

    class Clock:
        @staticmethod
        def now(_timezone):
            return next(times)

    monkeypatch.setattr(job_repository, "datetime", Clock)
    pipeline_session = shared_db()
    runner = _runner()
    for stage in ("clone", "scan", "gate"):
        runner._set_job_status(
            pipeline_session, job_id, "RUNNING", progress={"current_stage": stage},
        )
        with shared_db() as reader:
            job = reader.get(ScanJob, job_id)
            assert job.started_at.replace(tzinfo=timezone.utc) == started
            assert job.progress["current_stage"] == stage
    pipeline_session.close()


def test_progress_updates_are_visible_as_stages_advance(shared_db):
    job_id = _queued_job(shared_db)
    pipeline_session = shared_db()
    runner = _runner()

    seen = []
    for stage, percent in (("clone", 7), ("scan", 21), ("load", 29)):
        runner._set_job_status(
            pipeline_session, job_id, "RUNNING",
            progress={"current_stage": stage, "percent": percent},
        )
        reader = shared_db()
        row = reader.query(ScanJob).filter_by(id=job_id).one()
        seen.append((row.progress or {}).get("current_stage"))
        reader.close()

    assert seen == ["clone", "scan", "load"], seen
    pipeline_session.rollback()
    pipeline_session.close()


def test_status_commit_never_leaks_uncommitted_pipeline_rows(shared_db):
    """The telemetry commit must not drag half-built scan data with it.

    This is the reason status does not simply commit on the pipeline
    session: that session is carrying the scan and evidence rows, and the
    evidence load is atomic by design.

    Note what is NOT asserted here. SQLite permits a single writer, so
    while the pipeline holds a write transaction the telemetry connection
    is locked out and _set_job_status falls back to the pipeline session —
    deferred, as it always was, rather than lost. Live visibility under a
    concurrent write is a PostgreSQL property and is covered by the tests
    above, which do not hold a pipeline write lock. The isolation property
    below holds on every backend, which is why it is the one asserted.
    """
    job_id = _queued_job(shared_db)
    pipeline_session = shared_db()

    # Something the pipeline has built but not committed yet.
    pending = ScanJob(
        id=str(uuid.uuid4()),
        target_repo="local:///tmp/not-committed",
        target_branch="main",
        triggered_by="test",
        status="QUEUED",
        created_at=datetime.now(timezone.utc),
    )
    pipeline_session.add(pending)
    pipeline_session.flush()

    _runner()._set_job_status(pipeline_session, job_id, "RUNNING")

    reader = shared_db()
    assert reader.query(ScanJob).filter_by(id=pending.id).first() is None, (
        "the status commit leaked the pipeline's uncommitted rows"
    )
    reader.close()
    pipeline_session.rollback()
    pipeline_session.close()


def test_status_is_not_lost_when_a_second_writer_is_blocked(shared_db):
    """A locked-out telemetry session must defer, never drop the update.

    Before the split this was the only path and it always worked, so the
    fallback is what stops the fix being a regression on SQLite.
    """
    job_id = _queued_job(shared_db)
    pipeline_session = shared_db()
    pipeline_session.add(ScanJob(
        id=str(uuid.uuid4()),
        target_repo="local:///tmp/holds-the-write-lock",
        target_branch="main",
        triggered_by="test",
        status="QUEUED",
        created_at=datetime.now(timezone.utc),
    ))
    pipeline_session.flush()   # SQLite now holds the single write lock

    _runner()._set_job_status(pipeline_session, job_id, "RUNNING")

    # Applied on the pipeline session, so it lands with the pipeline commit.
    assert pipeline_session.query(ScanJob).filter_by(id=job_id).one().status == "RUNNING"
    pipeline_session.rollback()
    pipeline_session.close()


def test_falls_back_to_the_caller_session_for_an_uncommitted_job(shared_db, monkeypatch):
    """In-process callers create the job in their own open transaction.

    A fresh connection cannot see that row, so the update must fall back to
    the caller's session rather than silently doing nothing.
    """
    pipeline_session = shared_db()
    job_id = str(uuid.uuid4())
    pipeline_session.add(ScanJob(
        id=job_id,
        target_repo="local:///tmp/example",
        target_branch="main",
        triggered_by="test",
        status="QUEUED",
        created_at=datetime.now(timezone.utc),
    ))
    pipeline_session.flush()   # visible only inside this transaction

    runner = _runner()
    runner._set_job_status(pipeline_session, job_id, "RUNNING")
    assert job_id in pipeline_session.info["deferred_job_ids"]

    import db.connection.session as session_module

    def no_second_connection():
        raise AssertionError("uncommitted job retried on a new connection")

    monkeypatch.setattr(session_module, "SessionLocal", no_second_connection)
    runner._set_job_status(pipeline_session, job_id, "RUNNING", progress={"current_stage": "scan"})
    job = pipeline_session.query(ScanJob).filter_by(id=job_id).one()
    assert job.status == "RUNNING"
    assert job.progress["current_stage"] == "scan"
    pipeline_session.rollback()
    pipeline_session.close()


def test_postgres_stage_progress_does_not_lock_the_job_row(postgres_db):
    """A flushed scan/evidence transaction must not block live job telemetry."""
    from worker.pipeline.pipeline_runner import PipelineContext

    job_id = _queued_job(postgres_db)
    scan_id = str(uuid.uuid4())
    pipeline_session = postgres_db()
    pipeline_session.add(Scan(
        id=scan_id, scan_start=datetime.now(timezone.utc),
        target_location="local:///tmp/example", status="RUNNING",
    ))
    pipeline_session.flush()  # scan exists only in this open transaction
    ctx = PipelineContext(
        job_id=job_id, target_repo="local:///tmp/example", target_branch="main",
        triggered_by="test", workspace_dir="/tmp", scan_id=scan_id,
        scan_persisted=True,
    )
    runner = _runner()
    try:
        for stage in ("normalize", "policy", "gate"):
            runner._advance(pipeline_session, ctx, stage)
            with postgres_db() as reader:
                job = reader.get(ScanJob, job_id)
                assert job.status == "RUNNING"
                assert job.progress["current_stage"] == stage
                assert job.scan_id is None
                assert "scan_id" not in job.progress
                assert reader.get(Scan, scan_id) is None
        pipeline_session.commit()
        ctx.scan_committed = True
        runner._advance(pipeline_session, ctx, "alert", status="COMPLETED")
        with postgres_db() as reader:
            job = reader.get(ScanJob, job_id)
            assert job.status == "COMPLETED"
            assert job.scan_id == scan_id
            assert reader.get(Scan, scan_id) is not None
    finally:
        pipeline_session.rollback()
        pipeline_session.close()


def test_uncommitted_job_links_scan_after_caller_commit(shared_db):
    """In-process jobs cannot be seen by telemetry until the caller commits."""
    from worker.pipeline.pipeline_runner import PipelineContext

    job_id, scan_id = str(uuid.uuid4()), str(uuid.uuid4())
    pipeline_session = shared_db()
    pipeline_session.add(ScanJob(
        id=job_id, target_repo="local:///tmp/example", target_branch="main",
        triggered_by="test", status="QUEUED",
    ))
    pipeline_session.add(Scan(
        id=scan_id, scan_start=datetime.now(timezone.utc),
        target_location="local:///tmp/example", status="COMPLETED",
    ))
    pipeline_session.flush()
    ctx = PipelineContext(
        job_id=job_id, target_repo="local:///tmp/example", target_branch="main",
        triggered_by="test", workspace_dir="/tmp", scan_id=scan_id,
    )
    runner = _runner()
    runner._advance(pipeline_session, ctx, "load")
    runner._advance(pipeline_session, ctx, "alert", status="COMPLETED", defer_to_session=True)
    assert pipeline_session.get(ScanJob, job_id).scan_id is None
    runner._link_scan_after_commit(pipeline_session, job_id, scan_id)
    pipeline_session.commit()
    with shared_db() as reader:
        job = reader.get(ScanJob, job_id)
        assert job.status == "COMPLETED"
        assert job.scan_id == scan_id
    pipeline_session.close()


def test_failure_does_not_expose_sql_in_job_status(shared_db, tmp_path):
    from unittest.mock import patch
    from worker.pipeline.pipeline_runner import PipelineRunner

    job_id = _queued_job(shared_db)
    raw_error = "[SQL: SELECT secret FROM users] [parameters: ('super-secret',)]"
    runner = _runner()
    with patch.object(PipelineRunner, "_clone", side_effect=RuntimeError(raw_error)), \
            patch.object(PipelineRunner, "_post_github"):
        with pytest.raises(RuntimeError, match="Pipeline failed at stage init") as raised:
            runner.run(job_id=job_id, target_repo="local:///tmp/example", workspace=tmp_path)
    assert raw_error not in str(raised.value)
    with shared_db() as reader:
        job = reader.get(ScanJob, job_id)
        assert job.status == "FAILED"
        assert job.error_message == "Pipeline failed at stage init"
        assert raw_error not in str(job.progress)
