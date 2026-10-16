"""Durable derived writes must ride the caller's transaction, not a second one.

Every scan on the documented single-box backend (file-backed SQLite) used to
log two failures and then report success::

    WARNING platform_event_persist_failed: (sqlite3.OperationalError) database is locked
    WARNING stage_cbom_snapshot_persist_failed

and the database afterwards showed ``cbom_snapshots = 0``,
``monitor_events = 0``, ``graph_snapshots = 0`` next to a fully populated scan
(``scans = 1``, ``evidence_records = 19``, ``cryptographic_facts = 19``).

The mechanism is not a bug in SQLite and not a bug in the writers: the pipeline
opens one session, writes every stage, and commits once at the end — holding a
write transaction for the whole run. Any callee that opens its *own*
``SessionLocal()`` to write a derived row is a second writer, so it waits out
``busy_timeout`` (5 s) and loses. The same ``POST /cbom/scan/{id}/snapshot``
against an idle database succeeds in milliseconds, which is what made this look
like a CBOM bug rather than a transaction-scope bug.

These tests use file-backed SQLite with two real connections on purpose: the
existing pin test binds an in-memory engine with ``StaticPool``, where every
"second" session shares the one connection, so writer-vs-writer contention
cannot exist there and the test passed while every real run failed.
"""
from __future__ import annotations

import types
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

import db.connection.session as connection
from db.connection.session import Base, SessionLocal, configure_session
from db.models.cbom_snapshot import CbomSnapshot
from db.models.monitor import MonitorEvent
from db.models.scan import Scan
from worker.pipeline.pipeline_runner import PipelineContext, PipelineRunner
from worker.pipeline.stage_cbom_generate import _persist_snapshot
from worker.pipeline.stage_cbom_generate import execute as cbom_stage

FINDING = {"id": "e1", "algorithm": "AES", "mode": "GCM", "file_path": "a.py", "line_number": 1}


def _ctx(tmp_path) -> PipelineContext:
    ctx = PipelineContext(
        job_id="j-durable",
        target_repo="local://test-fixture",
        target_branch="main",
        triggered_by="t",
        workspace_dir=str(tmp_path),
        repo_path=str(tmp_path),
        scan_id="s-durable",
    )
    ctx.findings = [dict(FINDING)]
    return ctx


def _bom(ctx: PipelineContext) -> dict:
    from cbom.generator import CbomGenerator

    return CbomGenerator().from_records(ctx.findings, name=ctx.target_repo, version="1")


@pytest.fixture()
def sqlite_file_db(tmp_path, monkeypatch):
    """File-backed SQLite with the production pragmas, bound as the global
    ``SessionLocal``.

    ``busy_timeout`` is 0.5 s instead of the production 5 s so the suite stays
    fast; the outcome (the second writer loses) is identical.
    """
    import db.models  # noqa: F401 — register every table

    engine = create_engine(
        f"sqlite:///{tmp_path / 'contended.db'}",
        connect_args={"check_same_thread": False, "timeout": 0.5},
    )

    @event.listens_for(engine, "connect")
    def _sqlite_pragma(dbapi_connection, _record):  # mirrors db/connection/engine.py
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=500")
        cursor.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    configure_session(engine)
    monkeypatch.setattr(connection, "SessionLocal", factory)

    yield types.SimpleNamespace(engine=engine, factory=factory)

    engine.dispose()
    # never leave the global bind pointing at this test's closed database
    SessionLocal.configure(bind=None)
    connection.SessionLocal = SessionLocal


@pytest.fixture()
def contended_db(sqlite_file_db):
    """The same database with a pipeline session already inside an open write
    transaction — the condition every real scan runs under."""
    pipeline = sqlite_file_db.factory()
    pipeline.add(Scan(
        id="s-durable", status="RUNNING", target_type="LOCAL_DIRECTORY",
        target_location="local://test-fixture",
        scan_start=datetime(2026, 10, 16, tzinfo=timezone.utc),
    ))
    pipeline.flush()  # write transaction open, exactly like a live run

    yield types.SimpleNamespace(engine=sqlite_file_db.engine,
                                factory=sqlite_file_db.factory,
                                pipeline=pipeline)

    pipeline.close()


def _no_second_connection():
    raise AssertionError("a derived write must not open a second connection "
                         "while the caller's transaction is open")


def test_the_second_writer_really_does_lose(contended_db):
    """Pin the mechanism the fix depends on, so the fix cannot be reverted
    silently by "SQLite got faster"."""
    other = contended_db.factory()
    with pytest.raises(OperationalError, match="locked"):
        other.add(Scan(id="s-second", status="RUNNING", target_type="LOCAL_DIRECTORY",
                       target_location="local://other",
                       scan_start=datetime(2026, 10, 16, tzinfo=timezone.utc)))
        other.flush()
    other.rollback()
    other.close()

    # the identical write on the pipeline's own transaction is immediate
    contended_db.pipeline.add(Scan(id="s-same", status="RUNNING", target_type="LOCAL_DIRECTORY",
                                   target_location="local://same",
                                   scan_start=datetime(2026, 10, 16, tzinfo=timezone.utc)))
    contended_db.pipeline.flush()


def test_cbom_pin_rides_the_pipeline_transaction(contended_db, tmp_path, monkeypatch):
    """The pinned snapshot lands in the scan's own transaction and survives it."""
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(connection, "SessionLocal", _no_second_connection)

    snapshot_id = _persist_snapshot(ctx, _bom(ctx), session=contended_db.pipeline)

    assert snapshot_id
    assert contended_db.pipeline.query(CbomSnapshot).count() == 1

    contended_db.pipeline.commit()
    fresh = contended_db.factory()
    row = fresh.query(CbomSnapshot).one()
    assert row.generator == "pipeline"
    assert row.scan_id == "s-durable"
    assert row.component_count == 1
    fresh.close()


def test_graph_updated_event_reaches_the_journal(contended_db, monkeypatch):
    """``graph_builder.sync_graph`` emits from inside a pipeline run: the row
    must reach monitor_events, which is what the realtime fan-out, the
    notification feed and the health probes read."""
    from api.events.bus import reset_event_bus
    from api.events import platform_events
    from api.events.platform_events import emit_platform_event

    reset_event_bus()
    monkeypatch.setattr(platform_events, "app_state", lambda: types.SimpleNamespace())
    monkeypatch.setattr(connection, "SessionLocal", _no_second_connection)

    emitted = emit_platform_event(
        "graph.updated",
        "Dependency graph synced (3 nodes / 2 edges)",
        {"nodes": 3, "edges": 2, "synced": False},
        target_name="graph",
        session=contended_db.pipeline,
    )

    row = contended_db.pipeline.query(MonitorEvent).one()
    assert row.event_type == "graph.updated"
    assert row.target_name == "graph"
    # the bus payload carries the row id, and the dedup registry keys off it:
    # a dropped row means the tailer never replays this event to other replicas
    assert emitted is not None
    assert emitted["type"] == "platform.graph.updated"
    assert emitted["payload"]["row_id"] == row.id

    contended_db.pipeline.commit()
    fresh = contended_db.factory()
    assert fresh.query(MonitorEvent).count() == 1
    fresh.close()


def test_sync_graph_passes_its_own_session_to_the_event(contended_db, monkeypatch):
    """Regression pin at the call site: sync_graph receives the pipeline
    session and must hand it on rather than letting the emitter open a new one."""
    import api.graph_builder as graph_builder

    seen: dict[str, object] = {}

    def _capture(event_type, detail, payload=None, *, target_name="platform",
                 tenant_id=None, session=None):
        seen.update(event_type=event_type, target_name=target_name, session=session)
        return {"row_id": "r1"}

    monkeypatch.setattr("api.events.platform_events.emit_platform_event", _capture)

    graph_builder.sync_graph(contended_db.pipeline, driver=None)

    assert seen["event_type"] == "graph.updated"
    assert seen["target_name"] == "graph"
    assert seen["session"] is contended_db.pipeline


def test_a_failed_pin_is_disclosed_not_swallowed(contended_db, tmp_path, monkeypatch):
    """Round 39 §4.8: a COMPLETED scan must not imply complete observation.

    The CBOM stage used to log the failure and then report ``stage_cbom_done``
    with no disclosure entry, unlike every other soft-failed optional stage —
    so the operator saw a clean scan whose only durable BOM had evaporated with
    the workspace.
    """
    ctx = _ctx(tmp_path)

    def _locked():
        raise OperationalError("INSERT INTO cbom_snapshots", {}, Exception("database is locked"))

    monkeypatch.setattr(connection, "SessionLocal", _locked)
    cbom_stage(ctx)

    assert not ctx.scan_meta.get("cbom_snapshot_id")
    assert ctx.scan_meta.get("cbom_path"), "the ephemeral rendering is still written"
    assert "database is locked" in ctx.scan_meta["cbom_snapshot_persist_failed"]

    # the runner turns the stage's marker into the standard disclosure entry
    runner = PipelineRunner()
    runner._cbom(ctx, session=None)

    entries = ctx.scan_meta["statistics"]["optional_stage_failures"]
    assert [e["stage"] for e in entries] == ["cbom_snapshot_persist"]
    assert entries[0]["outcome"] == "failed"
    assert "ephemeral workspace" in entries[0]["detail"]
    assert "cbom_snapshot_persist_failed" not in ctx.scan_meta, "marker is consumed, not leaked"


def test_a_failed_scan_still_stamps_coverage_failed(sqlite_file_db, tmp_path, monkeypatch):
    """The failure path had the same defect, and it is the worse one.

    ``_stamp_coverage_failed`` writes on its own connection *because* the stamp
    has to survive the pipeline's rollback — but it ran while that rollback had
    not happened yet, so on SQLite it waited out ``busy_timeout``, raised
    ``database is locked``, and was swallowed at debug level
    (``coverage_fail_stamp_skipped``). A failed scan therefore left its system
    reporting ``coverage_status=CURRENT``: the one thing a failed scan must
    never claim. The runner now releases the write lock first.
    """
    import time

    from db.models.system import System
    from db.repositories.job_repository import JobRepository

    factory = sqlite_file_db.factory
    setup = factory()
    setup.add(System(id="sys-1", name="Payments", coverage_status="CURRENT"))
    job = JobRepository(setup).create_job(
        job_type="MANUAL", target_repo=f"local://{tmp_path}",
        target_branch="main", triggered_by="operator")
    setup.commit()
    job_id = job.id
    setup.close()

    # fail late enough that the pipeline transaction has really written: _load
    # has created the Scan row, so the runner is holding SQLite's write lock
    def _boom(self, ctx, session):
        raise RuntimeError("policy engine exploded")

    monkeypatch.setattr(PipelineRunner, "_policy", _boom)

    started = time.monotonic()
    with pytest.raises(RuntimeError, match="Pipeline failed at stage policy"):
        PipelineRunner().run(
            job_id=job_id, target_repo=f"local://{tmp_path}", target_branch="main",
            triggered_by="operator", workspace_dir=str(tmp_path / "ws"), system_id="sys-1")
    elapsed = time.monotonic() - started

    fresh = factory()
    system = fresh.get(System, "sys-1")
    assert system.coverage_status == "FAILED"
    assert system.extra["last_scan_error"] == "Pipeline failed at stage policy"
    fresh.close()
    # a lost stamp cost the full busy timeout before it failed; the real one is 5 s
    assert elapsed < 4.0, f"the coverage stamp waited out busy_timeout ({elapsed:.2f}s)"


def test_a_successful_pin_leaves_no_disclosure(contended_db, tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    PipelineRunner()._cbom(ctx, contended_db.pipeline)

    assert ctx.scan_meta.get("cbom_snapshot_id")
    assert "cbom_snapshot_persist_failed" not in ctx.scan_meta
    assert not (ctx.scan_meta.get("statistics") or {}).get("optional_stage_failures")
    assert contended_db.pipeline.query(CbomSnapshot).count() == 1
