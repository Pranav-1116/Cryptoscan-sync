"""Actual child-process interruption with file-backed SQLite SQL authority.

The collector and runtime preflight are doubles, not Docker/escape or production
PostgreSQL qualification. SIGKILL is real; expiry time is advanced explicitly.
"""
from contextlib import contextmanager
from dataclasses import asdict
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, select as sql_select

from db.connection.session import SessionLocal, configure_session
from db.models.execution_control import ExecutionAttempt, ExecutionBudget
from db.models.scan_job import ScanJob
from db.repositories import execution_control as controls
from db.tenancy import tenant_scope
from worker.core.job_reaper import fail_job
from test_execution_controls import approve, configure, queue
from test_execution_controls import controlled as controlled
from test_software_supply_chain_api import banks as banks


CHILD = r'''
import json, sys
from datetime import timedelta
from sqlalchemy import create_engine
from db.connection.session import configure_session, SessionLocal
from db.models.base import utcnow
from db.repositories import execution_control as controls
from worker.core.job_consumer import ScanJob
from worker.core.job_executor import JobExecutor
import worker.core.job_executor as executor_module
import worker.core.controlled_source as source_module

path, mode, descriptor_json = sys.argv[1:]
engine = create_engine("sqlite:///" + path)
configure_session(engine)
if mode == "recover":
    with SessionLocal() as db:
        count = controls.recover_expired(db, now=utcnow() + timedelta(hours=1))
        db.commit()
    print(json.dumps({"recovered": count}), flush=True)
else:
    # Isolate execution authority from a provisioned daemon / collector.
    executor_module.gate_job = lambda *a, **kw: (True, None)
    source_module.preflight = lambda: None
    job = ScanJob(**json.loads(descriptor_json))
    executor = JobExecutor()
    def collector(**kwargs):
        if mode == "checkpoint":
            controls.checkpoint("before-synthetic-launch", request=True)
        print("COLLECTOR_STARTED", flush=True)
        if mode == "redeliver":
            raise AssertionError("Duplicate/UNKNOWN work must not run")
        sys.stdin.buffer.read(1)  # parent SIGKILLs here; no cleanup can run
        raise AssertionError("Unexpected input")
    executor.runner.run = collector
    if mode == "before-claim":
        print("BEFORE_CLAIM", flush=True)
        sys.stdin.buffer.read(1)
    result = executor.execute(job)
    print(json.dumps({"executed": result}), flush=True)
engine.dispose()
'''


@contextmanager
def file_database(state):
    """Copy real admitted auth/job state, then stop using the memory database."""
    original = SessionLocal.kw["bind"]
    state["db"].rollback()  # release the fixture's read transaction before backup
    path = state["tmp"] / "durable-recovery.sqlite"
    source = original.raw_connection()
    try:
        with sqlite3.connect(path) as destination:
            source.driver_connection.backup(destination)
    finally:
        source.close()
    engine = create_engine("sqlite:///" + str(path))
    configure_session(engine)
    try:
        yield path
    finally:
        configure_session(original)
        engine.dispose()


def command(path, mode, descriptor):
    return [sys.executable, "-c", CHILD, str(path), mode, json.dumps(asdict(descriptor))]


def run_child(path, mode, descriptor):
    result = subprocess.run(command(path, mode, descriptor), text=True, capture_output=True,
                            timeout=30, cwd=Path(__file__).resolve().parents[4], env=os.environ.copy())
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def state_of(job_id):
    with SessionLocal() as db:
        job = db.get(ScanJob, job_id)
        attempts = db.execute(sql_select(ExecutionAttempt).where(ExecutionAttempt.job_id == job_id)).scalars().all()
        return (job.status, job.version, job.scan_id,
                [(a.status, a.version) for a in attempts],
                sorted((b.id, b.active, b.version) for b in db.query(ExecutionBudget)))


@pytest.mark.parametrize("point", ["before-claim", "claimed", "checkpoint"])
def test_sigkill_and_fresh_process_recovery_preserve_durable_unknown(controlled, point):
    configure(controlled)
    approve(controlled)
    row, descriptor = queue(controlled)
    job_id = row.id
    with file_database(controlled) as path:
        child = subprocess.Popen(command(path, point, descriptor), text=True,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 cwd=Path(__file__).resolve().parents[4], env=os.environ.copy())
        try:
            readable, _, _ = select.select([child.stdout], [], [], 20)
            assert readable, "Child failed to reach the selected interruption point"
            marker = child.stdout.readline().strip()
            if marker != ("BEFORE_CLAIM" if point == "before-claim" else "COLLECTOR_STARTED"):
                _, error = child.communicate(timeout=5)
                pytest.fail(f"Unexpected child startup marker {marker!r}: {error}")
            before = state_of(job_id)
            if point != "before-claim":
                assert before[0] == "RUNNING" and before[3][0][0] == "RUNNING"
                assert all(active == 1 for _, active, _ in before[4])
                # A second, independent worker process cannot execute an in-flight duplicate.
                assert run_child(path, "redeliver", descriptor) == {"executed": False}
                with SessionLocal() as db:
                    fail_job(db, job_id, "duplicate transport delivery exhausted")
                assert state_of(job_id) == before
            child.kill()
            child.communicate(timeout=5)
            assert child.returncode == -signal.SIGKILL
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)

        assert run_child(path, "recover", descriptor) == {"recovered": int(point != "before-claim")}
        recovered = state_of(job_id)
        if point == "before-claim":
            assert recovered[0] == "QUEUED" and recovered[3] == []
            assert all(active == 0 for _, active, _ in recovered[4])
        else:
            assert recovered[0] == "UNKNOWN" and recovered[3][0][0] == "UNKNOWN"
            assert recovered[2] is None
            assert all(active == 1 for _, active, _ in recovered[4])
            assert run_child(path, "redeliver", descriptor) == {"executed": False}
            with tenant_scope("a"), controls.execution_scope({
                "id": "stale-process", "owner": "a", "job_id": job_id, "fence": "stale-fence",
            }), pytest.raises(controls.ExecutionDenied):
                controls.checkpoint("late-worker")
        assert run_child(path, "recover", descriptor) == {"recovered": 0}
        assert state_of(job_id) == recovered
