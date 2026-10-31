"""The job/worker contract: nine properties, each proven by an executed drill.

`failure_matrix.py` asks "what happens when X breaks". This asks the other
question a bank asks of a scan platform: **does the job path actually keep its
promises** — exactly one delivery, a bounded retry, a dead letter, a timeout
that fires, a cancellation that stops work, an idempotent publication, recovery
after a crash, and concurrency that is controlled rather than hoped for.

The nine properties are the ones a production queue is judged on:

    job queue · worker · retry · timeout · cancellation · idempotency ·
    dead-letter · recovery · controlled concurrency

Each is graded by running the code that is supposed to provide it:

    PROVEN     the drill ran and every check passed
    BROKEN     the drill ran and the property did not hold
    UNPROVEN   the drill could not run here — not a pass

Run::

    python scripts/job_contract_matrix.py \\
        --json docs/bank-environment/111-job-contract.json \\
        --md   docs/bank-environment/111-job-contract.md

What the drills use: fakeredis for the queue (the real-Redis SIGKILL drill is
`scripts/queue_kill9_drill.py`), SQLite for the SQL side, and the real
`WorkerPool`, `JobConsumer`, `reap_stale_jobs`, `dispatch_one` and
`execution_control.checkpoint`. Every row states its own limit.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

try:  # running as a script
    from failure_matrix import BROKEN, PROVEN, UNPROVEN, Broken, Run, Unavailable
except ImportError:  # imported as a package (tests)
    from scripts.failure_matrix import BROKEN, PROVEN, UNPROVEN, Broken, Run, Unavailable

SCHEMA = "cryptoscan.job-contract/1"
VERSION = "job-contract/1.0"

QUEUE = "cryptoscan:contract:queue"


# ------------------------------------------------------------------ helpers --- #
def _consumer(server: Any, worker_id: str, **kwargs: Any) -> Any:
    import fakeredis

    from worker.core.job_consumer import JobConsumer

    consumer = JobConsumer(redis_url="", queue_name=QUEUE, poll_interval_seconds=1,
                           worker_id=worker_id, allow_memory_fallback=True, **kwargs)
    consumer.redis_client = fakeredis.FakeRedis(server=server, decode_responses=True)
    consumer.redis_url = "redis://contract"
    return consumer


def _payload(job_id: str, **extra: Any) -> dict[str, Any]:
    return {"job_id": job_id, "target_repo": "https://example/contract.git",
            "target_branch": "main", **extra}


def _sql_fixture() -> tuple[Any, Any, Any]:
    """An in-memory database with the ORM metadata registered."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 — registers the metadata
    from db.models.base import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine), Base


def _queued_job(session: Any, *, status: str = "QUEUED") -> Any:
    from db.repositories.job_repository import JobRepository

    job = JobRepository(session).create_job(job_type="MANUAL", target_repo="https://example/r.git",
                                            target_branch="main", triggered_by="contract")
    job.status = status
    session.flush()
    session.commit()
    return job


def _attempt(session: Any, job: Any, *, deadline_minutes: float = 60.0) -> Any:
    from db.models.execution_control import ExecutionAttempt

    now = datetime.now(timezone.utc)
    attempt = ExecutionAttempt(
        job_id=job.id, tenant_id=job.tenant_id, approval_id=str(uuid.uuid4()),
        status="RUNNING", checkpoint="contract", fence=uuid.uuid4().hex,
        heartbeat_at=now, deadline_at=now + timedelta(minutes=deadline_minutes), budget_ids=[],
    )
    session.add(attempt)
    session.commit()
    return attempt


# ------------------------------------------------------------------ drills --- #
def drill_job_queue(run: Run) -> tuple[str, str | None]:
    """A published job reaches exactly one consumer and is only dropped on ack."""
    import fakeredis

    server = fakeredis.FakeServer()
    producer = _consumer(server, "producer")
    producer.enqueue(_payload("q1"))
    run.check(producer.redis_client.llen(QUEUE) == 1, "the published job is not on the queue")

    worker = _consumer(server, "worker-a")
    claimed = worker._pop()
    run.check(claimed is not None and claimed.job_id == "q1", "the job was not claimed")
    run.check(worker.redis_client.llen(QUEUE) == 0, "the job is still visible to another consumer")
    run.check(worker.redis_client.llen(worker.processing_key) == 1,
              "the claimed job is not held in the worker's processing list")
    run.check(bool(worker.redis_client.exists(worker.lease_key)),
              "claiming a job did not write a worker lease")
    run.check(worker._pop() is None, "the same job was delivered twice")

    worker.ack(claimed)
    run.check(worker.redis_client.llen(worker.processing_key) == 0, "ack did not release the job")

    run.see(queue_after_claim=0, processing_after_claim=1, lease_written=True,
            second_pop=None, processing_after_ack=0)
    run.note("enqueue → pop moves the job to the worker's processing list under a lease; a second "
             "pop returns nothing; ack clears it")
    return ("enqueue → one claim, job moves to the processing list under a lease, a second pop gets "
            "nothing, ack releases it",
            "fakeredis; the ordering guarantee (BLMOVE left→right) is exercised against the real "
            "client only on a bank host, and a claim is not exactly-once execution")


def drill_worker(run: Run) -> tuple[str, str | None]:
    """The pool runs handlers, honours max_workers, and never leaks a slot."""
    from worker.core.pool import WorkerPool

    gate = threading.Event()
    active = 0
    peak = 0
    lock = threading.Lock()

    def handler(job: Any) -> bool:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            gate.wait(10)
            if job.job_id == "boom":
                raise RuntimeError("handler failed")
            return True
        finally:
            with lock:
                active -= 1

    class _Job:
        def __init__(self, job_id: str) -> None:
            self.job_id = job_id

    pool = WorkerPool(handler, max_workers=2, queue_limit=4)
    futures = [pool.submit(_Job(f"ok{i}")) for i in range(2)]
    time.sleep(0.2)
    run.check(peak <= 2, f"the pool ran {peak} handlers with max_workers=2")
    run.check(pool.saturated is True, "the pool did not report saturation at full occupancy")
    gate.set()
    results = [future.result(timeout=10) for future in futures]
    run.check(results == [True, True], f"handlers returned {results}")

    # A raising handler is deliberately swallowed by the pool: it is logged
    # (`job_execution_failed`), reported to the submitter as False and acked by
    # the worker. The property under test is that it does not wedge the pool,
    # not that it raises — the design does the opposite, and a drill that
    # demanded an exception would be testing the drill.
    failing = pool.submit(_Job("boom"))
    run.check(failing.result(timeout=10) is False,
              "a raising handler was not reported to the submitter as False")

    # The slot must have been released: a later submit still runs.
    after = pool.submit(_Job("after"))
    run.check(after.result(timeout=10) is True, "a failed handler leaked its worker slot")
    run.check(pool.saturated is False, "the pool still reports saturation with nothing running")
    pool.shutdown(wait=True)

    run.see(max_concurrent=peak, max_workers=2, handler_failure_reported_as=False,
            handler_failure_raised=False, slot_recovered=True)
    run.note("2 workers, peak 2; a raising handler is logged and reported as False, and its slot is "
             "released. It is NOT retried — the worker acks it and moves on.")
    return ("peak concurrency equals max_workers; a raising handler is reported to the submitter as "
            "False (logged, not raised) and releases its slot; saturation clears",
            "in-process ThreadPoolExecutor. A handler failure is ack-and-move-on: the row is marked "
            "failed by the executor and the queue does not retry it. Retry exists only for worker "
            "loss, so a transient collector error is a failed job, not a retried one")


def drill_retry(run: Run) -> tuple[str, str | None]:
    """A lost job is requeued with its attempt count, not silently dropped."""
    import fakeredis

    server = fakeredis.FakeServer()
    dead = _consumer(server, "dead")
    dead.enqueue(_payload("r1"))
    first = dead._pop()
    run.check(first is not None and first.attempts == 0, "the first delivery did not have attempts=0")
    dead.redis_client.delete(dead.lease_key)  # the worker died

    recoverer = _consumer(server, "new")
    stats = recoverer.recover_orphans()
    run.check(stats.get("requeued") == 1, f"recovery requeued {stats.get('requeued')} jobs")
    again = recoverer._pop()
    run.check(again is not None and again.job_id == "r1", "the requeued job was not redelivered")
    run.check(again.attempts == 1, f"the redelivery counted attempts={again.attempts}, expected 1")

    run.see(requeued=stats.get("requeued"), attempts_after_redelivery=again.attempts,
            max_redeliveries=recoverer.max_redeliveries)
    run.note("attempts increments on redelivery, so retry is bounded rather than infinite")
    return (f"orphan requeued ({stats.get('requeued')}) and redelivered with attempts=1, bounded by "
            f"max_redeliveries={recoverer.max_redeliveries}",
            "this is redelivery after worker loss, not retry-after-failure: a job whose handler "
            "raises is reported False and acked (see `worker`), so there is no exponential backoff, no "
            "retry budget on the job itself and no retry of a transient collector error. The attempt "
            "counter lives in the queue payload; the SQL row's own policy was not exercised")


def drill_timeout(run: Run) -> tuple[str, str | None]:
    """A job that stops making progress is timed out, twice over."""
    import fakeredis
    from worker.core.job_reaper import reap_stale_jobs

    # (a) queue side: a worker that stops heartbeating loses its lease.
    server = fakeredis.FakeServer()
    silent = _consumer(server, "silent")
    silent.enqueue(_payload("t1"))
    run.check(silent._pop() is not None, "the timeout drill could not claim its job")
    silent.redis_client.delete(silent.lease_key)  # no heartbeat
    recovered = _consumer(server, "new").recover_orphans()
    run.check(recovered.get("requeued") == 1,
              f"a silent worker's job was not recovered ({recovered})")

    # (b) SQL side: a RUNNING row past the wall-clock budget is failed, not stuck.
    engine, sessionmaker_, _base = _sql_fixture()
    session = sessionmaker_()
    try:
        stale = _queued_job(session, status="RUNNING")
        fresh = _queued_job(session, status="RUNNING")
        old = datetime.now(timezone.utc) - timedelta(hours=3)
        stale.created_at = stale.updated_at = old
        session.commit()
        reaped = reap_stale_jobs(session, queued_ids=set(), publish=None,
                                 running_timeout=timedelta(minutes=90))
        session.refresh(stale)
        session.refresh(fresh)
        run.check(reaped["failed_running"] == 1,
                  f"the reaper failed {reaped['failed_running']} stale RUNNING rows")
        run.check(stale.status == "FAILED", f"a stale RUNNING row stayed {stale.status}")
        run.check(fresh.status == "RUNNING", "the reaper failed a job that is still running")

        # (c) execution side: a past deadline denies the next checkpoint mid-run.
        import db.connection.session as session_module
        import db.repositories.execution_control as control

        original = session_module.SessionLocal
        session_module.SessionLocal = sessionmaker_
        try:
            expired_job = _queued_job(session, status="RUNNING")
            attempt = _attempt(session, expired_job, deadline_minutes=-1)
            active = {"id": attempt.id, "job_id": expired_job.id,
                      "owner": expired_job.tenant_id, "fence": attempt.fence}
            token = control._active_execution.set(active)
            try:
                control.checkpoint("stage-2")
            except control.ExecutionDenied as exc:
                denied = str(exc)
            else:
                raise Broken("timeout: an expired attempt passed a mid-run checkpoint")
            finally:
                control._active_execution.reset(token)
        finally:
            session_module.SessionLocal = original
        run.check("lease" in denied.lower(), f"an expired attempt was denied for another reason: {denied}")
    finally:
        session.close()
        engine.dispose()

    run.see(lease_recovered=recovered.get("requeued"), db_failed_running=1,
            checkpoint_denied=denied[:80])
    run.note("lease expiry recovers the job; the wall-clock reaper fails a stuck row; an expired "
             "deadline denies the next stage checkpoint")
    return ("silent worker's lease expires → job recovered; RUNNING row past 90m → FAILED; expired "
            "deadline → ExecutionDenied at the next checkpoint",
            "the three timeouts are checked at different layers and none of them interrupts a handler "
            "already inside a stage — a stage that never returns still occupies its worker")


def drill_cancellation(run: Run) -> tuple[str, str | None]:
    """Cancelling a RUNNING job denies its next checkpoint; a live job is not."""
    import db.connection.session as session_module
    import db.repositories.execution_control as control

    engine, sessionmaker_, _base = _sql_fixture()
    session = sessionmaker_()
    original = session_module.SessionLocal
    session_module.SessionLocal = sessionmaker_
    try:
        outcomes: dict[str, str] = {}
        for label, status in (("cancelled", "CANCELLED"), ("running", "RUNNING")):
            job = _queued_job(session, status=status)
            attempt = _attempt(session, job)
            active = {"id": attempt.id, "job_id": job.id, "owner": job.tenant_id,
                      "fence": attempt.fence}
            token = control._active_execution.set(active)
            try:
                control.checkpoint("stage-2")
                outcomes[label] = "allowed"
            except control.ExecutionDenied as exc:
                outcomes[label] = str(exc)
            finally:
                control._active_execution.reset(token)

        run.see(cancelled_outcome=outcomes["cancelled"], running_outcome=outcomes["running"])
        run.check(outcomes["cancelled"] != "allowed",
                  "a cancelled job passed a mid-run checkpoint")
        run.check("lease" in outcomes["cancelled"].lower(),
                  f"a cancelled job was stopped for another reason: {outcomes['cancelled']}")
        run.check(outcomes["running"] != outcomes["cancelled"],
                  "a live job was refused identically to a cancelled one — the check is not the status")
        run.check("lease" not in outcomes["running"].lower(),
                  "a live job was stopped at the lease check, so cancellation was not what fired")
    finally:
        session_module.SessionLocal = original
        session.close()
        engine.dispose()

    run.note("the same call denies the cancelled job at the lease check and stops the live job later, "
             "at the authority check — the status is what fired, not a broken lease")
    return ("cancelled job → ExecutionDenied('Execution lease is absent, fenced or expired') at the "
            "next checkpoint; the identical call on a RUNNING job gets past that check",
            "cancellation is a checkpoint boundary, not a signal: work already inside a stage runs to "
            "the end of that stage, and a stage that never returns is not interrupted")


def drill_idempotency(run: Run) -> tuple[str, str | None]:
    """The same job cannot be published twice, nor executed twice."""
    import db.repositories.execution_outbox as outbox_module
    from db.models.execution_control import ExecutionOutbox

    engine, sessionmaker_, _base = _sql_fixture()
    session = sessionmaker_()
    original = outbox_module.SessionLocal
    outbox_module.SessionLocal = sessionmaker_
    published: list[dict[str, Any]] = []
    try:
        job = _queued_job(session)
        session.add(ExecutionOutbox(job_id=job.id, tenant_id=job.tenant_id))
        session.commit()

        first = outbox_module.dispatch_one(job.id, published.append)
        second = outbox_module.dispatch_one(job.id, published.append)
        run.check(first is True, "the first dispatch did not publish")
        run.check(second is False, "a second dispatch of the same job published again")
        run.check(len(published) == 1, f"the outbox published {len(published)} times for one job")
        run.check(published[0]["job_id"] == job.id, "the published payload is for another job")

        # A unique key means even a racing insert cannot create a second row.
        from sqlalchemy.exc import IntegrityError

        session.add(ExecutionOutbox(job_id=job.id, tenant_id=job.tenant_id))
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            duplicate_refused = True
        else:
            duplicate_refused = False
        run.check(duplicate_refused, "a duplicate outbox row for one job was accepted")

        # And a duplicate queue delivery is refused at the SQL claim boundary.
        from worker.core import queued_authority

        class _Descriptor:
            job_id = job.id
            tenant_id = job.tenant_id
            target_repo = job.target_repo
            target_branch = job.target_branch
            target_commit = job.target_commit
            triggered_by = job.triggered_by
            job_type = job.job_type
            system_id = job.system_id
            scan_options: dict[str, Any] = {}

        job.status = "RUNNING"
        session.commit()
        try:
            queued_authority._row(session, _Descriptor())
        except queued_authority.QueueRefused as exc:
            refusal = str(exc)
        else:
            raise Broken("idempotency: a claim on an already-running job was accepted")
        run.check("no longer queued" in refusal.lower(), f"the claim was refused for another reason: {refusal}")
    finally:
        outbox_module.SessionLocal = original
        session.close()
        engine.dispose()

    run.see(dispatches=len(published), first_dispatch=first, second_dispatch=second,
            duplicate_row_refused=duplicate_refused, duplicate_claim_refusal=refusal)
    run.note("one outbox row, one publication; a duplicate row is refused by the unique key and a "
             "duplicate delivery is refused because the SQL row is no longer QUEUED")
    return ("outbox dispatch publishes once and returns False afterwards; a duplicate row is refused "
            "by the unique key; a duplicate delivery is refused at the SQL claim",
            "this is at-least-once publication with a claim fence, not exactly-once execution: a crash "
            "between publish and ack may duplicate a message, which the claim then refuses")


def drill_dead_letter(run: Run) -> tuple[str, str | None]:
    """After max_redeliveries a job is dead-lettered with a reason, not looped."""
    import fakeredis

    server = fakeredis.FakeServer()
    failures: list[tuple[str, str]] = []
    crasher = _consumer(server, "crash")
    crasher.enqueue(_payload("d1", _attempts=2))
    claimed = crasher._pop()
    run.check(claimed is not None and claimed.attempts == 2, "the drill job did not carry attempts=2")
    crasher.redis_client.delete(crasher.lease_key)

    recoverer = _consumer(server, "new", max_redeliveries=2,
                          on_dead_letter=lambda payload, reason: failures.append((payload["job_id"], reason)))
    stats = recoverer.recover_orphans()
    run.check(stats.get("dead_lettered") == 1, f"dead-lettered {stats.get('dead_lettered')} jobs")
    run.check(stats.get("requeued") == 0, "a job past max_redeliveries was requeued anyway")
    run.check(recoverer.redis_client.llen(QUEUE) == 0, "the dead-lettered job is still on the queue")
    run.check(recoverer.redis_client.llen(recoverer.dead_letter_key) == 1,
              "the dead-letter list is empty")
    run.check(bool(failures) and failures[0][0] == "d1", "the dead-letter hook was not called")
    run.check("giving up" in failures[0][1].lower(), f"the dead-letter reason is vague: {failures[0][1]}")

    run.see(dead_lettered=stats.get("dead_lettered"), reason=failures[0][1][:80],
            dead_letter_list=1, queue=0)
    run.note("attempts=2 with max_redeliveries=2 → dead letter, empty queue, named reason")
    return (f"past max_redeliveries → dead letter with reason {failures[0][1]!r}; queue empty, no "
            "requeue",
            "the dead-letter list is not drained by anything here: a job there needs an operator, and "
            "nothing in this drill proves someone is told")


def drill_recovery(run: Run) -> tuple[str, str | None]:
    """After a crash the job is picked up and finished by the next consumer."""
    import fakeredis

    server = fakeredis.FakeServer()
    crashed = _consumer(server, "crashed")
    crashed.enqueue(_payload("rec1"))
    job = crashed._pop()
    run.check(job is not None, "the recovery drill could not claim its job")
    crashed.redis_client.delete(crashed.lease_key)  # killed mid-run

    survivor = _consumer(server, "survivor")
    survivor.recover_orphans()
    processed: list[str] = []

    def handler(delivered: Any) -> None:
        processed.append(delivered.job_id)
        # The real worker acks from its future's done-callback (worker/main.py);
        # the drill acks here so completion is observable without a pool.
        survivor.ack(delivered)
        survivor.stop()

    try:
        survivor.consume(handler=handler)
    except Exception as exc:  # noqa: BLE001 — consume must not raise for a normal shutdown
        raise Broken(f"recovery: the consumer raised on the recovered job: {exc}") from exc
    run.check(processed == ["rec1"], f"the survivor processed {processed}, expected ['rec1']")
    run.check(survivor.redis_client.llen(survivor.processing_key) == 0,
              "the survivor left the recovered job in its processing list")

    run.see(processed=processed, processing_after=0)
    run.note("killed consumer → survivor requeues, pops and completes the job")
    return ("a killed consumer's job is requeued and completed by the next consumer, leaving the "
            "processing list empty",
            "the crash is simulated by deleting the lease; the process is not actually killed here "
            "(scripts/queue_kill9_drill.py does that)")


def drill_concurrency(run: Run) -> tuple[str, str | None]:
    """Concurrency is bounded, and over-submission applies backpressure."""
    from worker.core.pool import WorkerPool

    class _Job:
        def __init__(self, job_id: str) -> None:
            self.job_id = job_id

    release = threading.Event()
    started = threading.Event()

    def handler(_job: Any) -> bool:
        started.set()
        release.wait(10)
        return True

    pool = WorkerPool(handler, max_workers=1, queue_limit=1)
    first = pool.submit(_Job("a"))
    run.check(started.wait(5), "the first job never started")
    second = pool.submit(_Job("b"))  # fills the queue allowance

    submitted: list[bool] = []
    third_thread = threading.Thread(
        target=lambda: (pool.submit(_Job("c")), submitted.append(True)), daemon=True)
    third_thread.start()
    third_thread.join(0.4)
    run.check(not submitted, "a submit past max_workers+queue_limit did not apply backpressure")
    run.check(third_thread.is_alive(), "the over-limit submit returned without a slot")

    release.set()
    third_thread.join(10)
    run.check(submitted, "the blocked submit never completed after capacity came back")
    for future in (first, second):
        future.result(timeout=10)
    pool.shutdown(wait=True)
    run.check(pool.futures == [], "the pool still holds admitted work after shutdown")

    run.see(max_workers=1, queue_limit=1, third_submit_blocked=True,
            third_submit_completed=True, admitted_after_shutdown=0)
    run.note("max_workers=1 + queue_limit=1: the third submit blocked until a slot freed, then ran")
    return ("max_workers=1 + queue_limit=1 → the third submit blocks until a slot frees, then runs; "
            "no admitted work is left behind",
            "backpressure is per worker process; there is no cross-worker admission budget in this "
            "drill, and a blocked submitter is not visible to an operator")


DRILLS: dict[str, Callable[[Run], tuple[str, str | None]]] = {
    "job_queue": drill_job_queue,
    "worker": drill_worker,
    "retry": drill_retry,
    "timeout": drill_timeout,
    "cancellation": drill_cancellation,
    "idempotency": drill_idempotency,
    "dead_letter": drill_dead_letter,
    "recovery": drill_recovery,
    "concurrency": drill_concurrency,
}

PROPERTIES: tuple[dict[str, str], ...] = (
    {"item": "job_queue", "promise": "a published job is delivered to exactly one consumer, "
                                     "and only dropped on acknowledgement"},
    {"item": "worker", "promise": "handlers run, concurrency honours max_workers, a failure "
                                  "does not leak a slot"},
    {"item": "retry", "promise": "a job lost with its worker is redelivered, with the attempt counted"},
    {"item": "timeout", "promise": "a job that stops progressing is timed out, not stuck forever"},
    {"item": "cancellation", "promise": "a cancelled job stops before its next stage runs"},
    {"item": "idempotency", "promise": "duplicate publication or delivery cannot execute twice"},
    {"item": "dead_letter", "promise": "past the retry budget a job is set aside with a reason"},
    {"item": "recovery", "promise": "after a crash the work is picked up and finished"},
    {"item": "concurrency", "promise": "admission is bounded and over-submission is refused or "
                                       "blocked"},
)


@dataclass
class Row:
    item: str
    promise: str
    verdict: str
    behavior: str = ""
    observations: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None
    limit: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"item": self.item, "promise": self.promise, "verdict": self.verdict,
                "behavior": self.behavior, "observations": self.observations,
                "reason": self.reason, "limit": self.limit}


def measure(only: list[str] | None = None) -> dict[str, Any]:
    """Run every contract drill and grade it. Never raises for a failing property."""
    wanted = set(only) if only else None
    rows: list[Row] = []
    for entry in PROPERTIES:
        item = entry["item"]
        if wanted is not None and item not in wanted:
            continue
        run = Run(item)
        drill = DRILLS.get(item)
        if drill is None:
            rows.append(Row(item=item, promise=entry["promise"], verdict=UNPROVEN,
                            reason="no drill exists for this property"))
            continue
        started = time.monotonic()
        try:
            behavior, limit = drill(run)
        except Broken as exc:
            rows.append(Row(item=item, promise=entry["promise"], verdict=BROKEN,
                            observations=run.observations, reason=str(exc)))
            continue
        except Unavailable as exc:
            rows.append(Row(item=item, promise=entry["promise"], verdict=UNPROVEN,
                            observations=run.observations, reason=str(exc)))
            continue
        except Exception as exc:  # noqa: BLE001 — a drill that cannot run is not a proof
            rows.append(Row(item=item, promise=entry["promise"], verdict=UNPROVEN,
                            observations=run.observations,
                            reason=f"drill could not execute: {type(exc).__name__}: {exc}"))
            continue
        elapsed = time.monotonic() - started
        run.observations.setdefault("drill_seconds", round(elapsed, 2))
        rows.append(Row(item=item, promise=entry["promise"], verdict=PROVEN, behavior=behavior,
                        observations=run.observations, limit=limit))

    counts = {PROVEN: 0, BROKEN: 0, UNPROVEN: 0}
    for row in rows:
        counts[row.verdict] += 1
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "properties": len(rows),
        "expected_properties": len(PROPERTIES),
        "proven": counts[PROVEN],
        "broken": counts[BROKEN],
        "unproven": counts[UNPROVEN],
        "complete": counts[PROVEN] == len(PROPERTIES) and len(rows) == len(PROPERTIES),
        "rows": [row.as_dict() for row in rows],
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# The job/worker contract — nine properties, each proven by a drill",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{report['proven']} proven / {report['broken']} broken / {report['unproven']} unproven "
        f"of {report['expected_properties']}**",
        "",
        "Each row runs the code that is supposed to provide the property. `PROVEN` means every check "
        "passed; `UNPROVEN` means the drill could not run here and is **not** a pass.",
        "",
        "| Property | Promise | Observed | Verdict |",
        "|---|---|---|---|",
    ]
    icons = {PROVEN: "**PROVEN**", BROKEN: "**BROKEN**", UNPROVEN: "**UNPROVEN**"}
    for row in report["rows"]:
        # A non-PROVEN row must show why, even if it also recorded behaviour.
        observed = (row["reason"] or row["behavior"] or "—") if row["verdict"] != PROVEN \
            else (row["behavior"] or "—")
        lines.append(f"| `{row['item']}` | {row['promise']} | "
                     f"{str(observed).replace('|', '/')} | {icons.get(row['verdict'], row['verdict'])} |")

    if report["broken"]:
        lines += ["", "## Broken", ""]
        lines += [f"- `{row['item']}`: {row['reason']}" for row in report["rows"]
                  if row["verdict"] == BROKEN]
    if report["unproven"]:
        lines += ["", "## Unproven — not passes", ""]
        lines += [f"- `{row['item']}`: {row['reason']}" for row in report["rows"]
                  if row["verdict"] == UNPROVEN]

    lines += ["", "## What this does not prove", ""]
    limits = [(row["item"], row["limit"]) for row in report["rows"] if row.get("limit")]
    for item, limit in limits:
        lines.append(f"- `{item}`: {limit}")
    lines += [
        "",
        "And across all nine: this is one process, one SQLite database and fakeredis. It does not "
        "prove behaviour under a real Redis restart, a PostgreSQL failover, a queue backlog of "
        "thousands, or two workers racing on the same row. Those need the bank-host drills "
        "(`queue_kill9_drill.py`, `worker_dispatch_drill.py`, `postgres_drill.py`) and a load run.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="The job/worker contract, measured.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--only", help="comma-separated properties to run")
    parser.add_argument("--min-proven", type=int, default=0,
                        help="exit non-zero when fewer than this many properties are PROVEN")
    args = parser.parse_args(argv)

    only = [item.strip() for item in args.only.split(",") if item.strip()] if args.only else None
    report = measure(only)

    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            print(f"{row['verdict']:<9} {row['item']:<15} "
                  f"{(row['behavior'] or row['reason'] or '')[:90]}")
        print(f"\n{report['proven']} proven / {report['broken']} broken / "
              f"{report['unproven']} unproven of {report['expected_properties']}")
    return 0 if report["proven"] >= args.min_proven else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
