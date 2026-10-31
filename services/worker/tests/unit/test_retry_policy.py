"""Retry after failure: transient failures come back, permanent ones do not.

The gap this closes was not "no retry code" — the queue already redelivered work
lost with a dead worker. It was that a handler *failure* was logged, reported
False and acked, so a connection reset and a malformed payload had the same
outcome: one lost observation. These tests pin the distinction.
"""

from __future__ import annotations

import random

import fakeredis
import pytest

from worker.core import retry_policy
from worker.core.job_consumer import JobConsumer, ScanJob

QUEUE = "cryptoscan:test:retry"


def _consumer(server=None, worker_id: str = "w1", **kwargs) -> JobConsumer:
    consumer = JobConsumer(redis_url="", queue_name=QUEUE, poll_interval_seconds=1,
                           worker_id=worker_id, allow_memory_fallback=True, **kwargs)
    if server is not None:
        consumer.redis_client = fakeredis.FakeRedis(server=server, decode_responses=True)
        consumer.redis_url = "redis://fake"
    return consumer


def _job(**overrides) -> ScanJob:
    data = {"job_id": "j1", "target_repo": "https://example/repo.git", "target_branch": "main",
            "triggered_by": "t", "job_type": "MANUAL", "tenant_id": "tenant-a", "progress": {}}
    data.update(overrides)
    return ScanJob(**data)


# ---------------------------------------------------------------- classification --- #
@pytest.mark.parametrize("exc", [ConnectionResetError("reset"), TimeoutError("timed out"),
                                 BlockingIOError("again")])
def test_transport_failures_are_retryable(exc):
    retryable, why = retry_policy.classify(exc)
    assert retryable is True, why


@pytest.mark.parametrize("exc", [ValueError("bad payload"), KeyError("missing"), TypeError("x"),
                                 FileNotFoundError("gone"), PermissionError("denied")])
def test_permanent_failures_are_not_retried(exc):
    retryable, why = retry_policy.classify(exc)
    assert retryable is False, why


def test_an_unrecognised_exception_is_terminal_not_retried_blindly():
    class Strange(Exception):
        pass

    retryable, why = retry_policy.classify(Strange("nobody knows"))
    assert retryable is False
    assert "unrecognised" in why


def test_a_sqlalchemy_syntax_error_is_not_treated_as_transient():
    """OperationalError covers both 'connection died' and 'your SQL is wrong'."""
    from sqlalchemy.exc import OperationalError

    syntax = OperationalError("SELECT", {}, Exception("syntax error at or near"))
    assert retry_policy.classify(syntax)[0] is False
    dropped = OperationalError("SELECT", {}, Exception("server closed the connection unexpectedly"))
    assert retry_policy.classify(dropped)[0] is True


# ---------------------------------------------------------------------- backoff --- #
def test_backoff_grows_geometrically_and_is_capped():
    delays = [retry_policy.backoff_seconds(attempt, base=10, cap=60, jitter=0.0)
              for attempt in (1, 2, 3, 4)]
    assert delays[0] == 10 and delays[1] == 20 and delays[2] == 40
    assert delays[3] == 60, "the cap must hold"
    assert delays == sorted(delays)


def test_jitter_stays_within_bounds_and_never_exceeds_the_cap():
    rng = random.Random(7)
    values = [retry_policy.backoff_seconds(3, base=10, cap=45, jitter=0.25, rng=rng)
              for _ in range(50)]
    assert all(30.0 <= value <= 40.0 for value in values), (min(values), max(values))
    assert len(set(values)) > 1, "jitter must actually vary the delay"


# --------------------------------------------------------------------- decisions --- #
def test_a_transient_failure_is_scheduled_for_retry():
    decision = retry_policy.decide(exc=ConnectionError("reset"), attempt=0, max_attempts=3)
    assert decision.action == retry_policy.RETRY
    assert decision.delay_seconds > 0
    assert decision.attempt == 1


def test_exhausted_attempts_dead_letter_instead_of_retrying_forever():
    decision = retry_policy.decide(exc=ConnectionError("reset"), attempt=2, max_attempts=3)
    assert decision.action == retry_policy.DEAD_LETTER
    assert "giving up after 3 attempts" in decision.reason


def test_a_permanent_failure_is_not_delayed_by_a_useless_retry():
    decision = retry_policy.decide(exc=ValueError("bad"), attempt=0, max_attempts=3)
    assert decision.action == retry_policy.DEAD_LETTER
    assert decision.delay_seconds == 0.0


def test_controlled_execution_is_never_retried_here():
    decision = retry_policy.decide(exc=ConnectionError("reset"), attempt=0, controlled=True)
    assert decision.action == retry_policy.NEVER
    assert "operator must reconcile" in decision.reason


def test_controlled_jobs_left_alone_even_after_a_transient_failure():
    consumer = _consumer()
    job = _job(progress={"execution_control": {"approval_id": "a1"}})
    decision = retry_policy.handle_failure(consumer=consumer, job=job,
                                           exc=ConnectionError("reset"))
    assert decision.action == retry_policy.NEVER
    assert consumer.redis_client is None  # nothing was scheduled anywhere


# ------------------------------------------------------------------ the queue --- #
def test_a_retry_is_scheduled_for_later_not_immediately():
    server = fakeredis.FakeServer()
    consumer = _consumer(server)
    scheduled = consumer.enqueue_delayed({"job_id": "j1"}, 60)
    assert scheduled is True
    assert consumer.redis_client.llen(QUEUE) == 0
    assert consumer.redis_client.zcard(consumer.retry_key) == 1
    assert consumer.promote_due() == 0, "a retry must not run before its backoff elapses"
    assert consumer.redis_client.llen(QUEUE) == 0


def test_a_due_retry_is_promoted_to_the_queue_once():
    server = fakeredis.FakeServer()
    consumer = _consumer(server)
    consumer.enqueue_delayed({"job_id": "j1", "target_repo": "https://example/r.git",
                              "target_branch": "main", "_attempts": 1}, 30)
    assert consumer.promote_due(now=10**12) == 1
    assert consumer.redis_client.zcard(consumer.retry_key) == 0
    assert consumer.redis_client.llen(QUEUE) == 1
    assert consumer.promote_due(now=10**12) == 0, "a promoted retry must not be promoted twice"
    job = consumer._pop()
    assert job is not None and job.job_id == "j1" and job.attempts == 1


def test_two_workers_promoting_the_same_retry_deliver_it_once():
    server = fakeredis.FakeServer()
    first = _consumer(server, worker_id="a")
    second = _consumer(server, worker_id="b")
    first.enqueue_delayed({"job_id": "j1"}, 1)
    promoted = first.promote_due(now=10**12) + second.promote_due(now=10**12)
    assert promoted == 1
    assert first.redis_client.llen(QUEUE) == 1


def test_a_delayed_retry_is_visible_to_queued_job_ids():
    """The DB reaper must not republish a job that is only waiting out a backoff."""
    server = fakeredis.FakeServer()
    consumer = _consumer(server)
    consumer.enqueue_delayed({"job_id": "j1"}, 3600)
    assert consumer.queued_job_ids() == {"j1"}


def test_the_retry_payload_keeps_fields_the_worker_does_not_read():
    """The retry re-publishes the exact payload Redis holds, not a reconstruction.

    Deliberately redis-backed: the in-process memory queue is module-global, and
    a test that pushes into it leaks work into every later test in the session.
    """
    consumer = _consumer(fakeredis.FakeServer())
    consumer.enqueue({"job_id": "j1", "target_repo": "r", "target_branch": "main",
                      "custom_field": "carry me", "_attempts": 0})
    job = consumer._pop()
    assert job is not None
    payload = retry_policy.retry_payload(job)
    assert payload["custom_field"] == "carry me"


def test_a_retry_failure_is_dead_lettered_and_reports_why():
    server = fakeredis.FakeServer()
    consumer = _consumer(server)
    failed: list[tuple[str, str]] = []
    consumer.on_dead_letter = lambda payload, reason: failed.append((payload["job_id"], reason))

    class _Boom:
        job_id = "j1"
        raw = None
        attempts = 2
        target_repo = "r"
        target_branch = "main"
        triggered_by = "t"
        progress = {}
        scan_id = None
        target_commit = None
        job_type = "MANUAL"
        system_id = None
        tenant_id = "tenant-a"

    rows: list[tuple[str, str]] = []
    decision = retry_policy.handle_failure(consumer=consumer, job=_Boom(),
                                           exc=TimeoutError("slow"), max_attempts=3,
                                           fail_row=lambda job_id, reason: rows.append((job_id, reason)))
    assert decision.action == retry_policy.DEAD_LETTER
    assert consumer.redis_client.llen(consumer.dead_letter_key) == 1
    assert rows and rows[0][0] == "j1"
    assert failed and failed[0][0] == "j1"


def test_the_pool_calls_the_failure_hook_and_still_releases_the_slot():
    from worker.core.pool import WorkerPool

    seen: list[tuple[str, type]] = []
    released = []

    def handler(job):
        released.append(job.job_id)
        raise ConnectionResetError("peer went away")

    class _Job:
        def __init__(self, job_id: str) -> None:
            self.job_id = job_id

    pool = WorkerPool(handler, max_workers=1,
                      on_failure=lambda job, exc: seen.append((job.job_id, type(exc))))
    future = pool.submit(_Job("j1"))
    assert future.result(timeout=10) is False
    assert seen == [("j1", ConnectionResetError)]
    assert released == ["j1"]
    # the slot is free: a second submit still runs
    assert pool.submit(_Job("j2")).result(timeout=10) is False
    pool.shutdown(wait=True)


def test_a_raising_failure_hook_cannot_crash_the_worker():
    from worker.core.pool import WorkerPool

    class _Job:
        job_id = "j1"

    def handler(_job):
        raise ConnectionError("reset")

    def hook(_job, _exc):
        raise RuntimeError("the retry scheduler itself is broken")

    pool = WorkerPool(handler, max_workers=1, on_failure=hook)
    assert pool.submit(_Job()).result(timeout=10) is False
    pool.shutdown(wait=True)
