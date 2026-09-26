"""Job path hardening: at-least-once dequeue, orphan recovery, dead-lettering, DB reaper."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

fakeredis = pytest.importorskip("fakeredis")

from worker.core.job_consumer import JobConsumer, ScanJob
from worker.core.job_reaper import fail_job, reap_stale_jobs

Q = "cryptoscan:test:queue"


def _consumer(server, worker_id: str, **kw) -> JobConsumer:
    c = JobConsumer(redis_url="", queue_name=Q, poll_interval_seconds=1, worker_id=worker_id, **kw)
    c.redis_client = fakeredis.FakeRedis(server=server, decode_responses=True)
    c.redis_url = "redis://fake"
    return c


def _payload(job_id: str, **extra) -> dict:
    return {"job_id": job_id, "target_repo": "https://example/repo.git", "target_branch": "main", **extra}


def test_pop_moves_to_processing_and_ack_removes_it():
    server = fakeredis.FakeServer()
    c = _consumer(server, "w1")
    c.enqueue(_payload("j1"))
    job = c._pop()
    assert job is not None and job.job_id == "j1" and job.raw
    assert c.redis_client.llen(Q) == 0
    assert c.redis_client.llen(c.processing_key) == 1
    assert c.redis_client.exists(c.lease_key)  # heartbeat written on pop
    c.ack(job)
    assert c.redis_client.llen(c.processing_key) == 0


def test_orphans_of_a_dead_worker_are_requeued_but_live_workers_are_left_alone():
    server = fakeredis.FakeServer()
    dead = _consumer(server, "dead")
    live = _consumer(server, "live")
    dead.enqueue(_payload("j1"))
    live.enqueue(_payload("j2"))
    assert dead._pop().job_id == "j1"
    assert live._pop().job_id == "j2"
    dead.redis_client.delete(dead.lease_key)  # the lease expired: worker crashed

    recoverer = _consumer(server, "new")
    stats = recoverer.recover_orphans()
    assert stats == {"requeued": 1, "dead_lettered": 0, "workers": 1}
    assert recoverer.redis_client.llen(dead.processing_key) == 0
    assert recoverer.redis_client.llen(live.processing_key) == 1  # still in flight on the live worker
    requeued = recoverer._pop()
    assert requeued.job_id == "j1" and requeued.attempts == 1


def test_dead_letter_after_max_redeliveries():
    server = fakeredis.FakeServer()
    failed: list[tuple[str, str]] = []
    crasher = _consumer(server, "crash")
    crasher.enqueue(_payload("j1", _attempts=2))
    crasher._pop()
    crasher.redis_client.delete(crasher.lease_key)
    recoverer = _consumer(server, "new", max_redeliveries=2, on_dead_letter=lambda p, r: failed.append((p["job_id"], r)))
    stats = recoverer.recover_orphans()
    assert stats["dead_lettered"] == 1 and stats["requeued"] == 0
    assert recoverer.redis_client.llen(Q) == 0
    assert recoverer.redis_client.llen(recoverer.dead_letter_key) == 1
    assert failed and failed[0][0] == "j1" and "giving up" in failed[0][1]


def test_queued_job_ids_sees_queue_and_processing_lists():
    server = fakeredis.FakeServer()
    a = _consumer(server, "a")
    a.enqueue(_payload("j1"))
    a.enqueue(_payload("j2"))
    a._pop()
    assert a.queued_job_ids() == {"j1", "j2"}


def test_handler_exception_acks_so_the_job_is_not_redelivered_forever():
    server = fakeredis.FakeServer()
    c = _consumer(server, "w")
    c.enqueue(_payload("j1"))
    calls = []

    def handler(job):
        calls.append(job.job_id)
        c.stop()
        raise RuntimeError("boom")

    c.consume(handler=handler)
    assert calls == ["j1"]
    assert c.redis_client.llen(c.processing_key) == 0


# ------------------------------------------------------------------ DB reaper
def _job(session, status: str, age: timedelta, progress=None):
    from db.repositories.job_repository import JobRepository

    job = JobRepository(session).create_job(job_type="MANUAL", target_repo="https://example/r.git", target_branch="main", triggered_by="t")
    job.status = status
    job.progress = progress
    session.flush()
    stamp = datetime.now(timezone.utc) - age
    job.created_at = stamp
    job.updated_at = stamp
    session.flush()
    session.commit()
    return job.id


def test_reaper_fails_running_without_progress_and_leaves_fresh_alone(test_db):
    stale = _job(test_db, "RUNNING", timedelta(hours=3))
    fresh = _job(test_db, "RUNNING", timedelta(minutes=5))
    stats = reap_stale_jobs(test_db, queued_ids=set(), publish=lambda p: None, running_timeout=timedelta(minutes=90))
    assert stats["failed_running"] == 1
    from db.models.scan_job import ScanJob

    assert test_db.get(ScanJob, stale).status == "FAILED"
    assert "worker lost" in test_db.get(ScanJob, stale).error_message
    assert test_db.get(ScanJob, fresh).status == "RUNNING"


def test_reaper_republishes_lost_queued_then_fails_after_max(test_db):
    from db.models.scan_job import ScanJob

    lost = _job(test_db, "QUEUED", timedelta(minutes=30))
    visible = _job(test_db, "QUEUED", timedelta(minutes=30))
    published: list[dict] = []
    stats = reap_stale_jobs(test_db, queued_ids={visible}, publish=published.append, queued_timeout=timedelta(minutes=10), max_requeues=1)
    assert stats == {"failed_running": 0, "requeued": 1, "failed_queued": 0}
    assert published[0]["job_id"] == lost and published[0]["progress"]["requeued"] == 1
    assert test_db.get(ScanJob, visible).status == "QUEUED"
    # second sweep, still missing from Redis and past the timeout → give up
    row = test_db.get(ScanJob, lost)
    row.updated_at = datetime.now(timezone.utc) - timedelta(minutes=30)
    test_db.commit()
    stats = reap_stale_jobs(test_db, queued_ids={visible}, publish=published.append, queued_timeout=timedelta(minutes=10), max_requeues=1)
    assert stats["failed_queued"] == 1 and len(published) == 1
    assert test_db.get(ScanJob, lost).status == "FAILED"


def test_reaper_without_redis_visibility_never_touches_queued(test_db):
    from db.models.scan_job import ScanJob

    q = _job(test_db, "QUEUED", timedelta(hours=5))
    stats = reap_stale_jobs(test_db, queued_ids=None, publish=None)
    assert stats["requeued"] == 0 and stats["failed_queued"] == 0
    assert test_db.get(ScanJob, q).status == "QUEUED"


def test_fail_job_marks_row_failed(test_db):
    from db.models.scan_job import ScanJob

    j = _job(test_db, "QUEUED", timedelta(minutes=1))
    fail_job(test_db, j, "dead-lettered")
    assert test_db.get(ScanJob, j).status == "FAILED"
