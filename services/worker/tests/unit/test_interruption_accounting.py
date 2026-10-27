"""Thread interruption must release local backpressure, not imply external stop."""
import asyncio
from queue import Queue
from unittest.mock import Mock

import pytest

from worker.core import job_consumer
from worker.core.job_consumer import JobConsumer, ScanJob
from worker.core.pool import WorkerPool


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_interrupted_future_leaves_pool_accounting_and_capacity_usable(interruption):
    def handler(job):
        if job.job_id == "interrupted":
            raise interruption("synthetic interruption")
        return True

    pool = WorkerPool(handler=handler, max_workers=1, queue_limit=0)
    try:
        future = pool.submit(ScanJob(job_id="interrupted", target_repo="local://fixture"))
        with pytest.raises(interruption):
            future.result(timeout=3)
        assert pool.stats.active == 0
        assert pool.stats.completed == 1 and pool.stats.failed == 1
        assert not pool.saturated
        assert pool.submit(ScanJob(job_id="next", target_repo="local://fixture")).result(timeout=3)
        assert pool.stats.completed == 2 and pool.stats.failed == 1
    finally:
        pool.shutdown(wait=True)


@pytest.mark.parametrize("fault", ["publish-error", "missing-client"])
def test_no_memory_success_for_durable_queue_publish_failure(monkeypatch, fault, caplog):
    memory = Queue()
    monkeypatch.setattr(job_consumer, "_MEMORY_QUEUE", memory)
    client = Mock()
    client.rpush.side_effect = OSError("redis-credential-canary")
    monkeypatch.setattr(JobConsumer, "_connect_redis", lambda self: setattr(
        self, "redis_client", client if fault == "publish-error" else None))
    consumer = JobConsumer(redis_url="rediss://test.invalid", allow_memory_fallback=False)
    with pytest.raises(RuntimeError, match="memory fallback is disabled"):
        consumer.enqueue({"job_id": "job"})
    assert memory.empty()
    assert "redis-credential-canary" not in caplog.text
    assert all("redis-credential-canary" not in str(record.__dict__) for record in caplog.records)


def test_development_queue_retains_explicitly_allowed_fallback(monkeypatch):
    memory = Queue()
    monkeypatch.setattr(job_consumer, "_MEMORY_QUEUE", memory)
    client = Mock()
    client.rpush.side_effect = OSError("synthetic transport outage")
    monkeypatch.setattr(JobConsumer, "_connect_redis", lambda self: setattr(self, "redis_client", client))
    consumer = JobConsumer(redis_url="redis://test.invalid", allow_memory_fallback=True)
    consumer.enqueue({"job_id": "job"})
    assert '"job_id": "job"' in memory.get_nowait()


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_interrupted_submission_returns_its_semaphore_slot(monkeypatch, interruption):
    pool = WorkerPool(handler=lambda job: True, max_workers=1, queue_limit=0)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(pool._executor, "submit", Mock(side_effect=interruption("submission interrupted")))
            with pytest.raises(interruption):
                pool.submit(ScanJob(job_id="not-submitted", target_repo="local://fixture"))
        assert pool._semaphore.acquire(blocking=False), "Interrupted submission leaked local capacity"
        pool._semaphore.release()
        assert pool.submit(ScanJob(job_id="next", target_repo="local://fixture")).result(timeout=3)
        assert pool.stats.submitted == pool.stats.completed == 1
    finally:
        pool.shutdown(wait=True)


@pytest.mark.parametrize("fault", ["startup", "publish"])
def test_configured_redis_publish_helper_never_accepts_a_memory_delivery(monkeypatch, fault):
    memory = Queue()
    monkeypatch.setattr(job_consumer, "_MEMORY_QUEUE", memory)
    client = Mock()
    if fault == "startup":
        client.ping.side_effect = OSError("synthetic unavailable transport")
    else:
        client.rpush.side_effect = OSError("synthetic unavailable transport")
    monkeypatch.setattr("shared_models.redis_connection.verified_redis_client", lambda *a, **kw: client)
    with pytest.raises(RuntimeError, match="memory fallback is disabled"):
        job_consumer.enqueue_job({"job_id": "synthetic"}, redis_url="redis://synthetic.invalid")
    assert memory.empty()
