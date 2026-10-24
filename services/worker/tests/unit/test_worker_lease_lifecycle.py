"""Transport leases must outlive polling, backpressure and graceful draining.

FakeRedis tests exercise lifecycle wiring, not process-death/Redis durability.
The real Redis dispatch drill covers the same graceful-drain boundary.
"""
import signal
import threading
import time

import fakeredis
import pytest

from worker.config.settings import Settings
from worker.core.job_consumer import JobConsumer
from worker.main import Worker


def test_graceful_shutdown_keeps_processing_lease_until_executor_finishes(monkeypatch):
    server = fakeredis.FakeServer()
    entered, release = threading.Event(), threading.Event()
    errors = []

    class Consumer(JobConsumer):
        def __init__(self, **kwargs):
            super().__init__(**{**kwargs, "redis_url": "", "poll_interval_seconds": 1,
                                "lease_ttl_seconds": 3})
            self.redis_client = fakeredis.FakeRedis(server=server, decode_responses=True)

        def maintenance_due(self):
            return False  # isolate transport lifecycle from SQL maintenance

    class Executor:
        def execute(self, job):
            entered.set()
            assert release.wait(12)
            return True

    monkeypatch.setattr("db.connection.session.init_db", lambda: None)
    monkeypatch.setattr("worker.main.JobConsumer", Consumer)
    monkeypatch.setattr("worker.main.JobExecutor", Executor)
    monkeypatch.setattr("worker.main.signal.signal", lambda *args: None)
    client = fakeredis.FakeRedis(server=server, decode_responses=True)
    queue = "test:lease:drain"
    client.rpush(queue, '{"job_id":"synthetic","target_repo":"/synthetic"}')
    worker = Worker(Settings(SCAN_JOB_QUEUE_KEY=queue, MAX_CONCURRENT_JOBS=1))

    def run():
        try:
            worker.run()
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert entered.wait(5)
        worker.signal_handler(signal.SIGTERM, None)
        # Polling stops, but the in-flight executor still owns its delivery.
        time.sleep(worker.consumer.lease_ttl_seconds + 0.4)
        assert thread.is_alive()
        assert client.exists(worker.consumer.lease_key), "draining worker lost its transport lease"
        observer = Consumer(queue_name=queue)
        assert observer.recover_orphans()["requeued"] == 0
        assert client.llen(worker.consumer.processing_key) == 1
    finally:
        release.set()
        thread.join(6)
    assert not thread.is_alive() and not errors
    assert client.llen(worker.consumer.processing_key) == 0
    assert worker.pool.stats.completed == 1


def test_lease_keeper_renews_while_caller_is_blocked_and_stops_on_exception():
    consumer = JobConsumer(poll_interval_seconds=1, lease_ttl_seconds=3)
    consumer.redis_client = fakeredis.FakeRedis(decode_responses=True)
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        with consumer.maintain_lease():
            time.sleep(consumer.lease_ttl_seconds + 0.4)
            assert consumer.redis_client.exists(consumer.lease_key)
            raise RuntimeError("synthetic interruption")
    # Once ownership ends no thread may keep an abandoned worker alive.
    time.sleep(consumer.lease_ttl_seconds + 0.4)
    assert not consumer.redis_client.exists(consumer.lease_key)


def test_lease_keeper_handles_memory_backend_and_failed_renewal(monkeypatch):
    consumer = JobConsumer(poll_interval_seconds=1, lease_ttl_seconds=3)
    with consumer.maintain_lease():
        assert consumer.redis_client is None
    client = fakeredis.FakeRedis(decode_responses=True)
    consumer.redis_client = client
    renewed = threading.Event()
    original_set = client.set
    calls = 0

    def transient_outage(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("synthetic renewal outage")
        result = original_set(*args, **kwargs)
        renewed.set()
        return result

    monkeypatch.setattr(client, "set", transient_outage)
    with consumer.maintain_lease():
        assert renewed.wait(2), "A failed heartbeat killed lease renewal"
        assert client.exists(consumer.lease_key)
