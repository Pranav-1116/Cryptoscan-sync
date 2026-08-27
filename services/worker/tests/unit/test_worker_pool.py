"""WorkerPool concurrency tests."""

from __future__ import annotations

import threading
import time

from worker.core.job_consumer import ScanJob
from worker.core.pool import WorkerPool


def _job(n: int) -> ScanJob:
    return ScanJob(job_id=f"job-{n}", target_repo=f"local://demo/repo-{n}")


def test_jobs_run_concurrently():
    active = 0
    peak = 0
    lock = threading.Lock()

    def handler(job: ScanJob):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.25)
        with lock:
            active -= 1

    pool = WorkerPool(handler=handler, max_workers=4)
    for i in range(4):
        pool.submit(_job(i))
    pool.wait()
    pool.shutdown(wait=True)

    assert pool.stats.completed == 4
    assert pool.stats.failed == 0
    assert peak >= 2, f"expected overlapping execution, peak={peak}"


def test_failures_are_counted_not_fatal():
    def handler(job: ScanJob):
        if job.job_id.endswith("-bad"):
            raise RuntimeError("boom")

    pool = WorkerPool(handler=handler, max_workers=2)
    pool.submit(_job(1))
    bad = ScanJob(job_id="job-9-bad", target_repo="x://y")
    pool.submit(bad)
    pool.wait()
    pool.shutdown(wait=True)

    assert pool.stats.completed == 2
    assert pool.stats.failed == 1


def test_backpressure_semaphore_blocks_when_queue_full():
    release = threading.Event()

    def handler(job: ScanJob):
        release.wait(timeout=5)

    pool = WorkerPool(handler=handler, max_workers=1, queue_limit=0)
    pool.submit(_job(1))  # occupies the single worker
    # With queue_limit=0 the pool only allows max_workers in flight; the
    # acquire below must block until the first job finishes.
    stalled = threading.Event()

    def try_submit():
        pool.submit(_job(2))
        stalled.set()

    t = threading.Thread(target=try_submit, daemon=True)
    t.start()
    time.sleep(0.15)
    assert not stalled.is_set(), "submit should have applied backpressure"
    release.set()
    t.join(timeout=5)
    assert stalled.is_set()
    pool.shutdown(wait=True)
    assert pool.stats.submitted == 2


def test_shutdown_is_graceful():
    started = threading.Event()

    def handler(job: ScanJob):
        started.set()
        time.sleep(0.2)

    pool = WorkerPool(handler=handler, max_workers=1)
    pool.submit(_job(1))
    started.wait(timeout=5)
    pool.shutdown(wait=True)
    assert pool.stats.completed == 1
