"""Long-lived pools must bound owned futures and release cancelled admissions."""
import threading
from concurrent.futures import CancelledError

import pytest

from worker.core.job_consumer import ScanJob
from worker.core.pool import WorkerPool


def job(number):
    return ScanJob(job_id=f"synthetic-{number}", target_repo="local://synthetic")


def test_completed_futures_are_not_retained_across_batches():
    pool = WorkerPool(handler=lambda descriptor: True, max_workers=2, queue_limit=4)
    try:
        # Repeat without recreating the pool, like a long-running worker.
        for batch in range(8):
            for number in range(128):
                pool.submit(job(batch * 128 + number))
            pool.wait()
            assert len(pool.futures) <= 6, "Completed futures accumulate in the long-lived worker"
    finally:
        pool.shutdown(wait=True)
    assert not pool.futures
    assert pool.stats.completed == pool.stats.submitted == 1024
    assert pool.stats.failed == pool.stats.active == 0


def test_cancelled_queued_future_returns_its_capacity_without_running():
    entered, release = threading.Event(), threading.Event()
    ran = []

    def handler(descriptor):
        ran.append(descriptor.job_id)
        entered.set()
        assert release.wait(8)
        return True

    pool = WorkerPool(handler=handler, max_workers=1, queue_limit=1)
    try:
        running = pool.submit(job(0))
        assert entered.wait(3)
        cancelled = pool.submit(job(1))
        assert cancelled.cancel()
        with pytest.raises(CancelledError):
            cancelled.result()
        # Cancelled work still occupies an internal queue entry until consumed.
        # Freeing this slot immediately would allow unbounded cancelled items.
        assert not pool._semaphore.acquire(blocking=False)
        assert cancelled in pool.futures and running in pool.futures
        assert ran == ["synthetic-0"]
        release.set()
        assert running.result(timeout=3)
        pool.wait()  # must drain the cancelled wrapper, not just public results
        assert pool.submit(job(2)).result(timeout=3)
    finally:
        release.set()
        pool.shutdown(wait=True)
    assert not pool.futures
    assert ran == ["synthetic-0", "synthetic-2"]
    assert pool.stats.submitted == pool.stats.completed == 2
    assert pool._semaphore.acquire(blocking=False)
    assert pool._semaphore.acquire(blocking=False), "Cancellation permanently leaked an admission slot"


def test_snapshot_cannot_mutate_pool_tracking():
    release = threading.Event()
    pool = WorkerPool(handler=lambda descriptor: release.wait(5), max_workers=1, queue_limit=0)
    try:
        future = pool.submit(job(0))
        snapshot = pool.futures
        snapshot.clear()
        assert future in pool.futures
    finally:
        release.set()
        pool.shutdown(wait=True)
    assert not pool.futures


@pytest.mark.parametrize("queue_limit", [-1, -10])
def test_negative_queue_limits_are_rejected_instead_of_stalling(queue_limit):
    with pytest.raises(ValueError, match="queue_limit"):
        pool = WorkerPool(handler=lambda descriptor: True, max_workers=1, queue_limit=queue_limit)
        pool.shutdown(wait=True)


def test_raising_done_callback_does_not_leak_pool_capacity():
    release = threading.Event()
    pool = WorkerPool(handler=lambda descriptor: release.wait(5), max_workers=1, queue_limit=0)
    try:
        future = pool.submit(job(0))

        def bad_callback(done):
            raise RuntimeError("synthetic acknowledgement observer failure")

        future.add_done_callback(bad_callback)
        release.set()
        assert future.result(timeout=3)
        pool.wait()
        assert pool.submit(job(1)).result(timeout=3)
    finally:
        release.set()
        pool.shutdown(wait=True)
    assert not pool.futures
    assert pool.stats.completed == 2


def test_concurrent_submitters_never_exceed_bookkeeping_budget():
    from concurrent.futures import ThreadPoolExecutor

    pool = WorkerPool(handler=lambda descriptor: True, max_workers=2, queue_limit=4)
    errors = []

    def submit_batch(batch):
        for number in range(128):
            future = pool.submit(job(batch * 128 + number))
            if len(pool.futures) > 6:
                errors.append("bookkeeping exceeded the admission budget")
            assert future.result(timeout=5)

    try:
        with ThreadPoolExecutor(max_workers=8) as producers:
            list(producers.map(submit_batch, range(8)))
    finally:
        pool.shutdown(wait=True)
    assert not errors and not pool.futures
    assert pool.stats.submitted == pool.stats.completed == 1024
    assert pool.stats.max_active <= 2


@pytest.mark.parametrize("outcome", ["success", "refusal", "error", "interruption"])
def test_pool_does_not_keep_terminal_future_or_its_exception_alive(outcome, monkeypatch):
    import gc
    import weakref

    # Pytest's logging capture deliberately retains exception tracebacks and
    # their frames. Measure pool ownership, not that external capture buffer.
    monkeypatch.setattr("worker.core.pool.logger.disabled", True)

    def handler(descriptor):
        if outcome == "error":
            raise RuntimeError("synthetic job failure")
        if outcome == "interruption":
            raise SystemExit("synthetic job interruption")
        return outcome == "success"

    pool = WorkerPool(handler=handler, max_workers=1, queue_limit=0)
    try:
        future = pool.submit(job(0))
        reference = weakref.ref(future)
        if outcome == "interruption":
            with pytest.raises(SystemExit):
                future.result(timeout=3)
        else:
            assert future.result(timeout=3) is (outcome == "success")
        del future
    finally:
        pool.shutdown(wait=True)
    gc.collect()
    assert reference() is None, "Pool retained a terminal Future/exception graph"
    assert not pool.futures
    assert pool.stats.completed == 1
    assert pool.stats.failed == int(outcome != "success")


def test_shutdown_refuses_a_submitter_already_waiting_for_capacity(monkeypatch):
    entered, release, acquiring = threading.Event(), threading.Event(), threading.Event()
    failures = []

    def handler(descriptor):
        entered.set()
        assert release.wait(8)
        return True

    pool = WorkerPool(handler=handler, max_workers=1, queue_limit=0)
    pool.submit(job(0))
    assert entered.wait(3)
    acquire = pool._semaphore.acquire

    def observed_acquire(*args, **kwargs):
        acquiring.set()
        return acquire(*args, **kwargs)

    monkeypatch.setattr(pool._semaphore, "acquire", observed_acquire)

    def blocked_submitter():
        try:
            pool.submit(job(1))
        except RuntimeError as exc:
            failures.append(str(exc))

    submitter = threading.Thread(target=blocked_submitter)
    shutdown = threading.Thread(target=pool.shutdown)
    submitter.start()
    try:
        assert acquiring.wait(3)
        shutdown.start()
        assert pool._shutdown.wait(3)
    finally:
        release.set()
        submitter.join(4)
        if shutdown.ident is not None:
            shutdown.join(4)
        pool.shutdown(wait=True)
    assert not submitter.is_alive() and not shutdown.is_alive()
    assert failures == ["pool is shut down"]
    assert pool.stats.submitted == pool.stats.completed == 1
    assert not pool.futures
    assert pool._semaphore.acquire(blocking=False), "Refused submitter leaked its acquired slot"


@pytest.mark.parametrize("arguments", [
    ["--batches", "0"], ["--batch-size", "0"], ["--workers", "0"], ["--queue-limit", "-1"],
])
def test_lifecycle_witness_rejects_invalid_limits_before_writing_report(tmp_path, arguments):
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[4]
    output = tmp_path / "should-not-exist.json"
    result = subprocess.run([sys.executable, str(root / "scripts/worker_pool_soak.py"),
                             "--report", str(output), *arguments], cwd=root, text=True,
                            capture_output=True, timeout=20)
    assert result.returncode == 2 and not output.exists()


def test_lifecycle_witness_runs_in_a_fresh_process(tmp_path):
    import json
    from pathlib import Path
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[4]
    output = tmp_path / "synthetic.json"
    result = subprocess.run([sys.executable, str(root / "scripts/worker_pool_soak.py"),
                             "--report", str(output), "--batches", "2", "--batch-size", "32",
                             "--workers", "1", "--queue-limit", "2"], cwd=root,
                            text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_text())
    assert report["completed_jobs"] == report["completion_callbacks"] == 64
    assert report["observed_peak_owned_futures"] <= 3
    assert report["owned_futures_after_shutdown"] == 0
    assert report["cleanup"]["pool_shutdown_completed"]
    assert not report["production_capacity_qualified"] and not report["bank_approved"]


def test_cancel_resubmit_burst_cannot_create_unbounded_executor_tombstones():
    entered, release, two_cancelled = threading.Event(), threading.Event(), threading.Event()
    ran, cancelled, errors, observed = [], set(), [], []

    def handler(descriptor):
        ran.append(int(descriptor.job_id.rsplit("-", 1)[1]))
        entered.set()
        assert release.wait(8)
        return True

    pool = WorkerPool(handler=handler, max_workers=1, queue_limit=2)
    pool.submit(job(0))
    assert entered.wait(3)

    def burst():
        try:
            for number in range(1, 65):
                future = pool.submit(job(number))
                if future.cancel():
                    cancelled.add(number)
                    if len(cancelled) == 2:
                        two_cancelled.set()
                observed.append(len(pool.futures))
        except BaseException as exc:
            errors.append(exc)
            two_cancelled.set()

    producer = threading.Thread(target=burst)
    producer.start()
    try:
        assert two_cancelled.wait(3)
        assert producer.is_alive() and len(pool.futures) == 3
        assert len(cancelled) == 2, "Cancel/resubmit bypassed the admission budget"
    finally:
        release.set()
        producer.join(5)
        pool.shutdown(wait=True)
    assert not producer.is_alive() and not errors
    assert max(observed) <= 3 and not pool.futures
    assert not set(ran) & cancelled
    assert len(ran) + len(cancelled) == 65
    assert pool.stats.completed == pool.stats.submitted == len(ran)
    assert pool.stats.failed == pool.stats.active == 0


def test_completion_callback_can_submit_nonblocking_follow_up_work():
    entered, release, observed = threading.Event(), threading.Event(), threading.Event()
    errors, children = [], []

    def handler(descriptor):
        entered.set()
        assert release.wait(5)
        return True

    pool = WorkerPool(handler=handler, max_workers=1, queue_limit=0)
    try:
        first = pool.submit(job(0))
        assert entered.wait(3)

        def follow_up(future):
            try:
                # Probe first so a regression fails without hanging the worker.
                if not pool._semaphore.acquire(blocking=False):
                    errors.append("Completed admission held its slot during the callback")
                    return
                pool._semaphore.release()
                children.append(pool.submit(job(1)))
            finally:
                observed.set()

        first.add_done_callback(follow_up)
        release.set()
        assert first.result(timeout=3)
        assert observed.wait(3) and not errors
        assert children[0].result(timeout=3)
    finally:
        release.set()
        pool.shutdown(wait=True)
    assert not pool.futures
    assert pool.stats.completed == 2
