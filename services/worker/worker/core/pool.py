"""Bounded concurrency for scan job execution.

The pipeline itself is synchronous; jobs run in a thread pool of
`MAX_CONCURRENT_JOBS` workers. Each job gets its own SQLAlchemy session
(the configured database engine owns connection pooling; sessions are not
shared between jobs).
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from worker.core.job_consumer import ScanJob

logger = logging.getLogger(__name__)


@dataclass
class PoolStats:
    submitted: int = 0
    completed: int = 0
    failed: int = 0
    active: int = 0
    max_active: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def begin(self) -> None:
        with self.lock:
            self.submitted += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)

    def end(self, ok: bool) -> None:
        with self.lock:
            self.active -= 1
            self.completed += 1
            if not ok:
                self.failed += 1


class WorkerPool:
    """Run job handlers on `max_workers` threads with backpressure."""

    def __init__(self, handler: Callable[[ScanJob], object], max_workers: int = 2, queue_limit: int = 100):
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        if queue_limit < 0:
            raise ValueError("queue_limit must be >= 0")
        self.handler = handler
        self.max_workers = max_workers
        self._semaphore = threading.Semaphore(max_workers + queue_limit)
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="cryptoscan-job"
        )
        self._shutdown = threading.Event()
        self._pending: set[Future] = set()
        self._pending_lock = threading.Condition()
        self.stats = PoolStats()

    @property
    def futures(self) -> list[Future]:
        """Snapshot of admitted work, not an ever-growing completion history.

        Cancelled queued wrappers remain admitted until the executor consumes
        them. Callers may retain their returned Future; mutating this snapshot
        cannot alter accounting.
        """
        with self._pending_lock:
            return list(self._pending)

    def _finished(self, future: Future) -> None:
        # Prune BEFORE making the slot available or invoking public callbacks.
        # Cancelled work keeps its slot until the wrapper consumes its queued
        # entry: cancel/resubmit cannot build an unbounded tombstone queue.
        with self._pending_lock:
            self._pending.remove(future)
            self._semaphore.release()
            self._pending_lock.notify_all()

    @property
    def saturated(self) -> bool:
        """True while the pool is running at full worker occupancy."""
        with self.stats.lock:
            return self.stats.active >= self.max_workers

    def submit(self, job: ScanJob) -> Future:
        if self._shutdown.is_set():
            raise RuntimeError("pool is shut down")
        public_future = Future()
        self._semaphore.acquire()
        with self._pending_lock:
            self._pending.add(public_future)
        try:
            # Shutdown may have begun while this submitter waited for a slot.
            if self._shutdown.is_set():
                raise RuntimeError("pool is shut down")
            self._executor.submit(self._dispatch, job, public_future)
        except BaseException as exc:
            # Publish refusal to snapshot waiters as well as returning the slot.
            self._finished(public_future)
            public_future.set_exception(exc)
            raise
        return public_future

    def _dispatch(self, job: ScanJob, public_future: Future) -> bool:
        # The executor future is not exposed/cancelled. Even a cancelled public
        # future has a wrapper that consumes its work item and releases capacity.
        result = False
        try:
            running = public_future.set_running_or_notify_cancel()
            if running:
                result = self._run(job)
        except BaseException as exc:
            self._finished(public_future)
            if not public_future.done():
                public_future.set_exception(exc)
            raise
        self._finished(public_future)
        if running:
            # Release before user callbacks so a nonblocking follow-up submit
            # cannot deadlock waiting for this already-finished admission.
            public_future.set_result(result)
        return result

    def _run(self, job: ScanJob) -> bool:
        self.stats.begin()
        ok = False
        try:
            result = self.handler(job)
            ok = result is not False
            return ok
        except Exception:
            logger.exception("job_execution_failed", extra={"job_id": job.job_id})
            return False
        finally:
            # BaseException interruptions still propagate through the Future.
            # Terminal-future cleanup releases LOCAL backpressure (including
            # cancellations), never durable execution reservations.
            self.stats.end(ok=ok)

    def shutdown(self, wait: bool = True) -> None:
        self._shutdown.set()
        self._executor.shutdown(wait=wait)

    def wait(self) -> None:
        """Wait for the current admitted snapshot, including cancelled wrappers.

        This is an external coordinator barrier, not callable from a handler
        or completion callback that is itself part of the snapshot.
        """
        with self._pending_lock:
            snapshot = list(self._pending)
        for future in snapshot:
            # A cancelled public result is immediate, but its queued wrapper
            # must still drain before this admission barrier can return.
            with self._pending_lock:
                self._pending_lock.wait_for(lambda: future not in self._pending)
            try:
                if not future.cancelled():
                    future.result()
            except Exception as _handler_exc:  # pragma: no cover - already logged in _run
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass
