"""Bounded concurrency for scan job execution.

The pipeline itself is synchronous; jobs run in a thread pool of
`MAX_CONCURRENT_JOBS` workers. Each job gets its own SQLAlchemy session
(the SQLite engine uses NullPool for file-backed databases so threads do
not share a single DBAPI connection).
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
        self.handler = handler
        self.max_workers = max_workers
        self._semaphore = threading.Semaphore(max_workers + queue_limit)
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="cryptoscan-job"
        )
        self._shutdown = threading.Event()
        self.futures: list[Future] = []
        self.stats = PoolStats()

    @property
    def saturated(self) -> bool:
        """True while the pool is running at full worker occupancy."""
        with self.stats.lock:
            return self.stats.active >= self.max_workers

    def submit(self, job: ScanJob) -> Future:
        if self._shutdown.is_set():
            raise RuntimeError("pool is shut down")
        self._semaphore.acquire()
        try:
            future = self._executor.submit(self._run, job)
        except BaseException:
            # Submission may itself be interrupted after acquiring a slot.
            self._semaphore.release()
            raise
        self.futures.append(future)
        return future

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
            # BaseException interruptions still propagate through the Future,
            # but must not permanently saturate local pool accounting. This
            # releases LOCAL backpressure, not durable execution reservations.
            self.stats.end(ok=ok)
            self._semaphore.release()

    def shutdown(self, wait: bool = True) -> None:
        self._shutdown.set()
        self._executor.shutdown(wait=wait)

    def wait(self) -> None:
        for future in list(self.futures):
            try:
                future.result()
            except Exception as _handler_exc:  # pragma: no cover - already logged in _run
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass
