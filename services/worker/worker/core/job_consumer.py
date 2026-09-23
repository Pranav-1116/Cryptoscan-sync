"""Job queue: Redis when available, in-process fallback."""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from queue import Empty, Queue
from typing import Callable

logger = logging.getLogger(__name__)


@dataclass
class ScanJob:
    job_id: str
    target_repo: str
    target_branch: str = "main"
    triggered_by: str = "system"
    scan_id: str | None = None
    target_commit: str | None = None
    created_at: datetime | str | None = None
    job_type: str = "MANUAL"
    system_id: str | None = None
    #: the job row's progress JSON as queued — carries ``scan_options`` for the
    #: non-git targets (a binary scan needs its rules, format and artifact id)
    progress: dict | None = None

    @property
    def scan_options(self) -> dict:
        """Scan options carried on the payload, defaulting to none."""
        options = (self.progress or {}).get("scan_options")
        return dict(options) if isinstance(options, dict) else {}


_MEMORY_QUEUE: Queue = Queue()


class JobConsumer:
    def __init__(
        self,
        redis_url: str = "",
        queue_name: str = "cryptoscan:jobs:queue",
        poll_interval_seconds: int = 2,
        allow_memory_fallback: bool = True,
        **kwargs,
    ):
        self.redis_url = redis_url
        self.queue_name = queue_name
        self.poll_interval_seconds = poll_interval_seconds
        self.allow_memory_fallback = allow_memory_fallback
        self._stop = threading.Event()
        self.redis_client = None
        self._connect_redis()

    def _connect_redis(self) -> None:
        if not self.redis_url:
            self._handle_redis_unavailable("REDIS_URL not configured", phase="startup")
            return
        try:
            import redis

            client = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=self.poll_interval_seconds + 2,
            )
            client.ping()
            self.redis_client = client
            logger.info("redis_connected", extra={"queue": self.queue_name})
        except Exception as exc:
            self._handle_redis_unavailable(str(exc), phase="startup")

    def _handle_redis_unavailable(self, reason: str, *, phase: str) -> None:
        """Redis configured but unreachable.

        Production fails closed — a silently degraded queue loses jobs the API
        believes are enqueued. Development/test keeps the in-process fallback.
        """
        self.redis_client = None
        if not self.allow_memory_fallback:
            raise RuntimeError(
                f"Redis unavailable during {phase} and memory fallback is disabled: {reason}"
            )
        logger.warning("redis_unavailable_memory_fallback", extra={"error": reason, "phase": phase})

    def stop(self) -> None:
        self._stop.set()

    def enqueue(self, payload: dict) -> None:
        body = json.dumps(payload, default=str)
        if self.redis_url and self.redis_client is None:
            self._connect_redis()
        if self.redis_client is not None:
            try:
                self.redis_client.rpush(self.queue_name, body)
                return
            except Exception as exc:
                logger.warning("redis_enqueue_failed", extra={"error": str(exc)})
                self.redis_client = None
        _MEMORY_QUEUE.put(body)

    def publish_job(self, job: ScanJob | dict) -> bool:
        if isinstance(job, ScanJob):
            payload = {
                "job_id": job.job_id,
                "scan_id": job.scan_id,
                "target_repo": job.target_repo,
                "target_commit": job.target_commit,
                "target_branch": job.target_branch,
                "triggered_by": job.triggered_by,
                "created_at": job.created_at.isoformat() if isinstance(job.created_at, datetime) else job.created_at,
                "job_type": job.job_type,
                "system_id": job.system_id,
            }
        else:
            payload = dict(job)
        self.enqueue(payload)
        return True

    def consume(self, handler: Callable[[ScanJob], None] | None = None, executor_callback=None) -> None:
        callback = handler or executor_callback
        if callback is None:
            raise ValueError("handler is required")
        logger.info("job_consumer_started", extra={"backend": "redis" if self.redis_client else "memory"})
        while not self._stop.is_set():
            job = self._pop()
            if job is None:
                time.sleep(0.05)
                continue
            try:
                callback(job)
            except Exception:
                logger.exception("job_handler_failed", extra={"job_id": job.job_id})

    consume_jobs = consume

    def _pop(self) -> ScanJob | None:
        raw = None
        if self.redis_url and self.redis_client is None:
            self._connect_redis()
        if self.redis_client is not None:
            try:
                item = self.redis_client.blpop(self.queue_name, timeout=self.poll_interval_seconds)
                if item:
                    raw = item[1]
            except Exception as exc:
                self._handle_redis_unavailable(str(exc), phase="pop")
                return None
        else:
            try:
                raw = _MEMORY_QUEUE.get(timeout=self.poll_interval_seconds)
            except Empty:
                return None
            except Exception:
                return None
        if not raw:
            return None
        data = json.loads(raw)
        created = data.get("created_at")
        return ScanJob(
            job_id=data["job_id"],
            scan_id=data.get("scan_id"),
            target_repo=data["target_repo"],
            target_commit=data.get("target_commit"),
            target_branch=data.get("target_branch") or "main",
            triggered_by=data.get("triggered_by") or "system",
            created_at=datetime.fromisoformat(created) if created else datetime.utcnow(),
            job_type=data.get("job_type") or "MANUAL",
            system_id=data.get("system_id"),
            progress=data.get("progress"),
        )


def enqueue_job(payload: dict, redis_url: str = "", queue_name: str = "cryptoscan:jobs:queue") -> None:
    JobConsumer(redis_url=redis_url, queue_name=queue_name).enqueue(payload)
