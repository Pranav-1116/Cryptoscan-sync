"""Job queue: Redis when available, in-process fallback."""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from queue import Queue
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


_MEMORY_QUEUE: Queue = Queue()


class JobConsumer:
    def __init__(
        self,
        redis_url: str = "",
        queue_name: str = "cryptoscan:jobs:queue",
        poll_interval_seconds: int = 2,
        **kwargs,
    ):
        self.redis_url = redis_url
        self.queue_name = queue_name
        self.poll_interval_seconds = poll_interval_seconds
        self._stop = threading.Event()
        self.redis_client = None
        if redis_url:
            try:
                import redis

                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                self.redis_client.ping()
                logger.info("redis_connected", extra={"url": redis_url})
            except Exception as exc:
                logger.warning("redis_unavailable_using_memory_queue", extra={"error": str(exc)})
                self.redis_client = None

    def stop(self) -> None:
        self._stop.set()

    def enqueue(self, payload: dict) -> None:
        body = json.dumps(payload, default=str)
        if self.redis_client is not None:
            self.redis_client.lpush(self.queue_name, body)
        else:
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
                time.sleep(self.poll_interval_seconds)
                continue
            try:
                callback(job)
            except Exception:
                logger.exception("job_handler_failed", extra={"job_id": job.job_id})

    consume_jobs = consume

    def _pop(self) -> ScanJob | None:
        raw = None
        if self.redis_client is not None:
            item = self.redis_client.brpop(self.queue_name, timeout=self.poll_interval_seconds)
            if item:
                raw = item[1]
        else:
            try:
                raw = _MEMORY_QUEUE.get(timeout=self.poll_interval_seconds)
            except Exception:
                return None
        if not raw:
            return None
        data = json.loads(raw)
        return ScanJob(
            job_id=data["job_id"],
            scan_id=data.get("scan_id"),
            target_repo=data["target_repo"],
            target_commit=data.get("target_commit"),
            target_branch=data.get("target_branch") or "main",
            triggered_by=data.get("triggered_by") or "system",
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.utcnow(),
            job_type=data.get("job_type") or "MANUAL",
        )


def enqueue_job(payload: dict, redis_url: str = "", queue_name: str = "cryptoscan:jobs:queue") -> None:
    JobConsumer(redis_url=redis_url, queue_name=queue_name).enqueue(payload)
