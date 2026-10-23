"""Job queue: Redis when available, in-process fallback.

Reliability model (Redis backend)
---------------------------------
* ``BLMOVE queue -> queue:processing:<worker_id>``: a job is never removed from
  Redis until the worker acknowledges it (``ack``).  A worker that dies mid-scan
  leaves the payload in its processing list.
* Every worker refreshes ``queue:worker:<worker_id>`` (TTL ``lease_ttl_seconds``)
  while it polls.  ``recover_orphans`` moves the processing lists of workers whose
  lease expired back to the head of the queue, incrementing ``_attempts``; after
  ``max_redeliveries`` the payload goes to ``queue:dead`` and the DB row is failed
  through ``on_dead_letter`` so nothing stays QUEUED/RUNNING forever.
* Redis < 6.2 (no BLMOVE) falls back to BRPOPLPUSH-free BLPOP with a one-time
  warning: at-most-once, as before.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from queue import Empty, Queue
from typing import Callable

logger = logging.getLogger(__name__)


def _parse_created_at(created: str | None) -> datetime:
    """Always timezone-aware, however the payload spelled it.

    This used to be ``fromisoformat(created) if created else utcnow()``, which
    produced an aware datetime for a payload carrying an offset (what
    monitor/runners.py writes) and a naive one for the fallback. Mixing the two
    raises "can't subtract offset-naive and offset-aware datetimes" the moment
    anything ages a job — and job_reaper already carries an ``_aware()`` helper
    because it hit exactly that. Normalising at the producer means consumers
    don't each need their own guard.

    Naive input is read as UTC, which is what every writer here intends.
    """
    if not created:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(created)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


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
    #: Owning tenant, carried across the queue so the worker can re-enter the
    #: scope the caller was in. A worker has no session to resolve a tenant
    #: from, so if this does not travel with the job the work runs unscoped —
    #: and unscoped writes get tenant_id NULL, which db.tenancy treats as the
    #: platform estate that every tenant can read. ``None`` means genuinely
    #: platform-owned (or a job queued before this field existed).
    tenant_id: str | None = None
    #: the job row's progress JSON as queued — carries ``scan_options`` for the
    #: non-git targets (a binary scan needs its rules, format and artifact id)
    progress: dict | None = None
    #: exact payload string as stored in Redis — needed to ack (LREM) it
    raw: str | None = None
    #: redelivery counter maintained by recover_orphans
    attempts: int = 0

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
        worker_id: str | None = None,
        lease_ttl_seconds: int = 60,
        max_redeliveries: int = 3,
        on_dead_letter: Callable[[dict, str], None] | None = None,
        maintenance_interval_seconds: int = 60,
        **kwargs,
    ):
        self.redis_url = redis_url
        self.queue_name = queue_name
        self.poll_interval_seconds = poll_interval_seconds
        self.allow_memory_fallback = allow_memory_fallback
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self.lease_ttl_seconds = max(int(lease_ttl_seconds), 2 * max(int(poll_interval_seconds), 1) + 1)
        self.max_redeliveries = int(max_redeliveries)
        self.on_dead_letter = on_dead_letter
        self.maintenance_interval_seconds = int(maintenance_interval_seconds)
        self._last_maintenance = 0.0
        self.on_maintenance: Callable[[], None] | None = kwargs.get("on_maintenance")
        self._blmove_supported: bool | None = None
        self._stop = threading.Event()
        self.redis_client = None
        self._connect_redis()

    # ----------------------------------------------------------------- keys
    @property
    def processing_key(self) -> str:
        return f"{self.queue_name}:processing:{self.worker_id}"

    @property
    def lease_key(self) -> str:
        return f"{self.queue_name}:worker:{self.worker_id}"

    @property
    def dead_letter_key(self) -> str:
        return f"{self.queue_name}:dead"

    def _processing_prefix(self) -> str:
        return f"{self.queue_name}:processing:"

    def _lease_key_for(self, worker_id: str) -> str:
        return f"{self.queue_name}:worker:{worker_id}"

    def heartbeat(self) -> None:
        """Refresh this worker's lease; a missing lease marks our processing list as orphaned."""
        if self.redis_client is None:
            return
        try:
            self.redis_client.set(self.lease_key, str(int(time.time())), ex=self.lease_ttl_seconds)
        except Exception as exc:
            logger.warning("lease_refresh_failed", extra={"error": str(exc)})

    def ack(self, job: ScanJob) -> None:
        """Remove a finished job (success or failure) from this worker's processing list."""
        if self.redis_client is None or not job.raw:
            return
        try:
            self.redis_client.lrem(self.processing_key, 1, job.raw)
        except Exception as exc:
            logger.warning("job_ack_failed", extra={"job_id": job.job_id, "error": str(exc)})

    def recover_orphans(self) -> dict:
        """Requeue jobs left in the processing lists of workers whose lease expired.

        Returns ``{"requeued": n, "dead_lettered": n, "workers": n}``. Safe to call from any worker;
        idempotent (a payload is moved at most once per call)."""
        stats = {"requeued": 0, "dead_lettered": 0, "workers": 0}
        if self.redis_client is None:
            return stats
        try:
            keys = list(self.redis_client.scan_iter(match=self._processing_prefix() + "*", count=100))
        except Exception as exc:
            logger.warning("recover_scan_failed", extra={"error": str(exc)})
            return stats
        for key in keys:
            worker_id = str(key)[len(self._processing_prefix()):]
            if worker_id == self.worker_id:
                continue
            try:
                if self.redis_client.exists(self._lease_key_for(worker_id)):
                    continue  # alive
                stats["workers"] += 1
                while True:
                    raw = self.redis_client.rpop(key)
                    if raw is None:
                        break
                    try:
                        payload = json.loads(raw)
                    except (TypeError, ValueError) as payload_exc:
                        logger.warning(
                            "orphaned_job_payload_invalid",
                            extra={"error_type": type(payload_exc).__name__, "worker": worker_id},
                        )
                        continue
                    attempts = int(payload.get("_attempts") or 0) + 1
                    payload["_attempts"] = attempts
                    if attempts > self.max_redeliveries:
                        reason = f"job redelivered {attempts - 1} times after worker loss; giving up"
                        self.redis_client.rpush(self.dead_letter_key, json.dumps(payload, default=str))
                        stats["dead_lettered"] += 1
                        logger.error("job_dead_lettered", extra={"job_id": payload.get("job_id"), "worker": worker_id})
                        if self.on_dead_letter:
                            try:
                                self.on_dead_letter(payload, reason)
                            except Exception:
                                logger.exception("dead_letter_callback_failed")
                        continue
                    # head of the queue: the oldest work goes first
                    self.redis_client.lpush(self.queue_name, json.dumps(payload, default=str))
                    stats["requeued"] += 1
                    logger.warning("job_requeued_after_worker_loss", extra={"job_id": payload.get("job_id"), "lost_worker": worker_id, "attempt": attempts})
            except Exception as exc:
                logger.warning("recover_worker_failed", extra={"worker": worker_id, "error": str(exc)})
        return stats

    def queued_job_ids(self) -> set[str]:
        """job_ids currently in the queue or in any processing list (for the DB reaper)."""
        ids: set[str] = set()
        if self.redis_client is None:
            return ids
        try:
            keys = [self.queue_name] + list(self.redis_client.scan_iter(match=self._processing_prefix() + "*", count=100))
            for key in keys:
                for raw in self.redis_client.lrange(key, 0, -1):
                    try:
                        ids.add(str(json.loads(raw).get("job_id")))
                    except (TypeError, ValueError) as payload_exc:
                        logger.warning(
                            "queued_job_payload_invalid",
                            extra={"error_type": type(payload_exc).__name__},
                        )
                        continue
        except Exception as exc:
            logger.warning("queued_ids_failed", extra={"error": str(exc)})
        return ids

    def maintenance_due(self) -> bool:
        now = time.monotonic()
        if now - self._last_maintenance >= self.maintenance_interval_seconds:
            self._last_maintenance = now
            return True
        return False

    def _connect_redis(self) -> None:
        try:
            from worker.config.settings import get_settings
            from shared_models.redis_connection import connection_settings, verified_redis_client
            config = connection_settings(get_settings(), "queue", url=self.redis_url)
            if not config.REDIS_URL:
                self._handle_redis_unavailable("REDIS_URL not configured", phase="startup")
                return
            client = verified_redis_client(config, decode_responses=True,
                                           socket_timeout=self.poll_interval_seconds + 2)
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
                logger.warning("redis_enqueue_failed", extra={"error_type": type(exc).__name__})
                self.redis_client = None
        if not self.allow_memory_fallback:
            # The SQL outbox must observe failure, not acknowledge an ephemeral
            # process-local delivery as a durable publication.
            raise RuntimeError("Redis unavailable during enqueue and memory fallback is disabled")
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
                "tenant_id": job.tenant_id,
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
        self.heartbeat()
        while not self._stop.is_set():
            if self.maintenance_due():
                self.recover_orphans()
                if self.on_maintenance:
                    try:
                        self.on_maintenance()
                    except Exception:
                        logger.exception("maintenance_hook_failed")
            job = self._pop()
            if job is None:
                time.sleep(0.05)
                continue
            try:
                callback(job)
            except Exception:
                logger.exception("job_handler_failed", extra={"job_id": job.job_id})
                self.ack(job)  # handler refused it synchronously: do not redeliver forever

    consume_jobs = consume

    def _pop(self) -> ScanJob | None:
        raw = None
        if self.redis_url and self.redis_client is None:
            self._connect_redis()
        if self.redis_client is not None:
            self.heartbeat()
            try:
                if self._blmove_supported is not False:
                    try:
                        raw = self.redis_client.blmove(self.queue_name, self.processing_key, self.poll_interval_seconds, "LEFT", "RIGHT")
                        self._blmove_supported = True
                    except Exception as exc:  # Redis < 6.2 or a client without blmove
                        if "unknown command" in str(exc).lower() or isinstance(exc, (AttributeError, NotImplementedError)):
                            self._blmove_supported = False
                            logger.warning("blmove_unsupported_at_most_once_delivery", extra={"error": str(exc)})
                        else:
                            raise
                if self._blmove_supported is False:
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
            except Exception as _handler_exc:
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
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
            created_at=_parse_created_at(created),
            job_type=data.get("job_type") or "MANUAL",
            system_id=data.get("system_id"),
            # Absent on jobs queued before this field existed; those keep the
            # old unscoped behaviour rather than failing to deserialize.
            tenant_id=data.get("tenant_id"),
            progress=data.get("progress"),
            raw=raw if self.redis_client is not None else None,
            attempts=int(data.get("_attempts") or 0),
        )


def enqueue_job(payload: dict, redis_url: str = "", queue_name: str = "cryptoscan:jobs:queue") -> None:
    JobConsumer(redis_url=redis_url, queue_name=queue_name).enqueue(payload)
