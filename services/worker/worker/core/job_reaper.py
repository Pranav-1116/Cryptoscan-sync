"""DB-side job reaper: nothing stays QUEUED or RUNNING forever.

* RUNNING rows whose ``updated_at`` is older than ``running_timeout`` have lost their
  worker (every pipeline stage touches the row) → FAILED with a clear message.
* QUEUED rows older than ``queued_timeout`` that are in neither the Redis queue nor any
  processing list were published to a queue that has since been lost (Redis restart
  without persistence, API publish failure) → re-published once per sweep, with
  ``progress.requeued`` incremented; after ``max_requeues`` → FAILED.

Runs from the worker's maintenance hook and is safe to run from several workers at once
(updates are idempotent; the worst case is one duplicate publish, which the job's DB
status transition tolerates).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

logger = logging.getLogger(__name__)

ACTIVE = ("QUEUED", "RUNNING")


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def reap_stale_jobs(
    session: Any,
    *,
    queued_ids: Iterable[str] | None,
    publish: Callable[[dict], Any] | None,
    running_timeout: timedelta = timedelta(minutes=90),
    queued_timeout: timedelta = timedelta(minutes=10),
    max_requeues: int = 2,
    now: datetime | None = None,
) -> dict[str, int]:
    """Return ``{"failed_running": n, "requeued": n, "failed_queued": n}``.

    ``queued_ids`` is the set of job_ids visible in Redis (``JobConsumer.queued_job_ids``);
    pass ``None`` when Redis is unavailable — QUEUED rows are then left alone (we cannot
    tell whether they are still enqueued)."""
    from db.models.scan_job import ScanJob
    from db.repositories.job_repository import JobRepository

    now = now or datetime.now(timezone.utc)
    repo = JobRepository(session)
    stats = {"failed_running": 0, "requeued": 0, "failed_queued": 0}
    rows = session.query(ScanJob).filter(ScanJob.status.in_(ACTIVE)).all()
    visible = set(queued_ids) if queued_ids is not None else None
    for job in rows:
        touched = _aware(job.updated_at) or _aware(job.created_at) or now
        age = now - touched
        if job.status == "RUNNING":
            if age > running_timeout:
                repo.update_status(
                    job.id,
                    "FAILED",
                    error_message=f"worker lost: no progress for {int(age.total_seconds() // 60)} min (reaped)",
                )
                stats["failed_running"] += 1
                logger.error("job_reaped_running", extra={"job_id": job.id, "age_s": int(age.total_seconds())})
            continue
        # QUEUED
        if visible is None or age <= queued_timeout or job.id in visible:
            continue
        progress = dict(job.progress or {})
        requeues = int(progress.get("requeued") or 0)
        if requeues >= max_requeues or publish is None:
            updated = repo.update_status(
                job.id,
                "FAILED",
                error_message=f"queued job was not in the queue after {int(age.total_seconds() // 60)} min and {requeues} re-publish(es) (reaped)",
            )
            if updated is not None:
                stats["failed_queued"] += 1
                logger.error("job_reaped_queued", extra={"job_id": job.id, "requeues": requeues})
            else:
                logger.info("job_reaped_queued_lost_race", extra={"job_id": job.id})
            continue
        progress["requeued"] = requeues + 1
        progress["requeued_at"] = now.isoformat()
        payload = {
            "job_id": job.id,
            "scan_id": job.scan_id,
            "target_repo": job.target_repo,
            "target_commit": job.target_commit,
            "target_branch": job.target_branch,
            "triggered_by": job.triggered_by,
            "created_at": job.created_at.isoformat() if isinstance(job.created_at, datetime) else job.created_at,
            "job_type": job.job_type,
            "system_id": job.system_id,
            "progress": progress,
            # Ownership travels with the republish: without it the worker
            # re-ran a tenant's job unscoped and its results landed in the
            # platform estate (tenant_id NULL — readable by every tenant).
            "tenant_id": getattr(job, "tenant_id", None),
        }
        try:
            publish(payload)
        except Exception:
            logger.exception("job_republish_failed", extra={"job_id": job.id})
            continue
        # touch the row so the next sweep does not republish immediately.
        # If the CAS loses a race with a worker picking the job up, the job
        # is RUNNING now — the republish is harmless, only the requeue
        # counter on the row is not bumped.
        if repo.update_status(job.id, "QUEUED", progress=progress) is not None:
            stats["requeued"] += 1
            logger.warning("job_republished", extra={"job_id": job.id, "requeue": progress["requeued"]})
    session.commit()
    return stats


def fail_job(session: Any, job_id: str, reason: str) -> None:
    """Dead-letter callback: mark the DB row FAILED."""
    from db.repositories.job_repository import JobRepository

    JobRepository(session).update_status(job_id, "FAILED", error_message=reason)
    session.commit()
