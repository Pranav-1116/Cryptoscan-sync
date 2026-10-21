"""Scan job repository."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from datetime import datetime, timezone

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from db.models.scan_job import ScanJob
from db.repositories.base_repository import BaseRepository


_UNSCOPED = object()


class JobRepository(BaseRepository[ScanJob]):
    def __init__(self, session: Session):
        super().__init__(ScanJob, session)

    def create(self, obj=None, **kwargs):
        if obj is not None and not kwargs:
            return super().create(obj)
        payload = dict(kwargs)
        if obj is not None and hasattr(obj, "__dict__") and not payload:
            return super().create(obj)
        if "job_id" in payload:
            payload["id"] = payload.pop("job_id")
        allowed = {
            "id",
            "job_type",
            "target_repo",
            "target_branch",
            "target_commit",
            "triggered_by",
            "status",
            "scan_id",
            "progress",
            "system_id",
            # Trusted provenance only: webhook/monitor callers copy the tenant
            # of the configuration row that authorized the scan. The ORM
            # guard still stamps/rejects inside an active tenant scope.
            "tenant_id",
        }
        job = ScanJob(**{k: v for k, v in payload.items() if k in allowed})
        return super().create(job)

    def create_job(
        self,
        *,
        job_type: str,
        target_repo: str,
        target_branch: str,
        triggered_by: str,
        target_commit: str | None = None,
        tenant_id: str | None = None,
    ) -> ScanJob:
        job = ScanJob(
            job_type=job_type,
            target_repo=target_repo,
            target_branch=target_branch or "main",
            target_commit=target_commit,
            triggered_by=triggered_by,
            status="QUEUED",
            tenant_id=tenant_id,
        )
        return self.create(job)

    #: statuses a settled job must not silently leave. A non-forced update
    #: that would move a job out of one of these is a lost-update race
    #: (typically a stale worker finishing after the reaper failed the job)
    #: and is refused — the first verdict stands.
    TERMINAL_STATUSES = frozenset({"COMPLETED", "FAILED", "CANCELLED"})

    def update_status(
        self,
        job_id: str,
        status: str,
        *,
        error_message: str | None = None,
        scan_id: str | None = None,
        progress: dict | None = None,
        force: bool = False,
    ) -> ScanJob | None:
        """Transition a job's status with optimistic locking (audit 04).

        The write is a compare-and-set on ``version`` and refuses to leave a
        terminal state unless ``force=True``. On either conflict the row is
        left untouched and ``None`` is returned — callers that need to know
        which way the race went can re-read the row.
        """
        current = self.get_by_id(job_id)
        if current is None:
            return None
        if not force and current.status in self.TERMINAL_STATUSES:
            logger.warning(
                "job_status_conflict_terminal",
                extra={"job_id": job_id, "from": current.status, "to": status},
            )
            return None

        values: dict = {"status": status, "version": (current.version or 0) + 1}
        now = datetime.now(timezone.utc)
        if status == "RUNNING" and current.started_at is None:
            # Stage progress reports are RUNNING -> RUNNING transitions; keep
            # the original start time so elapsed duration remains meaningful.
            values["started_at"] = now
        if status in self.TERMINAL_STATUSES:
            values["completed_at"] = now
        if error_message is not None:
            values["error_message"] = error_message
        if scan_id is not None:
            values["scan_id"] = scan_id
        if progress is not None:
            values["progress"] = progress
        rowcount = (
            self.session.query(ScanJob)
            .filter(ScanJob.id == job_id, ScanJob.version == (current.version or 0))
            .update(values, synchronize_session=False)
        )
        if not rowcount:
            logger.warning(
                "job_status_conflict_version",
                extra={"job_id": job_id, "from": current.status, "to": status,
                       "version": current.version},
            )
            # No rollback: the UPDATE matched zero rows, so the session has
            # nothing pending from this statement and the caller's other
            # pending work (e.g. a reaper sweep) must survive the race.
            return None
        self.session.flush()
        # synchronize_session=False leaves the identity-map row stale; expire
        # it so the returned object (and any later read) sees the new state.
        self.session.expire(current)
        return self.get_by_id(job_id)

    def list_by_scan_option(self, key: str, value: str, limit: int = 500, *, owner=_UNSCOPED) -> list[ScanJob]:
        """Recent jobs whose stored ``scan_options[key]`` equals ``value``.

        A queued scan records its options (including an intake batch id) in
        ``progress.scan_options``. A JSON-path lookup keeps a fleet-pass status
        from loading and filtering the whole job table in Python; if the database
        cannot do JSON, that filter is the fallback, so the status degrades
        instead of failing.
        """
        window = max(1, min(int(limit or 500), 5000))
        try:
            stmt = (
                select(ScanJob)
                .where(ScanJob.progress["scan_options"][key].as_string() == str(value))
                .order_by(desc(ScanJob.created_at))
                .limit(window)
            )
            if owner is not _UNSCOPED:
                stmt = stmt.where(ScanJob.tenant_id == owner)
            return list(self.session.execute(stmt).scalars().all())
        except Exception:  # noqa: BLE001 — no JSON path support: filter the window instead
            try:
                self.session.rollback()
            except Exception as _handler_exc:  # noqa: BLE001
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass
            stmt = select(ScanJob).order_by(desc(ScanJob.created_at)).limit(window)
            if owner is not _UNSCOPED:
                stmt = stmt.where(ScanJob.tenant_id == owner)
            rows = self.session.execute(stmt).scalars().all()
            return [
                row for row in rows
                if str(((row.progress or {}).get("scan_options") or {}).get(key) or "") == str(value)
            ]

    def get_by_id(self, id_value, *, owner=_UNSCOPED):
        """API history supplies an exact owner, including None/platform.

        Omission preserves the internal worker/reaper repository contract;
        this is not an opt-out from an existing ORM tenant scope.
        """
        if owner is _UNSCOPED:
            return super().get_by_id(id_value)
        stmt = select(ScanJob).where(ScanJob.id == id_value, ScanJob.tenant_id == owner).limit(1)
        return self.session.execute(stmt).scalars().first()

    def list_recent(self, limit: int = 20, *, owner=_UNSCOPED) -> list[ScanJob]:
        stmt = (
            select(ScanJob)
            .order_by(desc(ScanJob.created_at), desc(ScanJob.id))
            .limit(max(1, min(int(limit or 20), 200)))
        )
        if owner is not _UNSCOPED:
            stmt = stmt.where(ScanJob.tenant_id == owner)
        return list(self.session.execute(stmt).scalars().all())
