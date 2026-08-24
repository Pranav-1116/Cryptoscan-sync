"""Scan job repository."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from db.models.scan_job import ScanJob
from db.repositories.base_repository import BaseRepository


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
    ) -> ScanJob:
        job = ScanJob(
            job_type=job_type,
            target_repo=target_repo,
            target_branch=target_branch or "main",
            target_commit=target_commit,
            triggered_by=triggered_by,
            status="QUEUED",
        )
        return self.create(job)

    def update_status(
        self,
        job_id: str,
        status: str,
        *,
        error_message: str | None = None,
        scan_id: str | None = None,
        progress: dict | None = None,
    ) -> ScanJob | None:
        values: dict = {"status": status}
        now = datetime.now(timezone.utc)
        if status == "RUNNING":
            values["started_at"] = now
        if status in {"COMPLETED", "FAILED", "CANCELLED"}:
            values["completed_at"] = now
        if error_message is not None:
            values["error_message"] = error_message
        if scan_id is not None:
            values["scan_id"] = scan_id
        if progress is not None:
            values["progress"] = progress
        return self.update(job_id, values)

    def list_recent(self, limit: int = 20) -> list[ScanJob]:
        stmt = select(ScanJob).order_by(desc(ScanJob.created_at)).limit(limit)
        return list(self.session.execute(stmt).scalars().all())
