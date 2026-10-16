"""Remediation task + verification repositories (audit 62 / GAP-006)."""

from __future__ import annotations

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from db.models.remediation_task import RemediationTask, RemediationVerification
from db.repositories.base_repository import BaseRepository


class RemediationTaskRepository(BaseRepository[RemediationTask]):
    def __init__(self, session: Session):
        super().__init__(RemediationTask, session)

    def list_tasks(
        self,
        *,
        status: str | None = None,
        scan_id: str | None = None,
        owner: str | None = None,
        evidence_id: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[RemediationTask], int]:
        stmt = select(RemediationTask)
        count_stmt = select(func.count()).select_from(RemediationTask)
        if status:
            stmt = stmt.where(RemediationTask.status == status)
            count_stmt = count_stmt.where(RemediationTask.status == status)
        if scan_id:
            stmt = stmt.where(RemediationTask.scan_id == scan_id)
            count_stmt = count_stmt.where(RemediationTask.scan_id == scan_id)
        if owner:
            stmt = stmt.where(RemediationTask.owner == owner)
            count_stmt = count_stmt.where(RemediationTask.owner == owner)
        if evidence_id:
            # the finding→task cross-link (§5, round 73): which tasks
            # reference THIS evidence record (indexed column)
            stmt = stmt.where(RemediationTask.evidence_id == evidence_id)
            count_stmt = count_stmt.where(RemediationTask.evidence_id == evidence_id)
        total = int(self.session.execute(count_stmt).scalar_one())
        stmt = (
            stmt.order_by(desc(RemediationTask.created_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return list(self.session.execute(stmt).scalars().all()), total

    def latest_completed_scan_after(self, target_location: str, after):
        """Latest COMPLETED scan of the same target started after ``after``."""
        from db.models.scan import Scan

        stmt = (
            select(Scan)
            .where(Scan.target_location == target_location)
            .where(Scan.status == "COMPLETED")
            .where(Scan.scan_start > after)
            .order_by(desc(Scan.scan_start))
            .limit(1)
        )
        return self.session.execute(stmt).scalars().first()


class RemediationVerificationRepository(BaseRepository[RemediationVerification]):
    def __init__(self, session: Session):
        super().__init__(RemediationVerification, session)

    def list_verifications(
        self,
        *,
        task_id: str | None = None,
        result: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[RemediationVerification], int]:
        stmt = select(RemediationVerification)
        count_stmt = select(func.count()).select_from(RemediationVerification)
        if task_id:
            stmt = stmt.where(RemediationVerification.task_id == task_id)
            count_stmt = count_stmt.where(RemediationVerification.task_id == task_id)
        if result:
            stmt = stmt.where(RemediationVerification.result == result)
            count_stmt = count_stmt.where(RemediationVerification.result == result)
        total = int(self.session.execute(count_stmt).scalar_one())
        stmt = (
            stmt.order_by(desc(RemediationVerification.verified_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return list(self.session.execute(stmt).scalars().all()), total

    def latest_for_task(self, task_id: str) -> RemediationVerification | None:
        stmt = (
            select(RemediationVerification)
            .where(RemediationVerification.task_id == task_id)
            .order_by(desc(RemediationVerification.verified_at), desc(RemediationVerification.created_at))
            .limit(1)
        )
        return self.session.execute(stmt).scalars().first()
