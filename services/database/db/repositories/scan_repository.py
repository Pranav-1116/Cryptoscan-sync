"""Scan repository."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from db.models.scan import Scan
from db.repositories.base_repository import BaseRepository


class ScanRepository(BaseRepository[Scan]):
    def __init__(self, session: Session):
        super().__init__(Scan, session)

    def get_recent_scans(self, limit: int = 10) -> list[Scan]:
        stmt = select(Scan).order_by(desc(Scan.scan_start)).limit(max(1, min(int(limit or 10), 200)))
        return list(self.session.execute(stmt).scalars().all())

    def list_scans(
        self,
        *,
        status: str | None = None,
        target: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Scan], int]:
        stmt = select(Scan)
        count_stmt = select(func.count()).select_from(Scan)
        if status:
            stmt = stmt.where(Scan.status == status)
            count_stmt = count_stmt.where(Scan.status == status)
        if target:
            stmt = stmt.where(Scan.target_location == target)
            count_stmt = count_stmt.where(Scan.target_location == target)
        total = int(self.session.execute(count_stmt).scalar_one())
        stmt = stmt.order_by(desc(Scan.created_at)).offset((page - 1) * page_size).limit(page_size)
        return list(self.session.execute(stmt).scalars().all()), total

    def get_by_target_location(self, target_location: str) -> list[Scan]:
        stmt = (
            select(Scan)
            .where(Scan.target_location == target_location)
            .order_by(desc(Scan.scan_start))
        )
        return list(self.session.execute(stmt).scalars().all())

    def get_latest_completed_for_target(self, target_location: str) -> Scan | None:
        stmt = (
            select(Scan)
            .where(Scan.target_location == target_location, Scan.status == "COMPLETED")
            .order_by(desc(Scan.scan_start))
            .limit(1)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def mark_completed(self, scan_id: str, statistics: dict, manifest_hash: str) -> Scan | None:
        return self.update(
            scan_id,
            {
                "status": "COMPLETED",
                "scan_end": datetime.now(timezone.utc),
                "statistics": statistics,
                "manifest_hash": manifest_hash,
            },
        )

    def mark_failed(self, scan_id: str, error_message: str) -> Scan | None:
        return self.update(
            scan_id,
            {
                "status": "FAILED",
                "scan_end": datetime.now(timezone.utc),
                "error_message": error_message,
            },
        )
