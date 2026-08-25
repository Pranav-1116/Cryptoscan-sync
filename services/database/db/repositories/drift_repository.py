"""Drift event repository."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from db.models.drift_event import DriftEvent
from db.repositories.base_repository import BaseRepository


class DriftRepository(BaseRepository[DriftEvent]):
    def __init__(self, session: Session):
        super().__init__(DriftEvent, session)

    def list_events(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        scan_id: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[DriftEvent], int]:
        stmt = select(DriftEvent)
        count_stmt = select(func.count()).select_from(DriftEvent)
        if severity:
            stmt = stmt.where(DriftEvent.severity == severity)
            count_stmt = count_stmt.where(DriftEvent.severity == severity)
        if status:
            stmt = stmt.where(DriftEvent.resolution_status == status)
            count_stmt = count_stmt.where(DriftEvent.resolution_status == status)
        if scan_id:
            stmt = stmt.where(DriftEvent.current_scan_id == scan_id)
            count_stmt = count_stmt.where(DriftEvent.current_scan_id == scan_id)
        total = int(self.session.execute(count_stmt).scalar_one())
        stmt = (
            stmt.order_by(desc(DriftEvent.detected_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return list(self.session.execute(stmt).scalars().all()), total

    def open_counts_by_severity(self) -> dict[str, int]:
        stmt = (
            select(DriftEvent.severity, func.count())
            .where(DriftEvent.resolution_status == "OPEN")
            .group_by(DriftEvent.severity)
        )
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
        for severity, count in self.session.execute(stmt):
            counts[str(severity)] = int(count)
        return counts

    def acknowledge(self, drift_id: str, user: str, notes: str | None = None) -> DriftEvent | None:
        return self._close(drift_id, user, notes, "ACKNOWLEDGED")

    def resolve(self, drift_id: str, user: str, notes: str | None = None) -> DriftEvent | None:
        return self._close(drift_id, user, notes, "RESOLVED")

    def mark_false_positive(self, drift_id: str, user: str, notes: str | None = None) -> DriftEvent | None:
        return self._close(drift_id, user, notes, "FALSE_POSITIVE")

    def list_since(self, since: datetime, *, page_size: int = 200) -> list[DriftEvent]:
        stmt = (
            select(DriftEvent)
            .where(DriftEvent.detected_at >= since)
            .order_by(desc(DriftEvent.detected_at))
            .limit(page_size)
        )
        return list(self.session.execute(stmt).scalars().all())

    def _close(
        self, drift_id: str, user: str, notes: str | None, status: str
    ) -> DriftEvent | None:
        return self.update(
            drift_id,
            {
                "resolution_status": status,
                "resolved_by": user,
                "resolved_at": datetime.now(timezone.utc),
                "resolution_notes": notes,
            },
        )
