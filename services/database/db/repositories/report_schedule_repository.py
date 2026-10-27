"""Persistence for report schedules and immutable report snapshots."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.report_snapshot import ReportSchedule, ReportSnapshot

FREQUENCY_DAYS = {"monthly": 30, "quarterly": 91}


def next_run(frequency: str, *, now: datetime | None = None) -> datetime:
    """Next due time for a frequency (30/91 days — documented, deterministic)."""
    now = now or datetime.now(timezone.utc)
    return now + timedelta(days=FREQUENCY_DAYS.get(frequency, 91))


class ReportScheduleRepository:
    def __init__(self, session: Session):
        self.session = session

    # ----------------------------------------------------------- schedules

    def create(self, **kwargs) -> ReportSchedule:
        now = datetime.now(timezone.utc)
        kwargs.setdefault("active", True)
        kwargs["next_run_at"] = now  # a new schedule is due immediately
        row = ReportSchedule(**kwargs)
        self.session.add(row)
        self.session.flush()
        return row

    def get(self, schedule_id: str) -> Optional[ReportSchedule]:
        return self.session.execute(select(ReportSchedule).where(ReportSchedule.id == schedule_id)).scalars().first()

    def get_by_name(self, name: str) -> Optional[ReportSchedule]:
        return self.session.execute(
            select(ReportSchedule).where(ReportSchedule.name == name)
        ).scalar_one_or_none()

    def list_schedules(self, *, active: bool | None = None) -> list[ReportSchedule]:
        stmt = select(ReportSchedule).order_by(ReportSchedule.created_at.desc())
        if active is not None:
            stmt = stmt.where(ReportSchedule.active.is_(active))
        return list(self.session.execute(stmt).scalars().all())

    def due(self, *, now: datetime | None = None) -> list[ReportSchedule]:
        now = now or datetime.now(timezone.utc)
        stmt = select(ReportSchedule).where(
            ReportSchedule.active.is_(True), ReportSchedule.next_run_at <= now
        )
        return list(self.session.execute(stmt).scalars().all())

    def mark_run(self, schedule: ReportSchedule, *, now: datetime | None = None) -> ReportSchedule:
        now = now or datetime.now(timezone.utc)
        schedule.last_run_at = now
        schedule.next_run_at = next_run(schedule.frequency, now=now)
        self.session.flush()
        return schedule

    def set_active(self, schedule_id: str, active: bool) -> Optional[ReportSchedule]:
        row = self.get(schedule_id)
        if row is None:
            return None
        row.active = active
        self.session.flush()
        return row

    def delete(self, schedule_id: str) -> bool:
        row = self.get(schedule_id)
        if row is None:
            return False
        self.session.delete(row)
        self.session.flush()
        return True

    # ----------------------------------------------------------- snapshots

    def add_snapshot(self, **kwargs) -> ReportSnapshot:
        row = ReportSnapshot(**kwargs)
        self.session.add(row)
        self.session.flush()
        return row

    def get_snapshot(self, snapshot_id: str) -> Optional[ReportSnapshot]:
        return self.session.execute(select(ReportSnapshot).where(ReportSnapshot.id == snapshot_id)).scalars().first()

    def list_snapshots(
        self,
        *,
        scan_id: str | None = None,
        schedule_id: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ReportSnapshot], int]:
        stmt = select(ReportSnapshot).order_by(ReportSnapshot.generated_at.desc())
        count = select(__import__("sqlalchemy").func.count()).select_from(ReportSnapshot)
        if scan_id:
            stmt, count = stmt.where(ReportSnapshot.scan_id == scan_id), count.where(
                ReportSnapshot.scan_id == scan_id
            )
        if schedule_id:
            stmt, count = stmt.where(ReportSnapshot.schedule_id == schedule_id), count.where(
                ReportSnapshot.schedule_id == schedule_id
            )
        total = int(self.session.execute(count).scalar_one())
        rows = list(
            self.session.execute(
                stmt.offset((page - 1) * page_size).limit(page_size)
            ).scalars().all()
        )
        return rows, total

    def mark_emailed(
        self, snapshot: ReportSnapshot, status: str, detail: str = "", *, now: datetime | None = None
    ) -> ReportSnapshot:
        now = now or datetime.now(timezone.utc)
        snapshot.email_status = status
        snapshot.emailed_at = now
        snapshot.email_detail = (detail or "")[:500] or None
        self.session.flush()
        return snapshot
