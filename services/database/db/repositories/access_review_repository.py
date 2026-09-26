"""Append-only records of completed quarterly access reviews.

Create + list only — review minutes are never edited or deleted through
the API (the table is the audit record itself).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.access_review import AccessReviewRecord


class AccessReviewRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, *, period: str, report_hash: str, estate_unchanged: bool,
               reviewer: str, findings: list | None,
               notes: str | None) -> AccessReviewRecord:
        row = AccessReviewRecord(
            period=period,
            report_hash=report_hash,
            estate_unchanged=estate_unchanged,
            reviewer=reviewer,
            findings=findings,
            notes=notes,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def get_by_period(self, period: str) -> AccessReviewRecord | None:
        return self.db.execute(
            select(AccessReviewRecord).where(AccessReviewRecord.period == period)
        ).scalar_one_or_none()

    def list_all(self) -> list[AccessReviewRecord]:
        rows = self.db.execute(
            select(AccessReviewRecord).order_by(AccessReviewRecord.created_at.desc())
        ).scalars().all()
        return list(rows)
