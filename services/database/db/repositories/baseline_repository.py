"""Baseline repository."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.baseline import Baseline
from db.repositories.base_repository import BaseRepository


class BaselineRepository(BaseRepository[Baseline]):
    def __init__(self, session: Session):
        super().__init__(Baseline, session)

    def get_active(self, system_identifier: str) -> Baseline | None:
        stmt = (
            select(Baseline)
            .where(
                Baseline.system_identifier == system_identifier,
                Baseline.status == "ACTIVE",
            )
            .limit(1)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def approve(
        self,
        *,
        system_identifier: str,
        scan_id: str,
        approved_by: str,
        notes: str | None = None,
        environment: str = "default",
    ) -> Baseline:
        existing = self.get_active(system_identifier)
        if existing:
            existing.status = "SUPERSEDED"
        baseline = Baseline(
            system_identifier=system_identifier,
            environment=environment,
            approved_scan_id=scan_id,
            approved_by=approved_by,
            approved_at=datetime.now(timezone.utc),
            status="ACTIVE",
            notes=notes,
        )
        return self.create(baseline)
