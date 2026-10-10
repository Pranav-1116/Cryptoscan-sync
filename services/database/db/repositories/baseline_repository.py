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

    def list_proposed(self, system_identifier: str | None = None) -> list[Baseline]:
        """PROPOSED baselines awaiting auditor approval (report 31 GAP-011)."""
        stmt = select(Baseline).where(Baseline.status == "PROPOSED")
        if system_identifier:
            stmt = stmt.where(Baseline.system_identifier == system_identifier)
        return list(self.session.execute(stmt.order_by(Baseline.approved_at.desc())).scalars().all())

    def approve_proposed(
        self, baseline_id: str, approved_by: str, notes: str | None = None
    ) -> Baseline | None:
        """Activate a PROPOSED baseline (auditor decision). Supersedes the
        current ACTIVE baseline for the same system, exactly like a fresh
        approval would."""
        row = self.get_by_id(baseline_id)
        if row is None or row.status != "PROPOSED":
            return None
        existing = self.get_active(row.system_identifier)
        if existing is not None and existing.id != row.id:
            existing.status = "SUPERSEDED"
        row.status = "ACTIVE"
        row.approved_by = approved_by
        row.approved_at = datetime.now(timezone.utc)
        if notes:
            row.notes = notes
        self.session.flush()
        return row

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
