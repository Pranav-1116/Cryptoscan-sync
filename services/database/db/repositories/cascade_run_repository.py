"""Persistence for cross-BOM cascade runs — the audit trail of "what breaks".

Runs are append-only history: the engine is a pure read-only function, and
the repository stores what it returned, for which tenant, and who asked.
Tenant visibility needs no explicit filter here — :class:`CascadeRun` is
:class:`~db.tenancy.TenantScoped`, so the session's tenancy machinery
already restricts reads to the caller's rows plus the un-attributed
platform estate (same semantics as every other repository).
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.cascade_run import CascadeRun


class CascadeRunRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, **kwargs) -> CascadeRun:
        row = CascadeRun(**kwargs)
        self.session.add(row)
        self.session.flush()
        return row

    def get(self, run_id: str) -> Optional[CascadeRun]:
        return self.session.execute(
            select(CascadeRun).where(CascadeRun.id == run_id)
        ).scalars().first()

    def list_runs(self, *, limit: int = 50, offset: int = 0) -> list[CascadeRun]:
        stmt = select(CascadeRun).order_by(
            CascadeRun.created_at.desc()).limit(limit).offset(offset)
        return list(self.session.execute(stmt).scalars().all())
