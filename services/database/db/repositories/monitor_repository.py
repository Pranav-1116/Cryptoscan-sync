"""Persistence for the 24/7 monitor: watch-list targets and their event feed."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models.monitor import MonitorEvent, MonitorTarget
from db.models.tenant import Tenant


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MonitorRepository:
    def __init__(self, session: Session):
        self.session = session

    # ------------------------------------------------------------- targets

    def create(self, **kwargs) -> MonitorTarget:
        now = utcnow()
        kwargs.setdefault("enabled", True)
        kwargs.setdefault("status", "PENDING")
        kwargs.setdefault("next_scan_at", now)  # a new target is due immediately (unless overridden)
        row = MonitorTarget(**kwargs)
        self.session.add(row)
        self.session.flush()
        return row

    def get(self, target_id: str) -> Optional[MonitorTarget]:
        return self.session.get(MonitorTarget, target_id)

    def get_by_name(self, name: str) -> Optional[MonitorTarget]:
        return self.session.execute(
            select(MonitorTarget).where(MonitorTarget.name == name)
        ).scalar_one_or_none()

    def get_by_name_scoped(self, name: str, *, tenant_id: str | None = None,
                           platform: bool = False) -> Optional[MonitorTarget]:
        """Uniqueness within one estate: a tenant may reuse the platform's
        (or another tenant's) target name without colliding with it."""
        stmt = select(MonitorTarget).where(MonitorTarget.name == name)
        if platform:
            stmt = stmt.where(MonitorTarget.tenant_id.is_(None))
        else:
            stmt = stmt.where(MonitorTarget.tenant_id == tenant_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def list_targets(self, *, enabled: bool | None = None,
                     tenant_id: str | None = None,
                     platform: bool = False) -> list[MonitorTarget]:
        """List targets. Platform context (platform=True) sees NULL-tenant
        rows; a tenant context sees only its own — never both, never anyone
        else's."""
        stmt = select(MonitorTarget).order_by(MonitorTarget.created_at.desc())
        if enabled is not None:
            stmt = stmt.where(MonitorTarget.enabled.is_(enabled))
        if platform:
            stmt = stmt.where(MonitorTarget.tenant_id.is_(None))
        elif tenant_id is not None:
            stmt = stmt.where(MonitorTarget.tenant_id == tenant_id)
        return list(self.session.execute(stmt).scalars().all())

    def due(self, *, now: datetime | None = None) -> list[MonitorTarget]:
        """All due targets across every ACTIVE tenant + the platform estate.

        The daemon is the platform worker: it runs everything that is due,
        stamping each result with its target's tenant. SUSPENDED tenants are
        skipped (their targets stay in place, they just stop being scanned).
        """
        now = now or utcnow()
        active = select(Tenant.id).where(Tenant.status == "ACTIVE")
        stmt = select(MonitorTarget).where(
            MonitorTarget.enabled.is_(True),
            MonitorTarget.next_scan_at <= now,
            MonitorTarget.tenant_id.is_(None) | MonitorTarget.tenant_id.in_(active),
        ).order_by(MonitorTarget.next_scan_at)
        return list(self.session.execute(stmt).scalars().all())

    def delete(self, target_id: str) -> bool:
        row = self.get(target_id)
        if row is None:
            return False
        self.session.delete(row)
        self.session.flush()
        return True

    def status_counts(self) -> dict[str, int]:
        rows = self.session.execute(
            select(MonitorTarget.status, func.count()).group_by(MonitorTarget.status)
        ).all()
        return {status: int(count) for status, count in rows}

    def type_counts(self) -> dict[str, int]:
        rows = self.session.execute(
            select(MonitorTarget.target_type, func.count()).group_by(MonitorTarget.target_type)
        ).all()
        return {kind: int(count) for kind, count in rows}

    # -------------------------------------------------------------- events

    def add_event(
        self,
        *,
        target: Optional[MonitorTarget],
        event_type: str,
        detail: str = "",
        payload: dict | None = None,
    ) -> MonitorEvent:
        row = MonitorEvent(
            target_id=target.id if target is not None else None,
            target_name=target.name if target is not None else "monitor",
            tenant_id=getattr(target, "tenant_id", None),
            event_type=event_type,
            detail=(detail or "")[:1000] or None,
            payload=payload,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_events(
        self, *, target_id: str | None = None, limit: int = 50,
        tenant_id: str | None = None, platform: bool = False,
    ) -> list[MonitorEvent]:
        stmt = select(MonitorEvent).order_by(MonitorEvent.created_at.desc()).limit(max(1, min(limit, 500)))
        if target_id:
            stmt = stmt.where(MonitorEvent.target_id == target_id)
        if platform:
            stmt = stmt.where(MonitorEvent.target_id.in_(
                select(MonitorTarget.id).where(MonitorTarget.tenant_id.is_(None))))
        elif tenant_id is not None:
            stmt = stmt.where(MonitorEvent.target_id.in_(
                select(MonitorTarget.id).where(MonitorTarget.tenant_id == tenant_id)))
        return list(self.session.execute(stmt).scalars().all())
