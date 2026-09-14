"""Persistence for tenants, memberships, metering, and lifecycle events."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models.base import utcnow
from db.models.monitor import MonitorTarget
from db.models.tenant import (
    TENANT_ROLES,
    Tenant,
    TenantMembership,
    TenantProvisionEvent,
    TenantUsageEvent,
)
from db.models.user import User


class TenantError(Exception):
    pass


class TenantRepository:
    def __init__(self, session: Session):
        self.session = session

    # ---------------------------------------------------------------- tenants

    def create(self, *, name: str, slug: str, plan: str = "FREE",
               created_by: str | None = None) -> Tenant:
        row = Tenant(name=name, slug=slug, plan=plan, created_by=created_by)
        self.session.add(row)
        self.session.flush()
        self.provision_event(row.id, "signup", actor=created_by or "system",
                             detail=f"slug={slug} plan={plan}")
        return row

    def get(self, tenant_id: str) -> Optional[Tenant]:
        return self.session.get(Tenant, tenant_id)

    def get_by_slug(self, slug: str) -> Optional[Tenant]:
        return self.session.execute(
            select(Tenant).where(Tenant.slug == slug)
        ).scalar_one_or_none()

    def existing_slugs(self) -> set[str]:
        return {r[0] for r in self.session.execute(select(Tenant.slug)).all()}

    def list_tenants(self) -> list[Tenant]:
        return list(self.session.execute(
            select(Tenant).order_by(Tenant.created_at)).scalars().all())

    def set_status(self, tenant_id: str, status: str, *, actor: str,
                   reason: str | None = None) -> Optional[Tenant]:
        row = self.get(tenant_id)
        if row is None:
            return None
        row.status = status
        row.suspended_at = utcnow() if status == "SUSPENDED" else None
        row.suspend_reason = reason
        self.session.flush()
        self.provision_event(tenant_id, status.lower(), actor=actor, detail=reason)
        return row

    def set_plan(self, tenant_id: str, plan: str, *, actor: str) -> Optional[Tenant]:
        row = self.get(tenant_id)
        if row is None:
            return None
        row.plan = plan
        self.session.flush()
        self.provision_event(tenant_id, "plan_change", actor=actor, detail=plan)
        return row

    # ------------------------------------------------------------- membership

    def add_member(self, tenant_id: str, username: str, tenant_role: str,
                   *, actor: str | None = None) -> TenantMembership:
        if tenant_role not in TENANT_ROLES:
            raise TenantError(f"unknown tenant role: {tenant_role}")
        if self.membership(tenant_id, username) is not None:
            raise TenantError(f"{username} is already a member of this tenant")
        row = TenantMembership(tenant_id=tenant_id, username=username, tenant_role=tenant_role)
        self.session.add(row)
        self.session.flush()
        self.record_usage(tenant_id, "member_create", 1, detail=username)
        if actor:
            self.provision_event(tenant_id, "member_add", actor=actor, detail=f"{username}:{tenant_role}")
        return row

    def remove_member(self, tenant_id: str, username: str) -> bool:
        row = self.membership(tenant_id, username)
        if row is None:
            return False
        self.session.delete(row)
        self.session.flush()
        return True

    def membership(self, tenant_id: str, username: str) -> Optional[TenantMembership]:
        return self.session.execute(
            select(TenantMembership).where(
                TenantMembership.tenant_id == tenant_id,
                TenantMembership.username == username,
            )
        ).scalar_one_or_none()

    def memberships_of(self, username: str) -> list[TenantMembership]:
        return list(self.session.execute(
            select(TenantMembership).where(TenantMembership.username == username)
        ).scalars().all())

    def members_of(self, tenant_id: str) -> list[TenantMembership]:
        return list(self.session.execute(
            select(TenantMembership).where(TenantMembership.tenant_id == tenant_id)
            .order_by(TenantMembership.tenant_role, TenantMembership.username)
        ).scalars().all())

    def member_count(self, tenant_id: str) -> int:
        return int(self.session.execute(
            select(func.count()).select_from(TenantMembership)
            .where(TenantMembership.tenant_id == tenant_id)
        ).scalar_one())

    def owner_count(self, tenant_id: str) -> int:
        return int(self.session.execute(
            select(func.count()).select_from(TenantMembership)
            .where(TenantMembership.tenant_id == tenant_id,
                   TenantMembership.tenant_role == "owner")
        ).scalar_one())

    def ensure_user(self, username: str, *, password_hash: str | None = None,
                    email: str | None = None) -> User:
        """Fetch or create the platform user behind a membership."""
        row = self.session.execute(
            select(User).where(User.username == username)
        ).scalar_one_or_none()
        if row is not None:
            return row
        row = User(
            username=username,
            email=email,
            password_hash=password_hash or "",
            roles="viewer",
        )
        self.session.add(row)
        self.session.flush()
        return row

    # ----------------------------------------------------------------- usage

    def record_usage(self, tenant_id: str, kind: str, amount: int = 1,
                     *, detail: str | None = None) -> TenantUsageEvent:
        row = TenantUsageEvent(tenant_id=tenant_id, kind=kind, amount=amount, detail=detail)
        self.session.add(row)
        self.session.flush()
        return row

    def month_usage(self, tenant_id: str, kind: str,
                    *, now: datetime | None = None) -> int:
        """SUM(amount) for the calendar month (UTC) — deletes never shrink it."""
        now = now or utcnow()
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        total = self.session.execute(
            select(func.coalesce(func.sum(TenantUsageEvent.amount), 0)).where(
                TenantUsageEvent.tenant_id == tenant_id,
                TenantUsageEvent.kind == kind,
                TenantUsageEvent.created_at >= start,
            )
        ).scalar_one()
        return int(total)

    def usage_breakdown(self, tenant_id: str, *, now: datetime | None = None) -> dict[str, int]:
        now = now or utcnow()
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        rows = self.session.execute(
            select(TenantUsageEvent.kind, func.coalesce(func.sum(TenantUsageEvent.amount), 0)).where(
                TenantUsageEvent.tenant_id == tenant_id,
                TenantUsageEvent.created_at >= start,
            ).group_by(TenantUsageEvent.kind)
        ).all()
        return {kind: int(total) for kind, total in rows}

    def live_target_count(self, tenant_id: str) -> int:
        return int(self.session.execute(
            select(func.count()).select_from(MonitorTarget)
            .where(MonitorTarget.tenant_id == tenant_id)
        ).scalar_one())

    # -------------------------------------------------------------- lifecycle

    def provision_event(self, tenant_id: str, action: str, *, actor: str,
                        detail: str | None = None) -> TenantProvisionEvent:
        row = TenantProvisionEvent(
            tenant_id=tenant_id, action=action, actor=actor, detail=detail,
            occurred_at=datetime.now(timezone.utc),
        )
        self.session.add(row)
        self.session.flush()
        return row

    def provision_timeline(self, tenant_id: str) -> list[TenantProvisionEvent]:
        return list(self.session.execute(
            select(TenantProvisionEvent).where(TenantProvisionEvent.tenant_id == tenant_id)
            .order_by(TenantProvisionEvent.occurred_at)
        ).scalars().all())
