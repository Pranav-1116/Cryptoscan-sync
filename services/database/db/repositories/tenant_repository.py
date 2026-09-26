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
    TenantInvite,
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

    # --------------------------------------------------------------- invites

    def create_invite(self, tenant_id: str, username: str, tenant_role: str,
                      *, invited_by: str, days: int = 7,
                      email: str | None = None) -> tuple[TenantInvite, str]:
        """Create a pending invite; returns (row, raw_token) — the raw token
        is shown once and stored only as a SHA-256 hash."""
        import hashlib
        import secrets
        from datetime import timedelta

        if tenant_role not in TENANT_ROLES:
            raise TenantError(f"unknown tenant role: {tenant_role}")
        if self.membership(tenant_id, username) is not None:
            raise TenantError(f"{username} is already a member of this tenant")
        raw = "csi_" + secrets.token_urlsafe(24)
        row = TenantInvite(
            tenant_id=tenant_id,
            username=username,
            email=email,
            tenant_role=tenant_role,
            token_hash=hashlib.sha256(raw.encode()).hexdigest(),
            invited_by=invited_by,
            expires_at=utcnow() + timedelta(days=max(1, min(int(days), 30))),
        )
        self.session.add(row)
        self.session.flush()
        self.provision_event(tenant_id, "invite_create", actor=invited_by,
                             detail=f"{username}:{tenant_role}")
        return row, raw

    def invites_for(self, tenant_id: str, *, pending_only: bool = True) -> list[TenantInvite]:
        stmt = select(TenantInvite).where(TenantInvite.tenant_id == tenant_id).order_by(
            TenantInvite.created_at.desc())
        rows = list(self.session.execute(stmt).scalars().all())
        if pending_only:
            rows = [r for r in rows if not r.is_dead]
        return rows

    def get_invite_by_raw(self, raw: str) -> Optional[TenantInvite]:
        import hashlib

        return self.session.execute(
            select(TenantInvite).where(
                TenantInvite.token_hash == hashlib.sha256((raw or "").encode()).hexdigest())
        ).scalar_one_or_none()

    def accept_invite(self, raw: str, *, actor: str) -> TenantMembership:
        """Validate the token and bind the invited user to the tenant.

        Raises TenantError with a caller-friendly message on any refusal:
        unknown/expired/revoked/used token, suspended tenant. Membership
        creation goes through add_member so metering/audit stay identical
        to direct adds."""
        invite = self.get_invite_by_raw(raw)
        if invite is None or invite.is_dead:
            raise TenantError("invite is invalid, expired, revoked or already used")
        tenant = self.get(invite.tenant_id)
        if tenant is None:
            raise TenantError("invite tenant no longer exists")
        if tenant.status == "SUSPENDED":
            raise TenantError("tenant is suspended — contact platform support")
        membership = self.add_member(invite.tenant_id, invite.username,
                                     invite.tenant_role, actor=actor)
        invite.accepted_at = utcnow()
        self.session.flush()
        return membership

    def revoke_invite(self, tenant_id: str, invite_id: str) -> Optional[TenantInvite]:
        row = self.session.get(TenantInvite, invite_id)
        if row is None or row.tenant_id != tenant_id or row.accepted_at is not None:
            return None
        row.revoked_at = utcnow()
        self.session.flush()
        self.provision_event(tenant_id, "invite_revoke", actor="system",
                             detail=row.username)
        return row
