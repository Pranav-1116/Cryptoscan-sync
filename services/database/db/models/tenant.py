"""Multi-tenant SaaS core: tenants, memberships, usage metering.

A tenant (organization) owns its scan surface. Isolation is enforced at the
data layer (tenant_id columns + repository filters) and at the request layer
(api.dependencies.TenantContext) — a tenant member can never read or write
another tenant's rows, and cross-tenant access is a 404, never a 403 (no
existence oracle). Platform operators (superadmin) keep a global estate for
single-tenant/on-prem stores: rows with a NULL tenant_id.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantOwned

# Tenant plans. Limits are policy — pinned by api tests via
# api.security.tenancy (the api-side pure engine mirrors this catalog by
# contract, like VALID_ROLES does for RBAC).
TENANT_PLANS = ("FREE", "PRO", "ENTERPRISE")
TENANT_STATUSES = ("ACTIVE", "SUSPENDED")
# Tenant-scoped roles (independent of the platform RBAC catalog): a tenant
# owner is not a platform superadmin.
TENANT_ROLES = ("owner", "admin", "member", "viewer")


# platform-scope: the tenant registry itself — it defines the scoping axis
# and must be readable while resolving which tenant a request belongs to.
class Tenant(BaseModel):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)
    plan: Mapped[str] = mapped_column(String(20), nullable=False, default="FREE", index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", index=True)
    created_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suspend_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)


# platform-scope: memberships are resolved by username *before* a tenant is
# known — login enumerates every tenant a user belongs to; the caller then scopes
# every subsequent read to the tenant it resolved.
class TenantMembership(BaseModel, TenantOwned):
    __tablename__ = "tenant_memberships"
    __table_args__ = (
        UniqueConstraint("tenant_id", "username", name="uq_tenant_member"),
        Index("ix_memberships_username", "username"),
    )

    username: Mapped[str] = mapped_column(String(100), nullable=False)
    tenant_role: Mapped[str] = mapped_column(String(20), nullable=False, default="member")


# platform-scope: metering is written by the platform control plane on behalf of
# whichever tenant consumed the unit, and read per tenant with an explicit
# tenant filter; it is the billing input, not tenant data a request may browse.
class TenantUsageEvent(BaseModel, TenantOwned):
    """Append-only per-tenant metering trail (plan enforcement + billing input).

    kind is a meter name (e.g. "scan_run", "target_create", "member_create");
    amount lets one event carry N units. Counts are SUM(amount) over the
    calendar month — never inferred from row counts that deletes would shrink.
    """

    __tablename__ = "tenant_usage_events"
    __table_args__ = (Index("ix_usage_tenant_kind_time", "tenant_id", "kind", "created_at"),)

    kind: Mapped[str] = mapped_column(String(60), nullable=False)
    amount: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    detail: Mapped[str | None] = mapped_column(String(300), nullable=True)


# platform-scope: tenant lifecycle (signup, suspend, restore, plan change) is
# recorded by the platform actor outside any single tenant's request context.
class TenantProvisionEvent(BaseModel, TenantOwned):
    """Audit trail for tenant lifecycle (signup, suspend, restore, plan change).

    The platform-wide audit log stays actor/action-shaped; this gives the SaaS
    control plane its own per-tenant lifecycle timeline.
    """

    __tablename__ = "tenant_provision_events"

    action: Mapped[str] = mapped_column(String(60), nullable=False)
    actor: Mapped[str] = mapped_column(String(100), nullable=False)
    detail: Mapped[str | None] = mapped_column(String(500), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


# platform-scope: an invite is looked up by token hash before the tenant is
# known — accepting the invite is how the tenant becomes known.
class TenantInvite(BaseModel, TenantOwned):
    """A pending invitation to join a tenant.

    The raw token is shown ONCE at creation (like API keys) and only its
    SHA-256 hash is stored. Accepting binds the invited username to the
    tenant with the invited role. Expired/accepted/revoked invites are dead
    tokens — accept refuses them.
    """

    __tablename__ = "tenant_invites"
    __table_args__ = (Index("ix_invites_tenant_pending", "tenant_id", "accepted_at"),)

    username: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    tenant_role: Mapped[str] = mapped_column(String(20), nullable=False, default="member")
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    invited_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_dead(self) -> bool:
        from db.models.base import utcnow
        from shared_models.chrono import aware

        expires = aware(self.expires_at) or utcnow()
        return (self.accepted_at is not None or self.revoked_at is not None
                or expires <= utcnow())
