"""Pure multi-tenant SaaS policy: plans, quotas, slug rules, tenant roles.

No I/O and no FastAPI imports — every rule here is pinned by unit tests
(test_tenancy_policy.py). Repositories and routers consume these helpers so
the *policy* and its *enforcement* stay separable.
"""

from __future__ import annotations

import re

# Plan catalog (mirrors db.models.tenant.TENANT_PLANS by contract — the DB
# layer cannot import from api). None = unlimited.
PLANS: dict[str, dict[str, int | None]] = {
    "FREE": {
        "max_targets": 5,
        "max_scans_per_month": 200,
        "max_users": 3,
    },
    "PRO": {
        "max_targets": 100,
        "max_scans_per_month": 20_000,
        "max_users": 25,
    },
    "ENTERPRISE": {
        "max_targets": None,
        "max_scans_per_month": None,
        "max_users": None,
    },
}
DEFAULT_PLAN = "FREE"

# Quota kinds -> the plan limit that governs them.
KIND_LIMITS: dict[str, str] = {
    "target_create": "max_targets",
    "scan_run": "max_scans_per_month",
    "member_create": "max_users",
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def plan_limits(plan: str) -> dict[str, int | None]:
    """Limits for a plan; unknown plans degrade to FREE (never to unlimited)."""
    return PLANS.get(plan, PLANS[DEFAULT_PLAN])


def quota_check(plan: str, kind: str, current_usage: int | None) -> tuple[bool, str | None]:
    """Pure gate: is one more unit of `kind` allowed on this plan?

    current_usage None means "unknown" — for safety this *denies* only when
    the plan has a finite limit and usage is unknowable; unlimited plans
    always pass. Returns (allowed, reason).
    """
    limit = plan_limits(plan).get(KIND_LIMITS.get(kind, ""))
    if limit is None:
        return True, None
    if current_usage is None:
        return False, f"usage for {kind} unavailable while plan limits apply"
    if current_usage >= limit:
        return False, f"plan {plan} allows {limit} {KIND_LIMITS.get(kind, kind)}"
    return True, None


def normalize_slug(name: str) -> str:
    """URL-safe tenant slug: lowercase alnum, dashes collapsed."""
    slug = _SLUG_RE.sub("-", (name or "").strip().lower()).strip("-")
    return slug[:80]


def unique_slug(base: str, taken: set[str]) -> str:
    """Deterministic first-free slug (acme, acme-2, acme-3, ...)."""
    slug = normalize_slug(base) or "tenant"
    if slug not in taken:
        return slug
    n = 2
    while f"{slug}-{n}" in taken:
        n += 1
    return f"{slug}-{n}"


# ---------------------------------------------------------------- tenant roles

# Capability matrix. Read is implied by membership; mutations ladder up.
# "members:grant" = may add members up to their own role level (an admin can
# grant admin-and-below, an owner can grant owner).
ROLE_ACTIONS: dict[str, set[str]] = {
    "viewer": set(),
    "member": {"scan:create"},
    "admin": {"scan:create", "targets:manage", "members:manage", "members:grant", "keys:manage"},
    "owner": {"scan:create", "targets:manage", "members:manage", "members:grant", "keys:manage", "tenant:delete"},
}


def tenant_role_allows(role: str, action: str) -> bool:
    return action in ROLE_ACTIONS.get(role, set())


# Owners sit at the top; grantable_roles uses this ladder.
TENANT_ROLE_ORDER = ("owner", "admin", "member", "viewer")


def grantable_roles(role: str) -> tuple[str, ...]:
    """Roles `role` may hand out: strictly below itself in the ladder."""
    order = TENANT_ROLE_ORDER
    if role not in order:
        return ()
    return tuple(order[order.index(role) + 1:])
