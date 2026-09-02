"""IAM authorization logic — ABAC on top of the existing RBAC role catalog.

RBAC (api.security.rbac) decides *which actions a role may perform*. This
layer decides *over which scope* (Region -> Business Unit -> Environment ->
Asset) a subject may perform them, and enforces tenant isolation.

Enforcement is fail-closed: an action is allowed only if an explicit,
active ``allow`` grant matches, no ``deny`` grant matches, the tenant is
active, and (for data-residency) the resource region is permitted for the
tenant. Grants are hierarchical — a grant at region level covers every
business unit / environment / asset under it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SCOPE_LEVELS = ("region", "business_unit", "environment", "asset_id")


@dataclass(frozen=True)
class Scope:
    region: str | None = None
    business_unit: str | None = None
    environment: str | None = None
    asset_id: str | None = None
    tenant_id: str | None = None


def _action_matches(granted_actions: list[str] | None, action: str) -> bool:
    if not granted_actions:
        return False
    return "*" in granted_actions or action in granted_actions


def _scope_covers(grant: Scope, target: Scope) -> bool:
    """True if a grant's (hierarchical) scope covers the target scope.

    A grant with a field set to None is unconstrained at that level. A grant
    with a field set constrains that level; deeper levels must match only if
    the grant specifies them (i.e. a region grant covers all sub-levels).
    """
    for level in SCOPE_LEVELS:
        gval = getattr(grant, level)
        tval = getattr(target, level)
        if gval is not None and gval != tval:
            return False
    return True


def is_authorized(
    grants: list[dict[str, Any]],
    *,
    username: str,
    roles: list[str],
    action: str,
    target: Scope,
) -> tuple[bool, str]:
    """Fail-closed authorization decision over explicit grants.

    ``grants`` are dicts with keys: subject, subject_type, actions, effect,
    is_active, region, business_unit, environment, asset_id, tenant_id.
    Decision order: explicit deny overrides allow; otherwise allow only on a
    matching active allow grant.
    """
    def belongs_to(grant: dict) -> bool:
        stype = grant.get("subject_type", "user")
        subj = grant.get("subject")
        if stype == "role":
            return subj in roles or subj == "*"
        return subj == username or subj == "*"

    active = [g for g in grants if g.get("is_active", True) and belongs_to(g)]
    # tenant isolation: grant tenant_id None means cross-tenant/platform; else must match
    tenant_scoped = [
        g for g in active
        if g.get("tenant_id") is None or g.get("tenant_id") == target.tenant_id
    ]

    allows, denies = [], []
    for g in tenant_scoped:
        if not _action_matches(g.get("actions"), action):
            continue
        gscope = Scope(region=g.get("region"), business_unit=g.get("business_unit"),
                       environment=g.get("environment"), asset_id=g.get("asset_id"),
                       tenant_id=g.get("tenant_id"))
        if not _scope_covers(gscope, target):
            continue
        (denies if g.get("effect", "allow") == "deny" else allows).append(g)

    if denies:
        return False, "denied by explicit deny grant"
    if allows:
        return True, "allowed by matching grant"
    return False, "no matching grant (fail-closed)"


def residency_permitted(tenant: dict[str, Any] | None, region: str | None) -> bool:
    """Data-residency / sovereignty check: a resource region must be in the
    tenant's allowed processing regions (or unrestricted)."""
    if tenant is None:
        return True
    if not tenant.get("is_active", True):
        return False
    allowed = tenant.get("processing_regions") or []
    if not allowed:
        return True  # unrestricted tenant
    if region is None:
        return True  # regionless/platform data
    return region in allowed
