"""Pure tenancy policy: plans, quotas, slugs, tenant roles (no I/O)."""

from __future__ import annotations

from api.security.tenancy import (
    KIND_LIMITS,
    PLANS,
    grantable_roles,
    normalize_slug,
    plan_limits,
    quota_check,
    tenant_role_allows,
    unique_slug,
)


def test_plan_catalog_is_honest():
    assert set(PLANS) == {"FREE", "PRO", "ENTERPRISE"}
    # enterprise is unlimited, not a bigger number
    assert PLANS["ENTERPRISE"]["max_targets"] is None
    assert PLANS["ENTERPRISE"]["max_scans_per_month"] is None
    # ladders increase
    assert PLANS["FREE"]["max_targets"] < PLANS["PRO"]["max_targets"]
    assert PLANS["FREE"]["max_scans_per_month"] < PLANS["PRO"]["max_scans_per_month"]


def test_plan_limits_degrade_to_free_never_unlimited():
    limits = plan_limits("GOLD")  # unknown plan
    assert limits == PLANS["FREE"]
    assert limits["max_targets"] is not None


def test_quota_check_boundaries():
    limit = PLANS["FREE"]["max_targets"]
    ok, reason = quota_check("FREE", "target_create", limit - 1)
    assert ok and reason is None
    ok, reason = quota_check("FREE", "target_create", limit)
    assert not ok and str(limit) in reason and "max_targets" in reason
    # unknown usage on a finite plan denies (fail closed), unlimited passes
    assert quota_check("FREE", "target_create", None)[0] is False
    assert quota_check("ENTERPRISE", "target_create", None)[0] is True
    # every meter kind maps to a real plan limit
    assert set(KIND_LIMITS.values()) <= set(next(iter(PLANS.values())))


def test_slug_normalization_and_uniqueness():
    assert normalize_slug("  Acme Corp & Co!  ") == "acme-corp-co"
    assert normalize_slug("___") == ""
    assert unique_slug("", set()) == "tenant"
    taken = {"acme"}
    assert unique_slug("Acme", taken) == "acme-2"
    taken.add("acme-2")
    assert unique_slug("Acme", taken) == "acme-3"


def test_tenant_role_ladder():
    assert grantable_roles("owner") == ("admin", "member", "viewer")
    assert grantable_roles("admin") == ("member", "viewer")
    assert grantable_roles("member") == ("viewer",)
    assert grantable_roles("viewer") == ()
    assert grantable_roles("intruder") == ()
    assert tenant_role_allows("owner", "tenant:delete")
    assert not tenant_role_allows("admin", "tenant:delete")
    assert tenant_role_allows("member", "scan:create")
    assert not tenant_role_allows("viewer", "scan:create")
