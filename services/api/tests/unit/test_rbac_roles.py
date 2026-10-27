"""RBAC — the spec's 8-role catalog + permission matrix."""

from __future__ import annotations

import pytest

from api.security.rbac import (
    ALL_PERMISSIONS,
    PERMISSION_MATRIX,
    ROLE_CATALOG,
    has_permission,
    normalize_roles,
    permissions_for_roles,
    roles_for_action,
)


def test_catalog_has_exactly_the_8_spec_roles():
    assert set(ROLE_CATALOG) == {
        "superadmin",
        "ciso",
        "security_analyst",
        "developer",
        "auditor",
        "business_owner",
        "scanner",
        "readonly",
    }


def test_legacy_aliases_resolve():
    assert normalize_roles(["admin"]) == ["superadmin"]
    assert normalize_roles(["viewer"]) == ["readonly"]
    assert normalize_roles(["ADMIN", "Viewer", "ciso"]) == ["superadmin", "readonly", "ciso"]


def test_unknown_roles_dropped_not_crashed():
    assert normalize_roles(["admin", "mystery-role", ""]) == ["superadmin"]
    assert normalize_roles(None) == []
    assert normalize_roles([]) == []


def test_duplicates_removed():
    assert normalize_roles(["auditor", "auditor", "Auditor"]) == ["auditor"]


def test_matrix_is_complete_and_consistent():
    # Every action grants at least one role, and every granted role is real.
    for action, roles in PERMISSION_MATRIX.items():
        assert roles, f"{action} grants nobody"
        assert roles <= set(ROLE_CATALOG), f"{action} grants unknown role(s)"
    # The two legacy admin-only endpoints keep working through aliases.
    assert "superadmin" in roles_for_action("users.manage")
    assert "superadmin" in roles_for_action("api_keys.manage")


def test_has_permission_semantics():
    assert has_permission(["superadmin"], "users.manage")
    assert has_permission(["admin"], "users.manage")  # legacy alias
    assert not has_permission(["auditor"], "users.manage")
    assert has_permission(["auditor"], "audit.read")
    assert has_permission(["security_analyst"], "exceptions.create")
    assert has_permission(["business_owner"], "exceptions.create")
    assert not has_permission(["readonly"], "exceptions.create")
    assert has_permission(["scanner"], "scan.trigger")
    assert not has_permission(["scanner"], "baseline.approve")
    assert has_permission(["readonly"], "findings.read")
    assert not has_permission(["readonly"], "drift.acknowledge")
    assert not has_permission(["developer"], "policy.configure")


def test_permissions_for_roles():
    perms = set(permissions_for_roles(["auditor"]))
    assert "audit.read" in perms and "reports.read" in perms
    assert "users.manage" not in perms
    super_perms = set(permissions_for_roles(["admin"]))  # legacy alias
    assert "users.manage" in super_perms and "platform.configure" in super_perms
    assert "scan.trigger" in super_perms
    # superadmin must cover every action in the matrix
    assert set(permissions_for_roles(["superadmin"])) == ALL_PERMISSIONS


def test_every_spec_role_has_at_least_one_permission():
    for role in ROLE_CATALOG:
        assert permissions_for_roles([role]), f"{role} has no permissions"
