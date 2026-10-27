"""Custom roles (report 13 §2.2 open item, round 30).

A custom role is a named permission SUBSET of the existing matrix: a
narrower key, never a bypass. Pure-function tests first, then the full
lifecycle through the real app: define → assign → enforce → update →
revoke.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings
from api.security.rbac import (ALL_PERMISSIONS, custom_role_names, has_permission,
                               has_permission_with_custom,
                               permissions_for_roles, permissions_with_custom)


# ------------------------------------------------------------------ #
# pure core
# ------------------------------------------------------------------ #

def test_custom_grant_honored_without_builtin_role():
    index = {"crypto-operator": frozenset({"crypto.read", "scan.trigger"})}
    roles = ["crypto-operator"]
    # the builtin matrix alone says no
    assert has_permission(roles, "crypto.read") is False
    # with the custom index, the declared grant applies
    assert has_permission_with_custom(roles, "crypto.read", index) is True
    # undeclared actions stay denied — a subset, never a superset
    assert has_permission_with_custom(roles, "users.manage", index) is False


def test_builtin_matrix_still_wins_first():
    index = {"almost-ciso": frozenset({"crypto.read"})}
    assert has_permission_with_custom(["ciso"], "crypto.read", index) is True
    assert has_permission_with_custom(["ciso"], "api_keys.manage", index) is True


def test_permissions_with_custom_unions_grants():
    index = {"scan-only": frozenset({"scan.trigger"})}
    base = permissions_for_roles(["auditor"])
    extended = permissions_with_custom(["auditor", "scan-only"], index)
    assert set(base) <= set(extended)
    assert "scan.trigger" in extended
    assert "users.manage" not in extended


def test_custom_role_names_recovers_defined_names_only():
    index = {"crypto-operator": frozenset({"crypto.read"})}
    raw = ["auditor", "crypto-operator", "made-up-role"]
    assert custom_role_names(raw, index) == ["crypto-operator"]
    assert custom_role_names(raw, {}) == []


def test_empty_and_none_index_is_safe():
    assert has_permission_with_custom(["ciso"], "crypto.read", None) is True
    assert has_permission_with_custom(["nobody"], "crypto.read", None) is False


def test_load_index_drops_stale_permissions(tmp_path):
    """A stale row (permission removed from the matrix) grants nothing."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import db.models  # noqa: F401 — register tables
    from api.security.rbac import load_custom_roles_index
    from db.connection.session import Base
    from db.models.custom_role import CustomRole

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(CustomRole(name="stale-role",
                           permissions=["crypto.read", "no.such.permission"]))
    session.commit()
    index = load_custom_roles_index(session)
    assert index["stale-role"] == frozenset({"crypto.read"})
    session.close()


# ------------------------------------------------------------------ #
# full lifecycle through the real app
# ------------------------------------------------------------------ #


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    db_url = f"sqlite:///{tmp_path}/custom_roles.db"
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()

    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None

    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client


def _seed_membership(db_url: str, username: str) -> None:
    """Give an API-created user the one tenant membership the SaaS layer
    requires (env-admin is platform-context; real users are tenancy-gated)."""
    import uuid

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 — register tables
    from db.models.tenant import Tenant, TenantMembership

    eng = create_engine(db_url)
    Session = sessionmaker(bind=eng)
    session = Session()
    tenant = Tenant(name="Acme Corp", slug=f"acme-{uuid.uuid4().hex[:8]}",
                    plan="ENTERPRISE", status="ACTIVE", created_by="admin")
    session.add(tenant)
    session.flush()
    session.add(TenantMembership(tenant_id=tenant.id, username=username,
                                 tenant_role="member"))
    session.commit()
    session.close()
    eng.dispose()


def _login(client, username, password):
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_custom_role_full_lifecycle(sqlite_app):
    client = sqlite_app
    admin = _login(client, "admin", "cryptoscan")

    # validation: unknown permission, builtin-name collision, duplicate
    bad_perm = client.post("/api/v1/auth/custom-roles", headers=admin,
                           json={"name": "crypto-operator",
                                 "permissions": ["crypto.read", "not.a.permission"]})
    assert bad_perm.status_code == 422
    collision = client.post("/api/v1/auth/custom-roles", headers=admin,
                            json={"name": "ciso", "permissions": ["crypto.read"]})
    assert collision.status_code == 409

    # create the role
    created = client.post("/api/v1/auth/custom-roles", headers=admin,
                          json={"name": "crypto-operator",
                                "description": "trigger scans, read crypto state",
                                "permissions": ["crypto.read", "scan.trigger"]})
    assert created.status_code == 200, created.text
    assert created.json()["permissions"] == ["crypto.read", "scan.trigger"]

    # the roles surface publishes custom roles + the full catalog
    roles_view = client.get("/api/v1/auth/roles", headers=admin)
    assert roles_view.status_code == 200
    assert roles_view.json()["custom_roles"] == {
        "crypto-operator": ["crypto.read", "scan.trigger"]}
    assert set(roles_view.json()["all_permissions"]) == set(ALL_PERMISSIONS)

    # assign to a new user (would have been 422 before custom roles)
    user = client.post("/api/v1/auth/users", headers=admin,
                       json={"username": "opuser", "password": "operator-pass-123",
                             "roles": ["crypto-operator"]})
    assert user.status_code == 201, user.text

    # enforcement: the granted permission passes, an ungranted one fails
    _seed_membership(get_settings().DATABASE_URL, "opuser")
    op = _login(client, "opuser", "operator-pass-123")
    state = client.get("/api/v1/crypto/live/state", headers=op)
    assert state.status_code == 200, state.text
    denied = client.get("/api/v1/auth/users", headers=op)
    assert denied.status_code == 403
    assert "admin" in denied.json()["detail"]

    # my_permissions reflects the custom grants
    me = client.get("/api/v1/auth/me", headers=op)
    assert me.status_code == 200
    assert set(me.json()["roles"]) == {"crypto-operator"}

    # update: narrow the role to read-only — takes effect on the NEXT
    # request (roles are read fresh), no re-login needed
    updated = client.put("/api/v1/auth/custom-roles/crypto-operator", headers=admin,
                         json={"permissions": ["crypto.read"]})
    assert updated.status_code == 200
    assert updated.json()["permissions"] == ["crypto.read"]
    state_again = client.get("/api/v1/crypto/live/state", headers=op)
    assert state_again.status_code == 200

    # delete: the grants disappear immediately
    deleted = client.delete("/api/v1/auth/custom-roles/crypto-operator", headers=admin)
    assert deleted.status_code == 200
    gone = client.get("/api/v1/crypto/live/state", headers=op)
    assert gone.status_code == 403

    # and the custom role name is no longer assignable
    stale = client.post("/api/v1/auth/users", headers=admin,
                        json={"username": "opuser2", "password": "operator-pass-123",
                              "roles": ["crypto-operator"]})
    assert stale.status_code == 422
