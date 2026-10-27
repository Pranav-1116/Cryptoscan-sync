"""Resource-level access grants (report 13 §2.2): per-system permissions.

Covers the grant semantics directly (repository) and the endpoint behavior
end to end: unrestricted systems unchanged, grant-restricted systems
enforce viewer/operator/owner, platform superadmin/auditor bypass rules,
first-grant switches a system into restricted mode, last-revoke switches
it back out.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session, require_admin
from api.main import create_app
from db.connection.session import Base
from db.models.system import System
from db.models.user import User
from db.repositories.resource_grant_repository import ResourceGrantRepository

SECRET = "grant-test-secret-key-" + "x" * 14


def _make_app(current_user="op-user", admin_override=True):
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", SECRET)
    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    # seed the users the role lookups resolve (developer = no platform bypass)
    session.add(User(username="op-user", roles="developer", password_hash="x"))
    session.add(User(username="boss", roles="superadmin", password_hash="x"))
    session.add(User(username="watcher", roles="auditor", password_hash="x"))
    session.add(User(username="admin", roles="superadmin", password_hash="x"))
    session.add(System(id="sys-pay", name="payments", environment="prod",
                       scan_target="https://github.com/org/payments.git"))
    session.add(System(id="sys-open", name="intranet", environment="dev",
                       scan_target="https://github.com/org/intranet.git"))
    session.commit()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: current_user
    if admin_override:
        app.dependency_overrides[require_admin] = lambda: current_user
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


# ---------------------------------------------------------------- repository

def test_repository_grant_semantics():
    from sqlalchemy.orm import Session as _S  # noqa: F401
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    grants = ResourceGrantRepository(session)

    assert grants.check_access("dev1", "SYSTEM", "sys-1", "viewer") is True, "unrestricted by default"
    grants.grant("dev1", "SYSTEM", "sys-1", "viewer", granted_by="admin")
    assert grants.is_restricted("SYSTEM", "sys-1") is True
    assert grants.check_access("dev1", "SYSTEM", "sys-1", "viewer") is True
    assert grants.check_access("dev1", "SYSTEM", "sys-1", "operator") is False
    assert grants.check_access("nobody", "SYSTEM", "sys-1", "viewer") is False
    # upsert promotes in place
    grants.grant("dev1", "SYSTEM", "sys-1", "operator")
    assert grants.effective_role("dev1", "SYSTEM", "sys-1") == "operator"
    assert grants.check_access("dev1", "SYSTEM", "sys-1", "operator") is True
    # owner outranks operator
    grants.grant("lead", "SYSTEM", "sys-1", "owner")
    assert grants.check_access("lead", "SYSTEM", "sys-1", "operator") is True
    # invalid role rejected
    with pytest.raises(ValueError):
        grants.grant("dev1", "SYSTEM", "sys-1", "emperor")
    # revoke last grant -> unrestricted again
    assert grants.revoke("dev1", "SYSTEM", "sys-1") is True
    assert grants.revoke("lead", "SYSTEM", "sys-1") is True
    assert grants.is_restricted("SYSTEM", "sys-1") is False
    assert grants.check_access("nobody", "SYSTEM", "sys-1", "viewer") is True
    engine.dispose()


# ---------------------------------------------------------------- endpoints

@pytest.mark.asyncio
async def test_unrestricted_system_behaves_as_before():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/systems/sys-open")
        assert resp.status_code == 200, resp.text
        assert resp.json()["name"] == "intranet"
        # developer with no grants can still PATCH an unrestricted system
        patch = await client.patch("/api/v1/systems/sys-open", json={"owner": "ops"})
        assert patch.status_code == 200, patch.text
    engine.dispose()


@pytest.mark.asyncio
async def test_grant_restriction_blocks_and_allows_by_role():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # admin puts sys-pay under grant control with op-user as viewer
        created = await client.post(
            "/api/v1/systems/sys-pay/grants", json={"subject": "op-user", "role": "viewer"})
        assert created.status_code == 200, created.text
        assert created.json()["restricted"] is True

        # op-user (viewer) can read the system but not write it
        read = await client.get("/api/v1/systems/sys-pay")
        assert read.status_code == 200
        patch = await client.patch("/api/v1/systems/sys-pay", json={"owner": "x"})
        assert patch.status_code == 403, "viewer must not write"
        assert "grant-restricted" in patch.json()["detail"]

        # promote to operator -> write passes
        await client.post("/api/v1/systems/sys-pay/grants", json={"subject": "op-user", "role": "operator"})
        patch2 = await client.patch("/api/v1/systems/sys-pay", json={"owner": "x"})
        assert patch2.status_code == 200, patch2.text

        # a developer with no grant at all is locked out of reads too
        app.dependency_overrides[get_current_user] = lambda: "stranger"
        denied = await client.get("/api/v1/systems/sys-pay")
        assert denied.status_code == 403
        # ...but the unrestricted system still opens
        assert (await client.get("/api/v1/systems/sys-open")).status_code == 200
    engine.dispose()


@pytest.mark.asyncio
async def test_platform_roles_bypass_grants():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/v1/systems/sys-pay/grants", json={"subject": "someone-else", "role": "owner"})

        # superadmin bypasses everything, grants or no grants
        app.dependency_overrides[get_current_user] = lambda: "boss"
        assert (await client.get("/api/v1/systems/sys-pay")).status_code == 200
        assert (await client.patch("/api/v1/systems/sys-pay", json={"owner": "b"})).status_code == 200

        # auditor passes READ gates but is still refused writes
        app.dependency_overrides[get_current_user] = lambda: "watcher"
        assert (await client.get("/api/v1/systems/sys-pay")).status_code == 200
        assert (await client.patch("/api/v1/systems/sys-pay", json={"owner": "w"})).status_code == 403
    engine.dispose()


@pytest.mark.asyncio
async def test_revoke_last_grant_unrestricts_and_audits():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/v1/systems/sys-pay/grants", json={"subject": "op-user", "role": "owner"})
        listing = await client.get("/api/v1/systems/sys-pay/grants")
        assert listing.status_code == 200
        assert listing.json()["restricted"] is True
        assert listing.json()["grants"][0]["role"] == "owner"

        revoked = await client.delete("/api/v1/systems/sys-pay/grants/op-user")
        assert revoked.status_code == 200
        assert revoked.json()["restricted"] is False, "last revoke returns to unrestricted"

        # and the audit chain recorded the whole lifecycle
        from db.models.user import AuditLog

        actions = [row.action for row in session.query(AuditLog).order_by(AuditLog.created_at).all()]
        assert "system.restrict" in actions
        assert "system.unrestrict" in actions

        # unknown grant revoke -> 404
        assert (await client.delete("/api/v1/systems/sys-pay/grants/ghost")).status_code == 404
    engine.dispose()


@pytest.mark.asyncio
async def test_invalid_grant_role_is_rejected():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/systems/sys-pay/grants", json={"subject": "x", "role": "emperor"})
        assert resp.status_code == 422
        assert "role must be" in resp.json()["detail"]
        # the failed grant must not have restricted the system
        assert (await client.get("/api/v1/systems/sys-pay")).status_code == 200
    engine.dispose()
