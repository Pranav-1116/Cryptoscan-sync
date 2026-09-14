"""Multi-tenant SaaS: isolation, quotas, suspension, signup, members.

The core guarantee under test: tenant data is invisible to other tenants —
not "403 forbidden", but *absent* (404 / not in listings), so no existence
oracle leaks the platform's tenant registry.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_db_session
from api.main import create_app
from db.connection.session import Base

STRONG_PW = "founder-pw-Str0ng!"


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _act_as(client, session, username: str, roles: str = "readonly"):
    """Authenticate the client as `username` with a REAL signed session.

    No dependency overrides: the token flows through get_current_user and
    every role gate exactly like production (test env accepts the HMAC token
    without a server-side session row)."""
    from api.security.session_manager import SessionManager
    from db.repositories.user_repository import UserRepository

    if UserRepository(session).get_by_username(username) is None:
        UserRepository(session).create_user(username, "x", roles=[roles])
        session.commit()
    token = SessionManager().create_session(username, roles=[roles])
    client.headers["Authorization"] = f"Bearer {token}"


async def _signup(client, org, username, password=STRONG_PW):
    return await client.post("/api/v1/saas/signup", json={
        "org_name": org, "username": username, "password": password,
        "email": f"{username}@example.io"})


async def _create_target(client, name, tenant_id=None):
    headers = {"X-Tenant-ID": tenant_id} if tenant_id else {}
    return await client.post("/api/v1/monitor/targets", headers=headers, json={
        "name": name, "target_type": "NETWORK",
        "config": {"endpoints": [f"{name.replace('_', '-')}.example.io:443"]}})


@pytest.mark.asyncio
async def test_signup_provisions_tenant_and_owner():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await _signup(client, "Acme Corp", "founder")
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["tenant"]["slug"] == "acme-corp"
        assert body["tenant_role"] == "owner"

        # same org name from another founder -> deterministic free slug
        r2 = await _signup(client, "Acme Corp", "second-founder")
        assert r2.status_code == 201, r2.text
        assert r2.json()["tenant"]["slug"] == "acme-corp-2"

        # weak password refused
        r3 = await _signup(client, "Weak Co", "weak-founder", password="short")
        assert r3.status_code == 422

        # existing username with WRONG password: no membership pollution
        r4 = await _signup(client, "Evil Co", "founder", password="attacker-pw-12345")
        assert r4.status_code == 401


@pytest.mark.asyncio
async def test_tenant_isolation_is_total():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        a = (await _signup(client, "Alpha", "alice")).json()["tenant"]["id"]
        b = (await _signup(client, "Beta", "bob")).json()["tenant"]["id"]

        _act_as(client, session, "alice")
        ta = (await _create_target(client, "alpha-edge", tenant_id=a)).json()
        assert (await _create_target(client, "alpha-edge-2", tenant_id=a)).status_code == 201

        _act_as(client, session, "bob")
        tb = (await _create_target(client, "beta-edge", tenant_id=b)).json()

        # bob sees only his target; alpha's names simply do not exist for him
        listed = (await client.get("/api/v1/monitor/targets", headers={"X-Tenant-ID": b})).json()["targets"]
        assert [t["name"] for t in listed] == ["beta-edge"]
        assert (await client.patch(f"/api/v1/monitor/targets/{ta['id']}",
                                   json={"enabled": False})).status_code == 404
        assert (await client.delete(f"/api/v1/monitor/targets/{ta['id']}")).status_code == 404
        assert (await client.post(f"/api/v1/monitor/targets/{ta['id']}/scan-now")).status_code == 404
        # alice's tenant id is not bob's: header for a foreign tenant -> 404
        assert (await client.get("/api/v1/monitor/targets",
                                 headers={"X-Tenant-ID": a})).status_code == 404

        # status + events are scoped too
        status = (await client.get("/api/v1/monitor/status", headers={"X-Tenant-ID": b})).json()
        assert status["overview"]["targets_total"] == 1
        assert status["overview"]["tenant_id"] == b

        # back in alice's context: her targets are intact, bob's invisible
        _act_as(client, session, "alice")
        listed_a = (await client.get("/api/v1/monitor/targets", headers={"X-Tenant-ID": a})).json()["targets"]
        assert {t["name"] for t in listed_a} == {"alpha-edge", "alpha-edge-2"}
        events = (await client.get("/api/v1/monitor/events", headers={"X-Tenant-ID": a})).json()["events"]
        assert all(e["target_id"] not in {tb["id"]} for e in events)


@pytest.mark.asyncio
async def test_platform_admin_sees_platform_estate_and_can_operate_tenants():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        a = (await _signup(client, "Alpha", "alice")).json()["tenant"]["id"]
        _act_as(client, session, "alice", roles="readonly")
        await _create_target(client, "alpha-edge", tenant_id=a)

        # platform estate (superadmin, no header): sees platform rows only
        _act_as(client, session, "root", roles="superadmin")
        platform_targets = (await client.post("/api/v1/monitor/targets", json={
            "name": "platform-core", "target_type": "NETWORK",
            "config": {"endpoints": ["core.example:443"]}})).json()
        listed = (await client.get("/api/v1/monitor/targets")).json()["targets"]
        assert [t["name"] for t in listed] == ["platform-core"]
        assert platform_targets["tenant_id"] is None

        # with the tenant header the operator works inside the tenant
        as_alpha = (await client.get("/api/v1/monitor/targets",
                                     headers={"X-Tenant-ID": a})).json()["targets"]
        assert [t["name"] for t in as_alpha] == ["alpha-edge"]

        # tenant registry is admin-visible with honest counts
        tenants = (await client.get("/api/v1/saas/admin/tenants")).json()["tenants"]
        alpha = next(t for t in tenants if t["id"] == a)
        assert alpha["members"] == 1 and alpha["targets"] == 1 and alpha["plan"] == "FREE"

        # plan bump then suspend / restore
        assert (await client.post(f"/api/v1/saas/admin/tenants/{a}/plan",
                                  json={"plan": "PRO"})).status_code == 200
        assert (await client.post(f"/api/v1/saas/admin/tenants/{a}/suspend",
                                  json={"reason": "payment overdue"})).status_code == 200
        _act_as(client, session, "alice", roles="readonly")
        suspended = await client.get("/api/v1/saas/whoami", headers={"X-Tenant-ID": a})
        assert suspended.status_code == 423, suspended.text
        assert (await client.get("/api/v1/monitor/targets",
                                 headers={"X-Tenant-ID": a})).status_code == 423
        _act_as(client, session, "root", roles="superadmin")
        assert (await client.post(f"/api/v1/saas/admin/tenants/{a}/restore")).status_code == 200
        _act_as(client, session, "alice", roles="readonly")
        assert (await client.get("/api/v1/saas/whoami",
                                 headers={"X-Tenant-ID": a})).status_code == 200


@pytest.mark.asyncio
async def test_free_plan_quotas_enforce_with_402():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        a = (await _signup(client, "Small Co", "owner1")).json()["tenant"]["id"]
        _act_as(client, session, "owner1")

        from api.security.tenancy import PLANS

        limit = PLANS["FREE"]["max_targets"]
        for i in range(limit):
            r = await _create_target(client, f"edge-{i}", tenant_id=a)
            assert r.status_code == 201, r.text
        over = await _create_target(client, "edge-over", tenant_id=a)
        assert over.status_code == 402, over.text
        assert "quota_exceeded" in over.json()["detail"]

        # usage endpoint mirrors the meters honestly
        usage = (await client.get("/api/v1/saas/usage", headers={"X-Tenant-ID": a})).json()
        assert usage["meters"]["targets"]["used"] == limit
        assert usage["meters"]["targets"]["remaining"] == 0

        # seat quota: FREE allows 3 users; owner + 2 more, the 4th -> 402
        assert (await client.post("/api/v1/saas/members", headers={"X-Tenant-ID": a}, json={
            "username": "member-a", "tenant_role": "member",
            "password": "member-pw-Str0ng!"})).status_code == 201
        assert (await client.post("/api/v1/saas/members", headers={"X-Tenant-ID": a}, json={
            "username": "member-b", "tenant_role": "viewer",
            "password": "viewer-pw-Str0ng!"})).status_code == 201
        full = await client.post("/api/v1/saas/members", headers={"X-Tenant-ID": a}, json={
            "username": "member-c", "tenant_role": "viewer"})
        assert full.status_code == 402, full.text


@pytest.mark.asyncio
async def test_member_roles_gates_and_owner_protection():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        a = (await _signup(client, "Roles Co", "chief")).json()["tenant"]["id"]
        _act_as(client, session, "chief")
        assert (await client.post("/api/v1/saas/members", headers={"X-Tenant-ID": a}, json={
            "username": "admin2", "tenant_role": "admin",
            "password": "gatekeep-pw-Str0ng!"})).status_code == 201
        assert (await client.post("/api/v1/saas/members", headers={"X-Tenant-ID": a}, json={
            "username": "peep", "tenant_role": "viewer",
            "password": "viewer-pw-Str0ng!"})).status_code == 201

        # admin cannot grant owner (ladder)
        _act_as(client, session, "admin2")
        denied = await client.post("/api/v1/saas/members", headers={"X-Tenant-ID": a}, json={
            "username": "upstart", "tenant_role": "owner"})
        assert denied.status_code == 403, denied.text

        # viewer may read but not create targets or manage members
        _act_as(client, session, "peep")
        assert (await _create_target(client, "peep-edge", tenant_id=a)).status_code == 403
        assert (await client.post("/api/v1/saas/members", headers={"X-Tenant-ID": a}, json={
            "username": "x1", "tenant_role": "viewer"})).status_code == 403
        assert (await client.get("/api/v1/monitor/targets",
                                 headers={"X-Tenant-ID": a})).status_code == 200

        # owner protection: admin cannot remove the owner; last owner cannot be removed
        _act_as(client, session, "admin2")
        assert (await client.delete("/api/v1/saas/members/chief",
                                    headers={"X-Tenant-ID": a})).status_code == 403
        _act_as(client, session, "chief")
        assert (await client.delete("/api/v1/saas/members/chief",
                                    headers={"X-Tenant-ID": a})).status_code == 409
        # owner removes a member fine
        assert (await client.delete("/api/v1/saas/members/peep",
                                    headers={"X-Tenant-ID": a})).status_code == 200

        # no-membership user never gets in
        _act_as(client, session, "outsider")
        assert (await client.get("/api/v1/monitor/targets")).status_code == 403


def test_due_skips_suspended_tenants(monkeypatch):
    """The daemon is the platform worker: due() returns everything due for
    ACTIVE tenants + the platform estate, and skips SUSPENDED tenants."""
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()

    from db.repositories.monitor_repository import MonitorRepository
    from db.repositories.tenant_repository import TenantRepository

    t_repo = TenantRepository(session)
    live = t_repo.create(name="Live", slug="live")
    dead = t_repo.create(name="Dead", slug="dead")
    t_repo.set_status(dead.id, "SUSPENDED", actor="root", reason="test")
    m_repo = MonitorRepository(session)
    m_repo.create(name="live-t", target_type="REPO", config={"name": "v"},
                  tenant_id=live.id)
    m_repo.create(name="dead-t", target_type="REPO", config={"name": "v"},
                  tenant_id=dead.id)
    m_repo.create(name="platform-t", target_type="REPO", config={"name": "v"})
    session.commit()
    due = {t.name for t in m_repo.due()}
    assert due == {"live-t", "platform-t"}, due


@pytest.mark.asyncio
async def test_api_keys_minted_in_a_tenant_are_bound_to_it():
    """A key minted inside a tenant context carries tenant_id: repository and
    router scoping keep machine access inside the org it was created for."""
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        a = (await _signup(client, "Keys Co", "keyowner")).json()["tenant"]["id"]
        b = (await _signup(client, "Other Co", "otherowner")).json()["tenant"]["id"]

        _act_as(client, session, "keyowner", roles="readonly")
        r = await client.post("/api/v1/api-keys", headers={"X-Tenant-ID": a},
                              json={"name": "tenant-bot", "roles": ["viewer"]})
        assert r.status_code == 201, r.text
        raw = r.json()["raw_key"]

        from db.repositories.api_key_repository import ApiKeyRepository

        row = ApiKeyRepository(session).get_by_raw(raw)
        assert row is not None and row.tenant_id == a

        # listings are scoped: tenant A sees the key, tenant B and the
        # platform estate do not
        mine = (await client.get("/api/v1/api-keys", headers={"X-Tenant-ID": a})).json()
        assert [k["name"] for k in mine] == ["tenant-bot"]
        _act_as(client, session, "otherowner", roles="readonly")
        theirs = (await client.get("/api/v1/api-keys", headers={"X-Tenant-ID": b})).json()
        assert theirs == []
        _act_as(client, session, "root", roles="superadmin")
        platform = (await client.get("/api/v1/api-keys")).json()
        assert platform == []
        all_keys = (await client.get("/api/v1/api-keys",
                                     headers={"X-Tenant-ID": a})).json()
        assert [k["name"] for k in all_keys] == ["tenant-bot"]
