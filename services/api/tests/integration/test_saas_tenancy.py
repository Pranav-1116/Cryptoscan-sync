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

        # The picker must work before a tenant header is selected. Add Alice
        # to a second tenant and verify the directory is membership-derived.
        from db.repositories.tenant_repository import TenantRepository
        TenantRepository(session).add_member(b, "alice", "member", actor="bob")
        session.commit()
        _act_as(client, session, "alice")
        memberships = await client.get("/api/v1/saas/memberships")
        assert memberships.status_code == 200, memberships.text
        assert {t["id"] for t in memberships.json()["tenants"]} == {a, b}
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


@pytest.mark.asyncio
async def test_invite_flow_provisions_account_and_membership():
    """Owner invites a brand-new user; the invitee redeems the token with
    their own password. The token is single-use and shown once."""
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        a = (await _signup(client, "Invite Co", "chief")).json()["tenant"]["id"]
        _act_as(client, session, "chief", roles="readonly")

        r = await client.post("/api/v1/saas/invites", headers={"X-Tenant-ID": a},
                              json={"username": "newjoiner", "tenant_role": "member"})
        assert r.status_code == 201, r.text
        invite = r.json()
        token = invite["token"]
        assert token.startswith("csi_")

        # pending list shows the invite WITHOUT the token
        listed = (await client.get("/api/v1/saas/invites", headers={"X-Tenant-ID": a})).json()["invites"]
        assert [i["username"] for i in listed] == ["newjoiner"]
        assert "token" not in listed[0]

        # redeem: new account + membership
        client.headers.pop("Authorization", None)  # invitee is anonymous
        r2 = await client.post("/api/v1/saas/invites/accept",
                               json={"token": token, "password": "joiner-pw-Str0ng!"})
        assert r2.status_code == 200, r2.text
        assert r2.json()["tenant_role"] == "member"

        # the new account can actually sign in (real password verification)
        client.headers.pop("Authorization", None)
        login = await client.post("/api/v1/auth/login",
                                  json={"username": "newjoiner", "password": "joiner-pw-Str0ng!"})
        assert login.status_code == 200, login.text
        client.headers["Authorization"] = f"Bearer {login.json()['token']}"
        who = (await client.get("/api/v1/saas/whoami", headers={"X-Tenant-ID": a})).json()
        assert who["tenant_role"] == "member"
        who = (await client.get("/api/v1/saas/whoami", headers={"X-Tenant-ID": a})).json()
        assert who["tenant_role"] == "member"

        # single use: the same token is dead
        r3 = await client.post("/api/v1/saas/invites/accept", json={"token": token})
        assert r3.status_code == 404, r3.text


        # the new account can actually sign in (real password verification)
        client.headers.pop("Authorization", None)
        login = await client.post("/api/v1/auth/login",
                                  json={"username": "newjoiner", "password": "joiner-pw-Str0ng!"})
        assert login.status_code == 200, login.text
        client.headers["Authorization"] = f"Bearer {login.json()['token']}"
        who = (await client.get("/api/v1/saas/whoami", headers={"X-Tenant-ID": a})).json()
        assert who["tenant_role"] == "member"


@pytest.mark.asyncio
async def test_invite_for_existing_identity_requires_that_session():
    """A leaked invite token can never rebind an EXISTING account: the
    accepter must be signed in as the invited username."""
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        a = (await _signup(client, "Safe Co", "chief")).json()["tenant"]["id"]
        # the invited identity ALREADY has a platform account
        _act_as(client, session, "veteran", roles="readonly")
        _act_as(client, session, "chief", roles="readonly")
        r = await client.post("/api/v1/saas/invites", headers={"X-Tenant-ID": a},
                              json={"username": "veteran", "tenant_role": "admin"})
        token = r.json()["token"]

        # anonymous accept for an existing identity -> refused (401: no
        # session to verify the invited identity against)
        client.headers.pop("Authorization", None)
        r1 = await client.post("/api/v1/saas/invites/accept", json={"token": token})
        assert r1.status_code == 401, r1.text

        # signed in as SOMEONE ELSE -> refused (no identity rebinding)
        _act_as(client, session, "mallory", roles="readonly")
        r2 = await client.post("/api/v1/saas/invites/accept", json={"token": token})
        assert r2.status_code == 403, r2.text

        # signed in as the invited user -> accepted
        _act_as(client, session, "veteran", roles="readonly")
        r3 = await client.post("/api/v1/saas/invites/accept", json={"token": token})
        assert r3.status_code == 200 and r3.json()["tenant_role"] == "admin"


@pytest.mark.asyncio
async def test_invite_guards_ladder_expiry_revocation_quota_suspension():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        a = (await _signup(client, "Guard Co", "chief")).json()["tenant"]["id"]
        _act_as(client, session, "chief", roles="readonly")

        # ladder: owner may not be invited by anyone (no role grants owner upward)
        r0 = await client.post("/api/v1/saas/invites", headers={"X-Tenant-ID": a},
                               json={"username": "wouldbe-owner", "tenant_role": "owner"})
        assert r0.status_code == 403

        # revoke kills a pending invite
        r1 = await client.post("/api/v1/saas/invites", headers={"X-Tenant-ID": a},
                               json={"username": "transient", "tenant_role": "member"})
        tok1, inv1 = r1.json()["token"], r1.json()["invite_id"]
        assert (await client.delete(f"/api/v1/saas/invites/{inv1}",
                                    headers={"X-Tenant-ID": a})).status_code == 200
        client.headers.pop("Authorization", None)
        assert (await client.post("/api/v1/saas/invites/accept", json={
            "token": tok1, "password": "whatever-pw-Str0ng!"})).status_code == 404
        _act_as(client, session, "chief", roles="readonly")

        # expiry kills a pending invite
        from db.models.base import utcnow
        from db.repositories.tenant_repository import TenantRepository

        r2 = await client.post("/api/v1/saas/invites", headers={"X-Tenant-ID": a},
                               json={"username": "latecomer", "tenant_role": "member"})
        tok2 = r2.json()["token"]
        row = TenantRepository(session).get_invite_by_raw(tok2)
        row.expires_at = utcnow()
        session.commit()
        client.headers.pop("Authorization", None)
        assert (await client.post("/api/v1/saas/invites/accept", json={
            "token": tok2, "password": "whatever-pw-Str0ng!"})).status_code == 404
        _act_as(client, session, "chief", roles="readonly")

        # seat quota enforced at accept: FREE = 3 seats (chief fills one),
        # so two invites land and the third accept is 402
        toks = []
        for i in (1, 2, 3):
            r = await client.post("/api/v1/saas/invites", headers={"X-Tenant-ID": a},
                                  json={"username": f"seat{i}", "tenant_role": "member"})
            toks.append(r.json()["token"])
        client.headers.pop("Authorization", None)
        assert (await client.post("/api/v1/saas/invites/accept", json={
            "token": toks[0], "password": "seat-one-pw-Str0ng!"})).status_code == 200
        assert (await client.post("/api/v1/saas/invites/accept", json={
            "token": toks[1], "password": "seat-two-pw-Str0ng!"})).status_code == 200
        assert (await client.post("/api/v1/saas/invites/accept", json={
            "token": toks[2], "password": "seat-tri-pw-Str0ng!"})).status_code == 402
        _act_as(client, session, "chief", roles="readonly")

        # suspended tenant: accept is 423
        _act_as(client, session, "root", roles="superadmin")
        assert (await client.post(f"/api/v1/saas/admin/tenants/{a}/suspend",
                                  json={"reason": "guard test"})).status_code == 200
        r5 = await client.post("/api/v1/saas/invites", headers={"X-Tenant-ID": a},
                               json={"username": "blocked", "tenant_role": "member"})
        # platform admin may still create the invite, but accept is locked
        tok5 = r5.json()["token"]
        client.headers.pop("Authorization", None)
        last = await client.post("/api/v1/saas/invites/accept", json={
            "token": tok5, "password": "blocked-pw-Str0ng!"})
        assert last.status_code == 423, last.text


@pytest.mark.asyncio
async def test_monitor_journal_is_scoped_to_the_calling_tenant():
    """A tenant reads its own journal rows through ``GET /monitor/events``.

    Round 81: the filter was the watch-list target behind a row, never the row's
    own owner, so a journal row with no target — which is what
    ``emit_platform_event`` writes — was invisible to the tenant it belongs to
    as well as to the platform. Ownership is now read from the row first, and
    the boundary is exact in both directions: another tenant's rows are absent
    (not 403 — absent, so no existence oracle), and the platform estate's rows
    are not folded into a tenant's monitor feed.
    """
    from api.events.platform_events import emit_platform_event
    from db.tenancy import tenant_scope

    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        a = (await _signup(client, "Alpha", "alice")).json()["tenant"]["id"]
        b = (await _signup(client, "Beta", "bob")).json()["tenant"]["id"]

        # The same emit a request makes: the tenant scope is active, so the row
        # is attributed, and it rides the caller's session (round 81's other
        # fix) rather than opening a second connection.
        with tenant_scope(a):
            emit_platform_event("remediation.task_created", "alpha task proposed",
                                {"task_id": "ta"}, target_name="remediation", session=session)
        with tenant_scope(b):
            emit_platform_event("remediation.task_created", "beta task proposed",
                                {"task_id": "tb"}, target_name="remediation", session=session)
        emit_platform_event("graph.updated", "platform estate graph", {"nodes": 1},
                            target_name="graph", session=session)
        session.commit()

        _act_as(client, session, "alice")
        resp_a = await client.get("/api/v1/monitor/events", headers={"X-Tenant-ID": a},
                                  params={"limit": 50})
        assert resp_a.status_code == 200, resp_a.text
        events_a = resp_a.json()["events"]
        assert [e["detail"] for e in events_a] == ["alpha task proposed"]
        assert events_a[0]["scope"] == "tenant"
        assert events_a[0]["payload"]["task_id"] == "ta"

        _act_as(client, session, "bob")
        events_b = (await client.get("/api/v1/monitor/events", headers={"X-Tenant-ID": b},
                                     params={"limit": 50})).json()["events"]
        assert [e["detail"] for e in events_b] == ["beta task proposed"]
