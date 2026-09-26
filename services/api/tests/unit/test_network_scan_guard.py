"""POST /network-scans: SSRF choke point + tenant quota metering.

Found by the round-28 SaaS review: this route ran the live TLS scanner on
raw operator hosts with no target validation — the same OWASP A10 class as
the round-26 monitor finding. Hosts now pass target_validation, and tenant
contexts spend plan quota (one scan_run unit per host) exactly like the
daemon's passes.
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
    from api.security.session_manager import SessionManager
    from db.repositories.user_repository import UserRepository

    if UserRepository(session).get_by_username(username) is None:
        UserRepository(session).create_user(username, "x", roles=[roles])
        session.commit()
    token = SessionManager().create_session(username, roles=[roles])
    client.headers["Authorization"] = f"Bearer {token}"


@pytest.fixture()
def fake_scanner(monkeypatch):
    probed: list[list[str]] = []

    class _Fake:
        def __init__(self, *a, **k):
            pass

        def scan_hosts(self, hosts, *a, **k):
            probed.append([str(h) for h in hosts])
            return {"results": [], "certificates": [], "usages": []}

    monkeypatch.setattr("api.routers.network_scans.NetworkTlsScanner", _Fake)
    return probed


@pytest.mark.asyncio
async def test_metadata_and_loopback_hosts_are_refused(fake_scanner):
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # legacy platform principal (no user row): platform estate context
        from api.security.session_manager import SessionManager

        client.headers["Authorization"] = f"Bearer {SessionManager().create_session('soc', roles=['security_analyst'])}"
        for hosts in (["169.254.169.254:80"], ["127.0.0.1:443"],
                      ["http://169.254.169.254/latest/meta-data/"],
                      ["[fd00:ec2::254]:80"], ["api.bank.example:443", "localhost:8010"]):
            r = await client.post("/api/v1/network-scans", json={"hosts": hosts})
            assert r.status_code == 422, (hosts, r.text)
        assert fake_scanner == []  # nothing ever probed


@pytest.mark.asyncio
async def test_public_hosts_scan_and_tenant_quota_meters(fake_scanner):
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # tenant context: signup, invite path not needed — owner scans directly
        r = await client.post("/api/v1/saas/signup", json={
            "org_name": "Scan Co", "username": "scanner1",
            "password": STRONG_PW})
        assert r.status_code == 201, r.text
        _act_as(client, session, "scanner1", roles="readonly")

        hosts = ["api.github.com:443", "example.org:443"]
        r = await client.post("/api/v1/network-scans", json={"hosts": hosts})
        assert r.status_code == 200, r.text
        assert fake_scanner == [hosts]

        from db.repositories.tenant_repository import TenantRepository

        t_repo = TenantRepository(session)
        tenant = t_repo.list_tenants()[0]
        assert t_repo.month_usage(tenant.id, "scan_run") == 2  # one unit per host

        # exhausting the FREE monthly scan quota turns the next run into 402
        from api.security.tenancy import PLANS

        t_repo.record_usage(tenant.id, "scan_run",
                            PLANS["FREE"]["max_scans_per_month"] - 2, detail="fill")
        session.commit()
        r2 = await client.post("/api/v1/network-scans", json={"hosts": ["api.github.com:443"]})
        assert r2.status_code == 402, r2.text
        assert len(fake_scanner) == 1  # refused before any probe


@pytest.mark.asyncio
async def test_platform_estate_scans_are_unmetered(fake_scanner):
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        _act_as(client, session, "root", roles="superadmin")
        r = await client.post("/api/v1/network-scans", json={"hosts": ["api.github.com:443"]})
        assert r.status_code == 200, r.text
        assert fake_scanner == [["api.github.com:443"]]
        # no tenants exist — nothing was metered anywhere
        from db.repositories.tenant_repository import TenantRepository

        assert TenantRepository(session).list_tenants() == []
