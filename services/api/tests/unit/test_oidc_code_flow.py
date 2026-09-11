"""OIDC authorization-code flow — the enterprise redirect flavor of SSO.

Same miniature-IdP approach as test_oidc.py: a locally generated RSA keypair
plus a hand-built JWKS — real RS256 math via OpenSSL, no network. Discovery
and the code exchange are injected (they'd otherwise hit the wire); the token
verification is NOT — the real verify_id_token runs on every test.
"""

from __future__ import annotations

import base64
import json
import subprocess
import time

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_db_session
from api.main import create_app
from db.connection.session import Base

ISSUER = "https://sso.corp.example.com/realms/main"
CLIENT = "cryptoscan"
AUTH_ENDPOINT = f"{ISSUER}/protocol/openid-connect/auth"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def idp(tmp_path_factory):
    """A miniature IdP: keypair + JWKS document + token factory."""
    directory = tmp_path_factory.mktemp("idp-code")
    private = directory / "idp.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(private), "2048"],
                   check=True, capture_output=True, timeout=60)
    modulus_hex = subprocess.run(
        ["openssl", "rsa", "-in", str(private), "-noout", "-modulus"],
        check=True, capture_output=True, timeout=60,
    ).stdout.decode().strip().split("=")[1]
    n = _b64url(int(modulus_hex, 16).to_bytes((int(modulus_hex, 16).bit_length() + 7) // 8, "big"))
    jwks = {"keys": [{"kty": "RSA", "kid": "idp-2026", "use": "sig", "alg": "RS256", "n": n, "e": "AQAB"}]}
    jwks_file = directory / "jwks.json"
    jwks_file.write_text(json.dumps(jwks))

    def mint(claims: dict, *, kid: str = "idp-2026", alg: str = "RS256") -> str:
        header = {"alg": alg, "typ": "JWT", "kid": kid}
        signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(private)],
            input=signing_input.encode("ascii"), capture_output=True, check=True, timeout=60,
        )
        return f"{signing_input}.{_b64url(proc.stdout)}"

    return {"mint": mint, "jwks_file": str(jwks_file)}


@pytest.fixture()
def app_env(monkeypatch, idp):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("OIDC_CLIENT_ID", CLIENT)
    monkeypatch.setenv("OIDC_AUTO_PROVISION", "true")
    monkeypatch.setenv("OIDC_JWKS_FILE", idp["jwks_file"])
    from api.config.settings import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _make_app(app_env):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    configure = sessionmaker(bind=engine, expire_on_commit=False)
    session = configure()
    application = create_app()

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    application.state.test_session = session
    return application, session


def _fake_discovery(monkeypatch):
    from api.security import oidc as oidc_mod

    monkeypatch.setattr(
        oidc_mod, "discover_oidc_endpoints",
        lambda issuer, **kwargs: {"authorization_endpoint": AUTH_ENDPOINT,
                                  "token_endpoint": TOKEN_ENDPOINT},
    )


def _state_nonce(state: str) -> str:
    payload = state.split(".", 1)[0]
    pad = "=" * (-len(payload) % 4)
    return str(json.loads(base64.urlsafe_b64decode(payload + pad))["nonce"])


def _claims(nonce: str = "", **overrides) -> dict:
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": CLIENT, "sub": "federated-kim",
              "preferred_username": "kim", "email": "kim@corp.example.com",
              "name": "Kim Fed", "exp": now + 600, "iat": now}
    if nonce:
        claims["nonce"] = nonce
    claims.update(overrides)
    return claims


# ----------------------------------------------------------------- state unit


def test_state_roundtrip_and_rejections():
    from api.security.oidc import make_state, read_state

    secret = "test-secret-key-for-sessions-min-32-chars"
    state = make_state(secret, "nonce-abc", now=1_000)
    assert read_state(secret, state, now=1_100) == "nonce-abc"
    # wrong key
    assert read_state("another-secret-key-that-is-long-enough!", state, now=1_100) is None
    # tampered payload
    payload, sig = state.split(".", 1)
    assert read_state(secret, f"{payload}x.{sig}", now=1_100) is None
    # stale beyond max_age
    assert read_state(secret, state, now=1_000 + 601) is None
    # from the future (beyond skew)
    assert read_state(secret, state, now=1_000 - 120) is None
    # garbage
    assert read_state(secret, "not-a-state") is None


# ------------------------------------------------------------ discovery/exchg


def test_discover_endpoints_validates_against_issuer():
    from api.security.oidc import OidcError, discover_oidc_endpoints

    good = {"authorization_endpoint": f"{ISSUER}/auth", "token_endpoint": f"{ISSUER}/token"}
    out = discover_oidc_endpoints(ISSUER, fetch=lambda url, timeout: json.dumps(good).encode())
    assert out == good

    # hostile discovery: token endpoint on a different host must be rejected
    hostile = {"token_endpoint": "https://evil.example.com/token"}
    with pytest.raises(OidcError):
        discover_oidc_endpoints(ISSUER, fetch=lambda url, timeout: json.dumps(hostile).encode())

    # honest but useless document
    with pytest.raises(OidcError):
        discover_oidc_endpoints(ISSUER, fetch=lambda url, timeout: b"{}")

    # broken fetch surfaces as OidcError, not a raw exception
    def _boom(url, timeout):
        raise OSError("unreachable")

    with pytest.raises(OidcError):
        discover_oidc_endpoints(ISSUER, fetch=_boom)


def test_exchange_code_posts_form_and_omits_empty_secret():
    from api.security.oidc import OidcError, exchange_code

    captured = {}

    def poster(url, data, timeout):
        captured["url"] = url
        captured["form"] = dict(pair.split("=", 1) for pair in data.decode().split("&"))
        return json.dumps({"access_token": "at", "id_token": "tok"}).encode()

    out = exchange_code("https://idp.example.com/token", code="abc", client_id="cryptoscan",
                        redirect_uri="https://app/callback", poster=poster)
    assert out["id_token"] == "tok"
    assert captured["url"] == "https://idp.example.com/token"
    assert captured["form"]["grant_type"] == "authorization_code"
    assert "client_secret" not in captured["form"]  # public client — omitted, not faked

    captured.clear()
    exchange_code("https://idp.example.com/token", code="abc", client_id="c",
                  redirect_uri="https://app/callback", client_secret="shh", poster=poster)
    assert captured["form"]["client_secret"] == "shh"

    def error_poster(url, data, timeout):
        return json.dumps({"error": "invalid_grant"}).encode()

    with pytest.raises(OidcError):
        exchange_code("https://idp.example.com/token", code="abc", client_id="c",
                      redirect_uri="https://app/callback", poster=error_poster)


# ----------------------------------------------------------------- endpoints


@pytest.mark.asyncio
async def test_authorize_redirects_with_state_and_nonce(app_env, monkeypatch):
    _fake_discovery(monkeypatch)
    application, _ = _make_app(app_env)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        response = await client.get("/api/v1/auth/oidc/authorize", follow_redirects=False)
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert location.startswith(AUTH_ENDPOINT)
    assert "response_type=code" in location and f"client_id={CLIENT}" in location
    assert "nonce=" in location and "state=" in location
    assert read_state_nonce(location)  # state is well-formed


def read_state_nonce(location: str) -> str:
    from urllib.parse import parse_qs, urlparse

    params = parse_qs(urlparse(location).query)
    payload = params["state"][0].split(".", 1)[0]
    pad = "=" * (-len(payload) % 4)
    return str(json.loads(base64.urlsafe_b64decode(payload + pad))["nonce"])


@pytest.mark.asyncio
async def test_callback_full_flow_provisions_mints_and_audits(app_env, monkeypatch, idp):
    from api.security import oidc as oidc_mod

    _fake_discovery(monkeypatch)

    def fake_exchange(token_endpoint, *, code, client_id, redirect_uri, client_secret="", **kw):
        assert token_endpoint == TOKEN_ENDPOINT
        assert client_id == CLIENT
        return {"access_token": "at", "id_token": idp["mint"](_claims(nonce=code))}

    monkeypatch.setattr(oidc_mod, "exchange_code", fake_exchange)

    application, session = _make_app(app_env)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        authorize = await client.get("/api/v1/auth/oidc/authorize", follow_redirects=False)
        state = authorize.headers["location"].split("state=")[1].split("&")[0]
        nonce = _state_nonce(state)

        response = await client.get(
            "/api/v1/auth/oidc/callback",
            params={"code": nonce, "state": state}, follow_redirects=False)
        assert response.status_code == 303, response.text
        assert response.headers["location"] == "/"
        assert response.cookies.get("cryptoscan_session")

        # the minted session passes the REAL auth dependency
        me = await client.get("/api/v1/auth/me")
        assert me.status_code == 200
        assert me.json()["username"] == "kim"

    from db.models.user import User
    from db.repositories.user_repository import UserRepository

    assert len(session.query(User).filter(User.username == "kim").all()) == 1
    events = [row for row in UserRepository(session).list_audit(page=1, page_size=20)
              if row.action == "auth.oidc_callback"]
    assert events and events[0].actor == "kim" and events[0].outcome == "SUCCESS"


@pytest.mark.asyncio
async def test_callback_rejects_tampered_state(app_env, monkeypatch):
    _fake_discovery(monkeypatch)
    application, session = _make_app(app_env)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        response = await client.get(
            "/api/v1/auth/oidc/callback",
            params={"code": "c", "state": "forged.state"}, follow_redirects=False)
    assert response.status_code == 401
    assert "state invalid" in response.json()["detail"]
    from db.repositories.user_repository import UserRepository

    failures = [row for row in UserRepository(session).list_audit(page=1, page_size=10)
                if row.action == "auth.oidc_callback" and row.outcome == "FAILURE"]
    assert failures


@pytest.mark.asyncio
async def test_callback_rejects_missing_id_token(app_env, monkeypatch):
    from api.security import oidc as oidc_mod

    _fake_discovery(monkeypatch)
    monkeypatch.setattr(oidc_mod, "exchange_code", lambda *a, **kw: {"access_token": "at"})
    application, _ = _make_app(app_env)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        authorize = await client.get("/api/v1/auth/oidc/authorize", follow_redirects=False)
        state = authorize.headers["location"].split("state=")[1].split("&")[0]
        response = await client.get(
            "/api/v1/auth/oidc/callback",
            params={"code": "c", "state": state}, follow_redirects=False)
    assert response.status_code == 401
    assert "no id_token" in response.json()["detail"]


@pytest.mark.asyncio
async def test_callback_rejects_nonce_mismatch(app_env, monkeypatch, idp):
    from api.security import oidc as oidc_mod

    _fake_discovery(monkeypatch)
    # token carries NO nonce — must fail the nonce binding, not slide through
    monkeypatch.setattr(oidc_mod, "exchange_code",
                        lambda *a, **kw: {"id_token": idp["mint"](_claims())})
    application, _ = _make_app(app_env)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        authorize = await client.get("/api/v1/auth/oidc/authorize", follow_redirects=False)
        state = authorize.headers["location"].split("state=")[1].split("&")[0]
        response = await client.get(
            "/api/v1/auth/oidc/callback",
            params={"code": "c", "state": state}, follow_redirects=False)
    assert response.status_code == 401
    assert "nonce mismatch" in response.json()["detail"]


@pytest.mark.asyncio
async def test_callback_surfaces_idp_error(app_env, monkeypatch):
    _fake_discovery(monkeypatch)
    application, _ = _make_app(app_env)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        authorize = await client.get("/api/v1/auth/oidc/authorize", follow_redirects=False)
        state = authorize.headers["location"].split("state=")[1].split("&")[0]
        response = await client.get(
            "/api/v1/auth/oidc/callback",
            params={"error": "access_denied", "state": state}, follow_redirects=False)
    assert response.status_code == 401
    assert "access_denied" in response.json()["detail"]


@pytest.mark.asyncio
async def test_sso_status_reports_capabilities(app_env):
    application, _ = _make_app(app_env)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        configured = (await client.get("/api/v1/auth/sso/status")).json()
        assert configured["oidc"]["enabled"] is True
        assert configured["oidc"]["authorize_url"] == "/api/v1/auth/oidc/authorize"

    import os

    os.environ.pop("OIDC_ISSUER", None)
    os.environ.pop("OIDC_CLIENT_ID", None)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    try:
        application, _ = _make_app(app_env)
        async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
            off = (await client.get("/api/v1/auth/sso/status")).json()
            assert off["oidc"]["enabled"] is False
            assert off["oidc"]["authorize_url"] is None
    finally:
        get_settings.cache_clear()


# ----------------------------------------------------------------- PKCE (S256)


def test_make_pkce_rfc7636_shapes():
    import base64 as b64
    import hashlib

    from api.security.oidc import make_pkce

    verifier, challenge = make_pkce()
    assert 43 <= len(verifier) <= 128
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    assert set(verifier) <= allowed and set(challenge) <= allowed
    expected = b64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    assert challenge == expected  # S256: challenge is exactly the hashed verifier
    assert make_pkce()[0] != verifier  # fresh verifier per login


@pytest.mark.asyncio
async def test_public_client_authorize_sends_challenge_and_stores_verifier(app_env, monkeypatch):
    _fake_discovery(monkeypatch)
    application, _ = _make_app(app_env)  # no OIDC_CLIENT_SECRET → public client
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        response = await client.get("/api/v1/auth/oidc/authorize", follow_redirects=False)
    location = response.headers["location"]
    assert "code_challenge=" in location
    assert "code_challenge_method=S256" in location
    # the verifier itself must NOT appear anywhere in the front-channel URL
    assert "verifier" not in location


@pytest.mark.asyncio
async def test_public_client_callback_without_verifier_fails_closed(app_env, monkeypatch):
    from api.security import oidc as oidc_mod

    _fake_discovery(monkeypatch)
    monkeypatch.setattr(oidc_mod, "exchange_code",
                        lambda *a, **kw: {"id_token": "would-be-accepted"})
    application, _ = _make_app(app_env)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        authorize = await client.get("/api/v1/auth/oidc/authorize", follow_redirects=False)
        state = authorize.headers["location"].split("state=")[1].split("&")[0]
        # a FRESH client: no PKCE cookie (login started elsewhere / cookie lost)
        fresh = AsyncClient(transport=ASGITransport(app=application), base_url="http://test")
        response = await fresh.get("/api/v1/auth/oidc/callback",
                                   params={"code": "c", "state": state}, follow_redirects=False)
        await fresh.aclose()
    assert response.status_code == 401
    assert "PKCE verifier missing" in response.json()["detail"]


@pytest.mark.asyncio
async def test_full_flow_carries_verifier_to_exchange(app_env, monkeypatch, idp):
    from api.security import oidc as oidc_mod

    _fake_discovery(monkeypatch)
    captured = {}

    def fake_exchange(token_endpoint, *, code, client_id, redirect_uri,
                      client_secret="", code_verifier="", **kw):
        captured["code_verifier"] = code_verifier
        return {"access_token": "at", "id_token": idp["mint"](_claims(nonce=code))}

    monkeypatch.setattr(oidc_mod, "exchange_code", fake_exchange)
    application, session = _make_app(app_env)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        authorize = await client.get("/api/v1/auth/oidc/authorize", follow_redirects=False)
        verifier_cookie = client.cookies.get("cryptoscan_pkce")
        assert verifier_cookie
        state = authorize.headers["location"].split("state=")[1].split("&")[0]
        nonce = _state_nonce(state)
        response = await client.get(
            "/api/v1/auth/oidc/callback",
            params={"code": nonce, "state": state}, follow_redirects=False)
        assert response.status_code == 303
    assert captured["code_verifier"] == verifier_cookie
    # cookie consumed — a replay of the callback cannot reuse the verifier
    assert not client.cookies.get("cryptoscan_pkce")


@pytest.mark.asyncio
async def test_confidential_client_skips_pkce(app_env, monkeypatch, idp):
    import os

    os.environ["OIDC_CLIENT_SECRET"] = "confidential-secret-value"
    from api.config.settings import get_settings

    get_settings.cache_clear()
    try:
        from api.security import oidc as oidc_mod

        _fake_discovery(monkeypatch)
        captured = {}

        def fake_exchange(token_endpoint, *, code, client_id, redirect_uri,
                          client_secret="", code_verifier="", **kw):
            captured["client_secret"] = client_secret
            captured["code_verifier"] = code_verifier
            return {"access_token": "at", "id_token": idp["mint"](_claims(nonce=code))}

        monkeypatch.setattr(oidc_mod, "exchange_code", fake_exchange)
        application, _ = _make_app(app_env)
        async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
            authorize = await client.get("/api/v1/auth/oidc/authorize", follow_redirects=False)
            location = authorize.headers["location"]
            assert "code_challenge=" not in location  # confidential → no PKCE
            assert not client.cookies.get("cryptoscan_pkce")
            state = location.split("state=")[1].split("&")[0]
            nonce = _state_nonce(state)
            response = await client.get(
                "/api/v1/auth/oidc/callback",
                params={"code": nonce, "state": state}, follow_redirects=False)
            assert response.status_code == 303
        assert captured["code_verifier"] == ""  # no PKCE for confidential clients
        assert captured["client_secret"] == "confidential-secret-value"
    finally:
        os.environ.pop("OIDC_CLIENT_SECRET", None)
        get_settings.cache_clear()
