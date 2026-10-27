"""W57-58 SSO item: OIDC federated login — verification side, bring-your-own-IdP.

The IdP in these tests is a locally generated RSA keypair plus a hand-built
JWKS — real RS256 math via OpenSSL, no network, no stubbed verification.
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


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def idp(tmp_path_factory):
    """A miniature IdP: keypair + JWKS document + token factory."""
    directory = tmp_path_factory.mktemp("idp")
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

    def mint(claims: dict, *, kid: str = "idp-2026", alg: str = "RS256", tamper_sig: bool = False) -> str:
        header = {"alg": alg, "typ": "JWT", "kid": kid}
        signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(private)],
            input=signing_input.encode("ascii"), capture_output=True, check=True, timeout=60,
        )
        signature = proc.stdout
        if tamper_sig:
            signature = bytes([signature[0] ^ 0xFF]) + signature[1:]
        return f"{signing_input}.{_b64url(signature)}"

    return {"mint": mint, "jwks_file": str(jwks_file), "private": str(private)}


def _make_app(*, auto_provision: bool = True, jwks_file: str = ""):
    import os

    os.environ["ENVIRONMENT"] = os.environ.get("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    os.environ["OIDC_ISSUER"] = ISSUER
    os.environ["OIDC_CLIENT_ID"] = CLIENT
    os.environ["OIDC_AUTO_PROVISION"] = "true" if auto_provision else "false"
    if jwks_file:
        os.environ["OIDC_JWKS_FILE"] = jwks_file
    else:
        os.environ.pop("OIDC_JWKS_FILE", None)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    # NOTE: get_current_user is NOT overridden — the minted session must pass the real validator
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _claims(**overrides) -> dict:
    now = int(time.time())
    claims = {
        "iss": ISSUER, "aud": CLIENT, "sub": "federated-kim", "preferred_username": "kim",
        "email": "kim@corp.example.com", "name": "Kim Fed", "exp": now + 600, "iat": now,
    }
    claims.update(overrides)
    return claims


@pytest.mark.asyncio
async def test_oidc_login_verifies_mints_session_and_provisions(idp):
    os_env = {}
    app, session, engine = _make_app(jwks_file=idp["jwks_file"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login = await client.post("/api/v1/auth/oidc", json={"token": idp["mint"](_claims())})
        assert login.status_code == 200, login.text
        body = login.json()
        assert body["username"] == "kim"
        assert body["roles"] == ["viewer"]  # provisioned accounts are viewers
        assert body["token"]

        # the minted session passes the REAL auth dependency (not overridden here)
        me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['token']}"})
        assert me.status_code == 200
        assert me.json()["username"] == "kim"

        # audit trail records the federated login
        from db.repositories.user_repository import UserRepository

        events = [row for row in UserRepository(session).list_audit(page=1, page_size=10) if row.action == "auth.oidc_login"]
        assert events and events[0].actor == "kim" and events[0].outcome == "SUCCESS"

        # second login reuses the account (no duplicates)
        again = await client.post("/api/v1/auth/oidc", json={"token": idp["mint"](_claims(exp=int(time.time()) + 700))})
        assert again.status_code == 200
        from db.models.user import User

        assert len(session.query(User).filter(User.username == "kim").all()) == 1


@pytest.mark.asyncio
async def test_rejected_tokens(idp):
    app, session, engine = _make_app(jwks_file=idp["jwks_file"])
    transport = ASGITransport(app=app)
    cases = {
        "bad signature": idp["mint"](_claims(), tamper_sig=True),
        "wrong issuer": idp["mint"](_claims(iss="https://evil.example.com")),
        "wrong audience": idp["mint"](_claims(aud="somebody-else")),
        "expired": idp["mint"](_claims(exp=int(time.time()) - 3600)),
        "alg none": idp["mint"](_claims(), alg="none"),
        "unknown kid": idp["mint"](_claims(), kid="ghost-key"),
    }
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for label, token in cases.items():
            response = await client.post("/api/v1/auth/oidc", json={"token": token})
            assert response.status_code == 401, f"{label} should be rejected, got {response.status_code}"
        # garbage input
        response = await client.post("/api/v1/auth/oidc", json={"token": "this-is-definitely-not-a-jwt-token"})
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_no_autoprovision_and_unconfigured(idp):
    app, session, engine = _make_app(auto_provision=False, jwks_file=idp["jwks_file"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # verified token, but no local user and provisioning disabled -> honest 401
        response = await client.post("/api/v1/auth/oidc", json={"token": idp["mint"](_claims())})
        assert response.status_code == 401
        assert "no local user" in response.json()["detail"]

    # SSO off entirely when OIDC_ISSUER is unset
    import os

    os.environ.pop("OIDC_ISSUER", None)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    app2, session2, engine2 = _make_app()
    os.environ.pop("OIDC_ISSUER", None)
    get_settings.cache_clear()
    transport2 = ASGITransport(app=app2)
    async with AsyncClient(transport=transport2, base_url="http://test") as client:
        response = await client.post("/api/v1/auth/oidc", json={"token": idp["mint"](_claims())})
        assert response.status_code == 404
        assert "not configured" in response.json()["detail"]
