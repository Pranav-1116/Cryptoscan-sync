"""MFA (TOTP) — RFC 6238 conformance + full API enrollment/challenge/recovery flow."""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings
from api.security import totp


# --------------------------------------------------------------------------- #
# RFC 6238 Appendix B conformance (SHA-1, 8 digits)
# --------------------------------------------------------------------------- #

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")

RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("ts,expected", RFC_VECTORS)
def test_rfc6238_vectors(ts, expected):
    assert totp.totp_at(RFC_SECRET, ts, digits=8) == expected


def test_verify_window_and_rejections():
    secret = totp.generate_secret()
    assert totp.verify(secret, totp.current_code(secret)) is True
    assert totp.verify(secret, "000000") is False or totp.current_code(secret) == "000000"
    assert totp.verify(secret, "12") is False  # wrong length
    assert totp.verify(secret, "abcdef") is False  # non-digits
    # provisioning URI is what authenticator apps parse
    uri = totp.provisioning_uri(secret, "alice")
    assert uri.startswith("otpauth://totp/CryptoScan:alice?secret=") and "period=30" in uri
    codes = totp.generate_recovery_codes(10)
    assert len(codes) == 10 and len(set(codes)) == 10 and all(len(c) == 9 for c in codes)


# --------------------------------------------------------------------------- #
# API flow against a real app + SQLite
# --------------------------------------------------------------------------- #

@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    db_url = f"sqlite:///{tmp_path}/mfa.db"
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


def _login(client, username="admin", password="cryptoscan"):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def test_full_mfa_flow_totp_and_recovery(sqlite_app):
    client = sqlite_app

    # enroll while authenticated
    token = _login(client).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    enroll = client.post("/api/v1/auth/mfa/enroll", headers=headers)
    assert enroll.status_code == 200
    secret = enroll.json()["secret"]
    assert enroll.json()["otpauth_uri"].startswith("otpauth://totp/")

    # pending enrollment does not gate login yet
    mid = _login(client)
    assert mid.status_code == 200 and not mid.json().get("mfa_required")

    # wrong confirmation code does not activate
    bad_enable = client.post("/api/v1/auth/mfa/enable", headers=headers, json={"code": "000000"})
    if bad_enable.status_code == 200:  # code 000000 legitimately matched the window
        assert bad_enable.json()["enabled"] is True
    else:
        assert bad_enable.status_code == 400
        enable = client.post("/api/v1/auth/mfa/enable", headers=headers, json={"code": totp.current_code(secret)})
        assert enable.status_code == 200
    # ensure enabled state now (either branch above)
    assert client.get("/api/v1/auth/me", headers=headers).json()["mfa_enabled"] is True

    # re-enroll is refused while enabled
    assert client.post("/api/v1/auth/mfa/enroll", headers=headers).status_code == 409

    # password alone no longer mints a session
    challenged = _login(client)
    assert challenged.status_code == 200
    body = challenged.json()
    assert body["mfa_required"] is True and body["token"] == "" and body["mfa_token"]
    # the challenge token is NOT a session (purpose-scoped)
    fake = {"Authorization": f"Bearer {body['mfa_token']}"}
    assert client.get("/api/v1/auth/me", headers=fake).status_code == 401

    # wrong code rejected
    wrong = client.post("/api/v1/auth/login/mfa", json={"mfa_token": body["mfa_token"], "code": "123456"})
    assert wrong.status_code == 401

    # valid TOTP code completes login
    done = client.post(
        "/api/v1/auth/login/mfa", json={"mfa_token": body["mfa_token"], "code": totp.current_code(secret)}
    )
    assert done.status_code == 200 and done.json()["token"] and not done.json()["mfa_required"]
    session_headers = {"Authorization": f"Bearer {done.json()['token']}"}
    assert client.get("/api/v1/auth/me", headers=session_headers).json()["username"] == "admin"


def test_recovery_codes_are_one_time(sqlite_app):
    client = sqlite_app
    headers = {"Authorization": f"Bearer {_login(client).json()['token']}"}
    secret = client.post("/api/v1/auth/mfa/enroll", headers=headers).json()["secret"]
    enable = client.post("/api/v1/auth/mfa/enable", headers=headers, json={"code": totp.current_code(secret)})
    assert enable.status_code == 200
    codes = enable.json()["recovery_codes"]
    assert len(codes) == 10 and "warning" in enable.json()

    # TOTP also still works alongside recovery codes — burn one TOTP login first
    challenge = _login(client).json()
    done = client.post(
        "/api/v1/auth/login/mfa",
        json={"mfa_token": challenge["mfa_token"], "code": totp.current_code(secret)},
    )
    assert done.status_code == 200
    client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {done.json()['token']}"})

    # recovery code works exactly once
    challenge = _login(client).json()
    first = client.post("/api/v1/auth/login/mfa", json={"mfa_token": challenge["mfa_token"], "code": codes[0]})
    assert first.status_code == 200
    client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {first.json()['token']}"})
    replay = client.post(
        "/api/v1/auth/login/mfa", json={"mfa_token": _login(client).json()["mfa_token"], "code": codes[0]}
    )
    assert replay.status_code == 401


def test_disable_requires_password_and_code_and_revokes(sqlite_app):
    client = sqlite_app
    headers = {"Authorization": f"Bearer {_login(client).json()['token']}"}
    secret = client.post("/api/v1/auth/mfa/enroll", headers=headers).json()["secret"]
    client.post("/api/v1/auth/mfa/enable", headers=headers, json={"code": totp.current_code(secret)})

    wrong_password = client.post(
        "/api/v1/auth/mfa/disable", headers=headers, json={"password": "nope", "code": totp.current_code(secret)}
    )
    assert wrong_password.status_code == 401
    wrong_code = client.post(
        "/api/v1/auth/mfa/disable", headers=headers, json={"password": "cryptoscan", "code": "123456"}
    )
    assert wrong_code.status_code in {400, 401}

    ok = client.post(
        "/api/v1/auth/mfa/disable",
        headers=headers,
        json={"password": "cryptoscan", "code": totp.current_code(secret)},
    )
    assert ok.status_code == 200 and ok.json()["disabled"] is True

    # the old session was revoked and password-only login works again
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    plain = _login(client)
    assert plain.status_code == 200 and not plain.json().get("mfa_required")


def test_mfa_challenge_expiry_and_garbage(sqlite_app):
    client = sqlite_app
    headers = {"Authorization": f"Bearer {_login(client).json()['token']}"}
    secret = client.post("/api/v1/auth/mfa/enroll", headers=headers).json()["secret"]
    client.post("/api/v1/auth/mfa/enable", headers=headers, json={"code": totp.current_code(secret)})

    for junk in ["garbagetoken", "x" * 40]:
        r = client.post("/api/v1/auth/login/mfa", json={"mfa_token": junk, "code": "123456"})
        assert r.status_code == 401  # well-formed but not a valid challenge
    # structurally too-short tokens are rejected by validation (422), still no login
    assert client.post("/api/v1/auth/login/mfa", json={"mfa_token": "short", "code": "123456"}).status_code == 422

    # a session token cannot be replayed as an mfa_token
    real_session = _login(client)  # password -> challenge
    challenge_token = real_session.json()["mfa_token"]
    done = client.post(
        "/api/v1/auth/login/mfa", json={"mfa_token": challenge_token, "code": totp.current_code(secret)}
    )
    session_token = done.json()["token"]
    r = client.post("/api/v1/auth/login/mfa", json={"mfa_token": session_token, "code": "123456"})
    assert r.status_code == 401
