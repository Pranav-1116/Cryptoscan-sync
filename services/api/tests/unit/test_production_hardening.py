"""Production settings, password hashing, and session identity."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config.settings import APISettings, get_settings, validate_runtime_settings
from api.security.auth import AuthService, AuthenticationError, reset_lockout_state
from api.security.passwords import hash_password, verify_password
from worker.config.settings import WorkerSettings


def test_production_metrics_require_bearer_token(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from api.routers.metrics import _require_metrics_token

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("METRICS_TOKEN", "m" * 32)
    get_settings.cache_clear()
    try:
        with pytest.raises(HTTPException) as missing:
            _require_metrics_token(SimpleNamespace(headers={}))
        assert missing.value.status_code == 401
        _require_metrics_token(SimpleNamespace(headers={"authorization": "Bearer " + "m" * 32}))
    finally:
        get_settings.cache_clear()


def test_password_hash_roundtrip():
    encoded = hash_password("s3cret-value!!")
    assert encoded.startswith("pbkdf2_sha256$")
    assert verify_password("s3cret-value!!", encoded)
    assert not verify_password("wrong-password", encoded)


def test_plaintext_dev_password_compare():
    assert verify_password("cryptoscan", "cryptoscan")
    assert not verify_password("cryptoscan", "other")


def test_plaintext_password_never_verifies_in_production(monkeypatch):
    """The dev-only literal comparison must not authenticate in production."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    get_settings.cache_clear()
    try:
        assert not verify_password("cryptoscan", "cryptoscan")
        # a real PBKDF2 hash still verifies normally
        assert verify_password("cryptoscan", hash_password("cryptoscan"))
    finally:
        get_settings.cache_clear()


def test_production_rejects_demo_defaults():
    settings = APISettings.model_construct(
        ENVIRONMENT="production",
        SECRET_KEY="dev-cryptoscan-secret-key-change-in-production-32",
        ADMIN_PASSWORD="cryptoscan",
        ADMIN_PASSWORD_HASH="",
        GITHUB_WEBHOOK_SECRET="dev-webhook-secret-change-me-32chars!!",
        METRICS_TOKEN="",
        DATABASE_URL="sqlite:///./data/cryptoscan.db",
        CORS_ORIGINS="*",
        ALLOW_SQLITE=False,
        ALLOW_INSECURE_CORS=False,
        DOCS_ENABLED=None,
        COOKIE_SECURE=None,
    )
    with pytest.raises(RuntimeError, match="production configuration rejected"):
        validate_runtime_settings(settings)


def test_production_rejects_plaintext_admin_password_even_when_strong():
    """A strong *plaintext* ADMIN_PASSWORD is still refused in production.

    verify_password() will not fall back to a literal comparison there, so a
    deployment configured this way would boot and then be unable to log in.
    Fail at boot with an actionable message instead.
    """
    settings = APISettings.model_construct(
        ENVIRONMENT="production",
        SECRET_KEY="n8f3k2p9q1w4e6r8t0y2u4i6o8a1s3d5",
        ADMIN_PASSWORD="correct-horse-battery",
        ADMIN_PASSWORD_HASH="",
        GITHUB_WEBHOOK_SECRET="webhook-secret-not-a-placeholder-value",
        METRICS_TOKEN="m" * 32,
        DATABASE_URL="postgresql://cryptoscan:secret@postgres:5432/cryptoscan",
        CORS_ORIGINS="https://cryptoscan.example",
        ALLOW_SQLITE=False,
        ALLOW_INSECURE_CORS=False,
        DOCS_ENABLED=False,
        COOKIE_SECURE=None,
    )
    with pytest.raises(RuntimeError, match="ADMIN_PASSWORD_HASH"):
        validate_runtime_settings(settings)


def test_production_accepts_strong_config():
    settings = APISettings.model_construct(
        ENVIRONMENT="production",
        SECRET_KEY="n8f3k2p9q1w4e6r8t0y2u4i6o8a1s3d5",
        ADMIN_PASSWORD="",
        ADMIN_PASSWORD_HASH=hash_password("correct-horse-battery"),
        GITHUB_WEBHOOK_SECRET="webhook-secret-not-a-placeholder-value",
        METRICS_TOKEN="m" * 32,
        DATABASE_URL="postgresql://cryptoscan:secret@postgres:5432/cryptoscan",
        CORS_ORIGINS="https://cryptoscan.example",
        ALLOW_SQLITE=False,
        ALLOW_INSECURE_CORS=False,
        DOCS_ENABLED=False,
        COOKIE_SECURE=None,
    )
    validate_runtime_settings(settings)
    assert settings.docs_enabled is False
    assert settings.cookie_secure is True


def test_development_keeps_docs_and_insecure_cookie():
    settings = APISettings.model_construct(
        ENVIRONMENT="development",
        DOCS_ENABLED=None,
        COOKIE_SECURE=None,
    )
    validate_runtime_settings(settings)
    assert settings.docs_enabled is True
    assert settings.cookie_secure is False


def test_worker_production_requires_postgres_and_redis():
    with pytest.raises(RuntimeError, match="production worker"):
        WorkerSettings.model_construct(
            ENVIRONMENT="production",
            DATABASE_URL="sqlite:///./x.db",
            REDIS_URL="",
            ALLOW_SQLITE=False,
        ).validate_runtime()
    WorkerSettings.model_construct(
        ENVIRONMENT="production",
        DATABASE_URL="postgresql://cryptoscan:secret@postgres:5432/cryptoscan",
        REDIS_URL="redis://redis:6379/0",
        ALLOW_SQLITE=False,
    ).validate_runtime()


def test_hashed_admin_password(monkeypatch):
    hashed = hash_password("operator-pass-123")
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("ADMIN_PASSWORD", "unused-plaintext")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", hashed)
    get_settings.cache_clear()
    reset_lockout_state()
    user = AuthService().authenticate("admin", "operator-pass-123")
    assert user.username == "admin"
    with pytest.raises(AuthenticationError):
        AuthService().authenticate("admin", "unused-plaintext")
    get_settings.cache_clear()


def test_login_lockout(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("LOGIN_MAX_FAILURES", "2")
    monkeypatch.setenv("LOGIN_LOCKOUT_SECONDS", "600")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    get_settings.cache_clear()
    reset_lockout_state()
    with pytest.raises(AuthenticationError):
        AuthService().authenticate("admin", "nope", client_key="1.1.1.1")
    with pytest.raises(AuthenticationError):
        AuthService().authenticate("admin", "nope", client_key="1.1.1.1")
    with pytest.raises(AuthenticationError, match="Too many"):
        AuthService().authenticate("admin", "cryptoscan", client_key="1.1.1.1")
    reset_lockout_state()
    get_settings.cache_clear()


def test_login_me_meta_and_security_headers(monkeypatch, tmp_path):
    # a fresh database: this test logs in with the bootstrap credentials, and
    # another test in the same process may have rotated the shared admin row
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'hardening.db'}")
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    get_settings.cache_clear()
    from api.main import create_app
    from db.connection import engine as _engine_mod
    from db.connection.session import configure_session, init_db

    previous_engine = _engine_mod.get_engine()
    fresh = _engine_mod.create_db_engine()
    _engine_mod.set_engine(fresh)
    init_db(fresh)
    reset_lockout_state()
    try:
        _run_login_me_meta(create_app)
    finally:
        _engine_mod.set_engine(previous_engine)
        configure_session(previous_engine)
        fresh.dispose()
        get_settings.cache_clear()


def _run_login_me_meta(create_app):
    with TestClient(create_app()) as client:
        denied = client.get("/api/v1/auth/me")
        assert denied.status_code == 401
        meta = client.get("/api/v1/meta")
        assert meta.status_code == 200
        body = meta.json()
        assert body["name"] == "CryptoScan"
        assert body["version"] == "1.0.0"
        assert "environment" in body
        assert "docs_enabled" in body
        assert meta.headers.get("x-content-type-options") == "nosniff"
        assert meta.headers.get("x-frame-options") == "DENY"
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"})
        assert login.status_code == 200
        token = login.json()["token"]
        me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200
        assert me.json()["username"] == "admin"
        # /me canonicalizes legacy roles (admin → superadmin) per the 8-role catalog
        assert "superadmin" in me.json()["roles"]
