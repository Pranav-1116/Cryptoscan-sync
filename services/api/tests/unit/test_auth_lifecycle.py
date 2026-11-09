"""API-level auth lifecycle: login → use → logout → revoked, plus user management."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    """Real app whose lifespan init_db() runs against a throwaway SQLite file."""
    db_url = f"sqlite:///{tmp_path}/auth.db"
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()

    # Drop the process-wide cached engine so each test gets its own SQLite file.
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None

    from api.main import create_app

    app = create_app()

    with TestClient(app) as client:
        # Lifespan ran init_db() against the SQLite file; seed a viewer user.
        from db.connection.session import SessionLocal
        from db.repositories.user_repository import UserRepository
        from api.security.passwords import hash_password

        with SessionLocal() as s:
            UserRepository(s).create_user("viewer1", hash_password("viewer-pass-123"), roles=["viewer"])
            s.commit()
        yield client, None


def test_full_login_logout_revocation_flow(sqlite_app):
    client, _ = sqlite_app

    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"})
    assert login.status_code == 200
    token = login.json()["token"]
    assert login.json()["roles"] == ["superadmin"]

    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200 and me.json()["username"] == "admin"

    logout = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout.status_code == 200

    # Token is revoked server-side: /me rejects it.
    me_after = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_after.status_code == 401


def test_admin_can_create_and_disable_user(sqlite_app):
    client, _ = sqlite_app
    admin_token = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}
    ).json()["token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    created = client.post(
        "/api/v1/auth/users",
        json={"username": "auditor1", "password": "auditor-pass-123", "roles": ["auditor"]},
        headers=headers,
    )
    assert created.status_code == 201
    assert created.json()["roles"] == ["auditor"]

    # Duplicate rejected
    dup = client.post(
        "/api/v1/auth/users",
        json={"username": "auditor1", "password": "auditor-pass-123"},
        headers=headers,
    )
    assert dup.status_code == 409

    # New auditor can log in
    audit_login = client.post(
        "/api/v1/auth/login", json={"username": "auditor1", "password": "auditor-pass-123"}
    )
    assert audit_login.status_code == 200

    # Disable → sessions revoked → token dead
    disabled = client.patch(
        "/api/v1/auth/users/auditor1", json={"is_active": False}, headers=headers
    )
    assert disabled.status_code == 200 and disabled.json()["is_active"] is False
    dead = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {audit_login.json()['token']}"},
    )
    assert dead.status_code == 401


def test_viewer_cannot_manage_users_or_trigger_scans(sqlite_app):
    client, _ = sqlite_app
    viewer_token = client.post(
        "/api/v1/auth/login", json={"username": "viewer1", "password": "viewer-pass-123"}
    ).json()["token"]
    headers = {"Authorization": f"Bearer {viewer_token}"}

    denied = client.post(
        "/api/v1/auth/users",
        json={"username": "sneaky", "password": "sneaky-pass-12345", "roles": ["admin"]},
        headers=headers,
    )
    assert denied.status_code == 403

    trigger = client.post(
        "/api/v1/scans/trigger",
        json={"repo_url": "local://test-fixture/vulnerable-app"},
        headers=headers,
    )
    assert trigger.status_code == 403


def test_admin_can_view_audit_trail(sqlite_app):
    client, _ = sqlite_app
    client.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"})
    admin_token = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}
    ).json()["token"]
    audit = client.get("/api/v1/auth/audit", headers={"Authorization": f"Bearer {admin_token}"})
    assert audit.status_code == 200
    actions = {e["action"] for e in audit.json()["events"]}
    assert "auth.login" in actions


def test_login_purges_long_dead_session_rows_but_keeps_live_ones(sqlite_app):
    """The storage sweep: rows dead past the grace window go at login; live rows stay.

    ``user_sessions`` grew without bound before this — every login added a row
    and nothing ever deleted one. The sweep runs at login (the cadence that
    creates rows) and must never touch a session that could still authenticate
    or one still inside the incident-review window.
    """
    client, _ = sqlite_app
    from datetime import datetime, timedelta, timezone

    from db.connection.session import SessionLocal
    from db.repositories.user_repository import UserRepository

    now = datetime.now(timezone.utc)
    with SessionLocal() as s:
        repo = UserRepository(s)
        repo.create_session("dead-token-60d", "admin", now - timedelta(days=60))
        repo.create_session("grace-token-1d", "admin", now - timedelta(days=1))
        repo.create_session("live-token", "admin", now + timedelta(days=1))
        repo.revoke_session("live-token")  # revoked-but-unexpired: revocation checks still read it
        s.commit()

    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"})
    assert login.status_code == 200, login.text  # the sweep must never block a login

    with SessionLocal() as s:
        repo = UserRepository(s)
        assert repo.get_session("dead-token-60d") is None, "a 60-day-dead row survived the login sweep"
        assert repo.get_session("grace-token-1d") is not None, "the 30-day review window was pruned early"
        kept = repo.get_session("live-token")
        assert kept is not None and kept.revoked_at is not None, "revoked-but-unexpired rows must survive"
        # An explicit tighter cutoff removes the reviewed-and-aged row, and is idempotent.
        assert repo.purge_expired_sessions(expired_before=now) == 1
        assert repo.get_session("grace-token-1d") is None
        assert repo.get_session("live-token") is not None, "an unexpired row must survive any expiry-based purge"
        assert repo.purge_expired_sessions(expired_before=now) == 0
        s.commit()
