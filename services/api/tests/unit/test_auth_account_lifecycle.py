"""Self-service account lifecycle: register + profile + password + sessions,
and the real-time ``auth.*`` events each transition publishes.

Runs against a real FastAPI app backed by SQLite (dev mode) so the full
middleware + dependency + repository stack is exercised.
"""

from __future__ import annotations

import pytest
from api.config.settings import get_settings
from fastapi.testclient import TestClient


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    db_url = f"sqlite:///{tmp_path}/auth_lifecycle.db"
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

    from api.events.bus import reset_event_bus
    reset_event_bus()

    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register(client, username, password="password123", role="readonly", **extra):
    body = {"username": username, "password": password, "role": role, **extra}
    return client.post("/api/v1/auth/register", json=body)


def _login(client, username, password):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def _recent_event_types(client, token):
    r = client.get("/api/v1/events/recent?limit=100", headers=_auth(token))
    events = r.json().get("events", [])
    return [e["type"] for e in events]


# ------------------------------------------------------------------- register

def test_register_open_role_and_login(sqlite_app):
    c = sqlite_app
    r = _register(c, "alice", role="developer", display_name="Alice A")
    assert r.status_code == 201, r.text
    assert r.json()["roles"] == ["developer"]

    # the new account can authenticate and sees a canonical role
    r = _login(c, "alice", "password123")
    assert r.status_code == 200
    assert r.json()["roles"] == ["developer"]
    assert r.json()["token"]


def test_register_superadmin_forbidden(sqlite_app):
    r = _register(sqlite_app, "evil", role="superadmin")
    assert r.status_code == 403


def test_register_legacy_admin_alias_also_forbidden(sqlite_app):
    # admin is the superadmin alias — it must not slip past the deny list
    r = _register(sqlite_app, "evil2", role="admin")
    assert r.status_code == 403


def test_register_unknown_role_422(sqlite_app):
    r = _register(sqlite_app, "bob", role="wizard")
    assert r.status_code == 422


def test_register_duplicate_409(sqlite_app):
    assert _register(sqlite_app, "carol", role="readonly").status_code == 201
    assert _register(sqlite_app, "carol", role="auditor").status_code == 409


def test_register_is_whitelisted_without_token(sqlite_app):
    # No Authorization header sent — proves the middleware lets it through.
    r = sqlite_app.post(
        "/api/v1/auth/register",
        json={"username": "dave", "password": "password123", "role": "scanner"},
    )
    assert r.status_code == 201


def test_admin_can_soft_delete_and_restore_user(sqlite_app):
    c = sqlite_app
    # admin + a victim account
    admin = _login(c, "admin", "cryptoscan").json()["token"]
    _register(c, "victim", password="password123", role="readonly")
    victim = _login(c, "victim", "password123").json()["token"]
    # victim has a live session before deletion
    assert c.get("/api/v1/auth/me", headers=_auth(victim)).status_code == 200

    # delete
    r = c.delete("/api/v1/auth/users/victim", headers=_auth(admin))
    assert r.status_code == 200, r.text
    assert r.json()["deleted"] is True

    # victim can no longer log in / use the (now revoked) token
    assert c.get("/api/v1/auth/me", headers=_auth(victim)).status_code == 401
    assert _login(c, "victim", "password123").status_code == 401
    # deleted user is hidden from the default list ...
    users = c.get("/api/v1/auth/users", headers=_auth(admin)).json()
    assert all(u["username"] != "victim" for u in users)
    # ... but visible with include_deleted
    users_all = c.get("/api/v1/auth/users?include_deleted=true", headers=_auth(admin)).json()
    assert any(u["username"] == "victim" for u in users_all)

    # restore brings the account back
    r = c.post("/api/v1/auth/users/victim/restore", headers=_auth(admin))
    assert r.status_code == 200, r.text
    assert r.json()["is_active"] is True
    assert _login(c, "victim", "password123").status_code == 200


def test_superadmin_cannot_be_deleted(sqlite_app):
    c = sqlite_app
    admin = _login(c, "admin", "cryptoscan").json()["token"]
    r = c.delete("/api/v1/auth/users/admin", headers=_auth(admin))
    assert r.status_code == 403


def test_delete_unknown_user_404(sqlite_app):
    c = sqlite_app
    admin = _login(c, "admin", "cryptoscan").json()["token"]
    assert c.delete("/api/v1/auth/users/ghost", headers=_auth(admin)).status_code == 404


def test_non_admin_cannot_delete(sqlite_app):
    c = sqlite_app
    _register(c, "regular", role="readonly")
    token = _login(c, "regular", "password123").json()["token"]
    _register(c, "target", role="readonly")
    assert c.delete("/api/v1/auth/users/target", headers=_auth(token)).status_code in (401, 403)


def test_register_normalizes_email_and_rejects_bad(sqlite_app):
    c = sqlite_app
    r = _register(c, "olive", role="readonly", email="Olive@Example.COM")
    assert r.status_code == 201
    # email is stored lowercased and served back normalized via /me
    token = _login(c, "olive", "password123").json()["token"]
    assert c.get("/api/v1/auth/me", headers=_auth(token)).json()["email"] == "olive@example.com"
    # a malformed email is rejected at registration time
    r = _register(c, "pete", role="readonly", email="not-an-email")
    assert r.status_code == 422


# --------------------------------------------------------------- /me profile

def test_me_returns_canonical_roles_permissions_and_profile(sqlite_app):
    c = sqlite_app
    _register(c, "erin", role="auditor")
    token = _login(c, "erin", "password123").json()["token"]
    r = c.get("/api/v1/auth/me", headers=_auth(token))
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "erin"
    assert body["roles"] == ["auditor"]
    assert "audit.read" in body["permissions"]
    assert body["mfa_enabled"] is False
    assert body["active_sessions"] >= 1


def test_update_me_profile(sqlite_app):
    c = sqlite_app
    _register(c, "frank", role="readonly")
    token = _login(c, "frank", "password123").json()["token"]
    r = c.patch("/api/v1/auth/me", headers=_auth(token),
                json={"display_name": "Frank F", "email": "Frank@Example.com"})
    assert r.status_code == 200, r.text
    assert r.json()["display_name"] == "Frank F"
    assert r.json()["email"] == "frank@example.com"  # normalized lowercase


def test_update_me_rejects_bad_email(sqlite_app):
    c = sqlite_app
    _register(c, "gina", role="readonly")
    token = _login(c, "gina", "password123").json()["token"]
    r = c.patch("/api/v1/auth/me", headers=_auth(token), json={"email": "not-an-email"})
    assert r.status_code == 422


# ------------------------------------------------------- self-service password

def test_change_password_requires_current(sqlite_app):
    c = sqlite_app
    _register(c, "hank", password="password123", role="readonly")
    token = _login(c, "hank", "password123").json()["token"]
    r = c.post("/api/v1/auth/me/password", headers=_auth(token),
               json={"current_password": "wrong-old", "new_password": "brand-new-pass-9"})
    assert r.status_code == 401


def test_change_password_rejects_same_password(sqlite_app):
    c = sqlite_app
    _register(c, "ivy", password="password123", role="readonly")
    token = _login(c, "ivy", "password123").json()["token"]
    r = c.post("/api/v1/auth/me/password", headers=_auth(token),
               json={"current_password": "password123", "new_password": "password123"})
    assert r.status_code == 422


def test_change_password_rotates_and_revokes_other_sessions(sqlite_app):
    c = sqlite_app
    _register(c, "jane", password="password123", role="developer")
    # two independent sessions (two devices)
    t1 = _login(c, "jane", "password123").json()["token"]
    t2 = _login(c, "jane", "password123").json()["token"]
    assert t1 != t2

    r = c.post("/api/v1/auth/me/password", headers=_auth(t1),
               json={"current_password": "password123", "new_password": "rotated-pass-1"})
    assert r.status_code == 200, r.text
    assert r.json()["revoked_other_sessions"] >= 1

    # current session still works
    assert c.get("/api/v1/auth/me", headers=_auth(t1)).status_code == 200
    # the other device's token is revoked
    assert c.get("/api/v1/auth/me", headers=_auth(t2)).status_code == 401
    # old password no longer works, new one does
    assert _login(c, "jane", "password123").status_code == 401
    assert _login(c, "jane", "rotated-pass-1").status_code == 200


# ------------------------------------------------------------------- sessions

def test_list_and_revoke_sessions(sqlite_app):
    c = sqlite_app
    _register(c, "kim", password="password123", role="readonly")
    t1 = _login(c, "kim", "password123").json()["token"]
    _login(c, "kim", "password123")  # second device

    r = c.get("/api/v1/auth/me/sessions", headers=_auth(t1))
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    assert r.json()["active_count"] == 2
    current = [s for s in sessions if s["current"]]
    assert len(current) == 1
    # tokens are never exposed
    assert all("token" not in s for s in sessions)

    # log out everywhere else
    r = c.post("/api/v1/auth/me/sessions/revoke", headers=_auth(t1),
               json={"include_current": False})
    assert r.status_code == 200
    assert r.json()["revoked"] >= 1

    r = c.get("/api/v1/auth/me/sessions", headers=_auth(t1))
    assert r.json()["active_count"] == 1
    assert r.json()["sessions"][0]["current"] is True


# ----------------------------------------------------------------- realtime

def test_auth_events_published(sqlite_app):
    c = sqlite_app
    admin = _login(c, "admin", "cryptoscan").json()["token"]

    _register(c, "leo", role="readonly")
    _login(c, "leo", "password123")
    types = _recent_event_types(c, admin)
    assert "auth.register" in types
    assert "auth.login" in types

    # failed login publishes auth.login_failed
    c.post("/api/v1/auth/login", json={"username": "leo", "password": "nope"})
    types = _recent_event_types(c, admin)
    assert "auth.login_failed" in types


def test_password_change_event_published(sqlite_app):
    c = sqlite_app
    admin = _login(c, "admin", "cryptoscan").json()["token"]
    _register(c, "mia", password="password123", role="readonly")
    token = _login(c, "mia", "password123").json()["token"]
    c.post("/api/v1/auth/me/password", headers=_auth(token),
           json={"current_password": "password123", "new_password": "fresh-pass-77"})
    types = _recent_event_types(c, admin)
    assert "auth.password_change" in types


# --------------------------------------------------------------- rate limiting

def test_register_rate_limited(monkeypatch, tmp_path):
    # tighten the register window before the app builds its middleware stack
    import api.middleware.rate_limit as rl

    monkeypatch.setitem(rl.DEFAULT_RULES, "register", (3, 3600))
    monkeypatch.setitem(rl.DEFAULT_RULES, "api", (100_000, 60))
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/rl.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod
    engine_mod._ENGINE = None

    from api.main import create_app
    with TestClient(create_app()) as client:
        statuses = [_register(client, f"rl{i}", role="readonly").status_code for i in range(6)]
    assert statuses.count(201) == 3, statuses
    assert 429 in statuses, statuses
