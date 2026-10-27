"""Machine API keys: repository lifecycle, router, X-API-Key auth, RBAC, audit."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from api.main import create_app
from api.middleware.rate_limit import _identity
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, SessionLocal, configure_session
from db.models.api_key import KEY_PREFIX
from db.repositories.api_key_repository import ApiKeyRepository
from db.repositories.user_repository import UserRepository


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # one shared connection: the API serves from other threads
    )
    Base.metadata.create_all(engine)
    configure_session(engine)
    s = SessionLocal()
    yield s
    s.close()


def _mint_session(db, username: str, roles: list[str]) -> str:
    """Mint a real session token + DB row (mirrors auth._issue_session)."""
    manager = SessionManager()
    token = manager.create_session(username, roles=roles)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    UserRepository(db).create_session(token, username, expires, ip="127.0.0.1")
    db.commit()
    return token


@pytest.fixture()
def admin_client(session):
    repo = UserRepository(session)
    repo.create_user("admin", hash_password("x"), ["admin", "auditor", "viewer"])
    session.commit()
    app = create_app()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", _mint_session(session, "admin", ["admin"]))
    return client


# --------------------------------------------------------------- repository

def test_repository_create_and_lookup(session):
    repo = ApiKeyRepository(session)
    row, raw = repo.create(name="ci-bot", created_by="admin", roles=["auditor"])
    assert raw.startswith(KEY_PREFIX) and len(raw) > len(KEY_PREFIX) + 16
    assert row.key_hash != raw and len(row.key_hash) == 64  # hash, never plaintext
    assert row.role_list == ["auditor"]
    found = repo.get_by_raw(raw)
    assert found is not None and found.id == row.id
    assert repo.get_by_raw("csk_totally-made-up-invalid-key-000") is None
    session.commit()


def test_repository_revocation_and_expiry(session):
    repo = ApiKeyRepository(session)
    row, raw = repo.create(name="tmp", created_by="admin")
    repo.revoke(row.id)
    session.commit()
    assert repo.get_by_raw(raw) is None  # revoked keys stop working instantly

    expired, raw2 = repo.create(
        name="old", created_by="admin",
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    session.commit()
    assert expired.is_active_key is False
    assert repo.get_by_raw(raw2) is None


def test_repository_rejects_bad_input(session):
    repo = ApiKeyRepository(session)
    with pytest.raises(ValueError):
        repo.create(name="  ", created_by="admin")
    with pytest.raises(ValueError):
        repo.create(name="bad-roles", created_by="admin", roles=["superuser"])


# ------------------------------------------------------------------- router

def test_create_list_revoke_flow_and_audit(admin_client, session):
    resp = admin_client.post(
        "/api/v1/api-keys", json={"name": "siem-pull", "roles": ["viewer", "auditor"]}
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    raw = body["raw_key"]
    assert raw.startswith(KEY_PREFIX)
    assert body["roles"] == ["auditor", "viewer"]
    assert body["key_prefix"].startswith(KEY_PREFIX) and "…" in body["key_prefix"]

    listed = admin_client.get("/api/v1/api-keys").json()
    assert any(k["name"] == "siem-pull" for k in listed)
    assert all(not k.get("raw_key") for k in listed)  # raw shown exactly once

    audit = UserRepository(session).list_audit(action="auth.api_key_create")
    assert any(a.target_id == body["id"] for a in audit)

    revoked = admin_client.delete(f"/api/v1/api-keys/{body['id']}")
    assert revoked.status_code == 200 and revoked.json()["active"] is False
    assert admin_client.delete(f"/api/v1/api-keys/{body['id']}").status_code == 200  # idempotent
    assert admin_client.delete("/api/v1/api-keys/missing").status_code == 404


def test_non_admin_cannot_manage_keys(session):
    repo = UserRepository(session)
    repo.create_user("auditor1", hash_password("x"), ["auditor"])
    session.commit()
    app = create_app()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", _mint_session(session, "auditor1", ["auditor"]))
    assert client.get("/api/v1/api-keys").status_code == 403
    assert client.post("/api/v1/api-keys", json={"name": "sneaky"}).status_code == 403


# ------------------------------------------------------- X-API-Key over API

def test_api_key_authenticates_regular_endpoints(admin_client, session):
    raw = admin_client.post(
        "/api/v1/api-keys", json={"name": "ci-bot", "roles": ["viewer"]}
    ).json()["raw_key"]

    plain = TestClient(create_app())
    # no credentials -> 401
    assert plain.get("/api/v1/scans").status_code == 401
    # valid key -> authenticated everywhere (get_current_user path)
    ok = plain.get("/api/v1/scans", headers={"X-API-Key": raw})
    assert ok.status_code == 200
    # key roles are honored: viewer cannot trigger scans (auditor-only)
    forbidden = plain.post(
        "/api/v1/scans/trigger",
        headers={"X-API-Key": raw},
        json={"repo_url": "https://github.com/example/x.git"},
    )
    assert forbidden.status_code == 403
    assert "roles" in forbidden.json()["detail"]
    # garbage key -> 401
    assert plain.get("/api/v1/scans", headers={"X-API-Key": "csk_nope"}).status_code == 401


def test_revoked_key_stops_working_and_last_use_stamped(admin_client, session):
    created = admin_client.post(
        "/api/v1/api-keys", json={"name": "tmp", "roles": ["viewer"]}
    ).json()
    raw, key_id = created["raw_key"], created["id"]
    plain = TestClient(create_app())
    assert plain.get("/api/v1/scans", headers={"X-API-Key": raw}).status_code == 200

    session.expire_all()
    row = ApiKeyRepository(session).get(key_id)
    assert row.last_used_at is not None  # usage is visible to admins

    admin_client.delete(f"/api/v1/api-keys/{key_id}")
    assert plain.get("/api/v1/scans", headers={"X-API-Key": raw}).status_code == 401


def test_auditor_key_can_trigger_gate_check(admin_client):
    # auditor-scoped key reaches auditor-only endpoints (CI gate integration)
    raw = admin_client.post(
        "/api/v1/api-keys", json={"name": "ci-gate", "roles": ["auditor"]}
    ).json()["raw_key"]
    plain = TestClient(create_app())
    resp = plain.get("/api/v1/policy/rules", headers={"X-API-Key": raw})
    assert resp.status_code == 200


# --------------------------------------------------------------- rate limit

class _FakeRequest:
    def __init__(self, headers: dict[str, str]):
        self.headers = headers
        self.client = type("C", (), {"host": "203.0.113.9"})()


def test_rate_limit_identity_uses_key_bucket():
    a = _identity(_FakeRequest({"x-api-key": "csk_aaaa"}))
    b = _identity(_FakeRequest({"x-api-key": "csk_bbbb"}))
    assert a.startswith("apikey:") and b.startswith("apikey:") and a != b
    assert _identity(_FakeRequest({"x-api-key": "csk_aaaa"})) == a  # stable
    assert _identity(_FakeRequest({})).startswith("ip:")


def test_auth_middleware_passes_api_keys_through_to_dependencies():
    """The session gate must not swallow X-API-Key requests before the
    route-level key validation runs (live regression: 401 MISSING_AUTH_HEADER)."""
    from fastapi import FastAPI
    from api.middleware.auth_middleware import AuthMiddleware

    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/api/v1/probe")
    def probe():
        return {"ok": True}

    client = TestClient(app)
    assert client.get("/api/v1/probe").status_code == 401  # nothing presented
    resp = client.get("/api/v1/probe", headers={"X-API-Key": "csk_something"})
    assert resp.status_code == 200  # reaches the route; key checked downstream
    assert client.get(
        "/api/v1/probe", headers={"Authorization": "Bearer garbage"}
    ).status_code == 401


def test_should_stamp_last_use_throttles():
    from api.dependencies import _last_use_writes, should_stamp_last_use

    _last_use_writes.clear()
    assert should_stamp_last_use("k1", now=100.0) is True
    assert should_stamp_last_use("k1", now=100.5) is False  # within 60s
    assert should_stamp_last_use("k1", now=200.0) is True
    assert should_stamp_last_use("k2", now=200.0) is True
    _last_use_writes.clear()
