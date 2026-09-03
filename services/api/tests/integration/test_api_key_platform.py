"""End-to-end tests for the P2 machine API-key platform.

Exercises the real HTTP path with a real SQLite DB: an admin creates a scoped,
rate-limited key, then that key is used over X-API-Key and the scope, method,
and quota limits are enforced (403 / 429). Deterministic — no AI/ML.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"

    db_file = os.path.join(tempfile.gettempdir(), "apikey_platform_test.db")
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(db_file + ext):
            os.remove(db_file + ext)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"

    from api.config.settings import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        from api.security.session_manager import SessionManager

        token = SessionManager(
            secret="test-secret-key-for-sessions-min-32-chars"
        ).create_session("admin", roles=["superadmin"])
        c.headers["Authorization"] = f"Bearer {token}"
        yield c


def _make_key(client, **overrides):
    body = {"name": "ci-reader", "roles": ["auditor"],
            "scopes": ["/findings"], "allowed_methods": ["GET"],
            "rate_per_minute": 2}
    body.update(overrides)
    r = client.post("/api/v1/api-keys", json=body)
    assert r.status_code == 201, r.text
    return r.json()["raw_key"]


class TestApiKeyPlatform:
    def test_key_created_with_constraints(self, client):
        r = client.post("/api/v1/api-keys", json={
            "name": "scoped", "roles": ["auditor"],
            "scopes": ["/findings"], "allowed_methods": ["GET"], "rate_per_minute": 5,
        })
        assert r.status_code == 201
        out = r.json()
        assert out["scopes"] == ["/findings"]
        assert out["allowed_methods"] == ["GET"]
        assert out["rate_per_minute"] == 5
        assert out["raw_key"].startswith("csk_")

    def test_scoped_key_allows_in_scope(self, client):
        raw = _make_key(client)
        r = client.get("/api/v1/findings", headers={"X-API-Key": raw})
        # /findings is reachable by an auditor read-only key (200)
        assert r.status_code in (200, 404)
        assert r.status_code != 403

    def test_scoped_key_denied_out_of_scope(self, client):
        raw = _make_key(client)
        # /api-keys is outside the /findings scope -> 403
        r = client.get("/api/v1/api-keys", headers={"X-API-Key": raw})
        assert r.status_code == 403, r.text

    def test_scoped_key_denied_wrong_method(self, client):
        # key scoped to /datalake but GET-only: POST to a real POST route under
        # that scope must be rejected with 403 by the method allowlist.
        raw = _make_key(client, name="getonly-lake", scopes=["/datalake"],
                        allowed_methods=["GET"], rate_per_minute=100)
        r = client.post("/api/v1/datalake/export", headers={"X-API-Key": raw},
                        json={"lake_id": "k", "records": []})
        assert r.status_code == 403, r.text

    def test_quota_exhaustion_returns_429(self, client):
        raw = _make_key(client, name="quota-bot", rate_per_minute=1)
        h = {"X-API-Key": raw}
        first = client.get("/api/v1/findings", headers=h)
        assert first.status_code in (200, 404)
        second = client.get("/api/v1/findings", headers=h)
        assert second.status_code == 429, second.text

    def test_invalid_key_rejected(self, client):
        r = client.get("/api/v1/findings", headers={"X-API-Key": "csk_doesnotexist00000000000000000000"})
        assert r.status_code == 401
