"""Integration: notification routing preferences persist across reloads.

Event-class -> channel routing (in-app/email/webhook/SIEM) is stored in the
settings key/value store so it survives a new request; only the four known
channels are persisted.
"""
from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"


def _token(roles=("admin",)):
    from api.security.session_manager import SessionManager

    return SessionManager(secret="test-secret-key-for-sessions-min-32-chars").create_session(
        "admin", roles=list(roles))


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "notifications_integration_test.db")
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(db_file + ext):
            os.remove(db_file + ext)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"

    from api.config.settings import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {_token()}"
        yield c


class TestNotificationRouting:
    def test_empty_by_default(self, client):
        r = client.get(f"{API}/notifications/routing")
        assert r.status_code == 200
        assert r.json()["routing"] == []
        assert r.json()["persisted"] is False

    def test_put_then_get_persists(self, client):
        payload = {"routing": [
            {"id": "n1", "name": "Critical crypto change", "severity": "CRITICAL",
             "channels": {"inApp": True, "email": True, "webhook": False, "siem": True}},
        ]}
        r = client.put(f"{API}/notifications/routing", json=payload)
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert r.json()["count"] == 1

        g = client.get(f"{API}/notifications/routing").json()
        assert g["persisted"] is True
        assert g["routing"][0]["id"] == "n1"
        assert g["routing"][0]["channels"] == {"inApp": True, "email": True, "webhook": False, "siem": True}

    def test_unknown_channels_are_stripped(self, client):
        r = client.put(f"{API}/notifications/routing", json={"routing": [
            {"id": "n9", "name": "x", "severity": "LOW",
             "channels": {"inApp": True, "pager": True, "carrier_pigeon": True}},
        ]})
        assert r.status_code == 200
        chans = r.json()["routing"][0]["channels"]
        assert "pager" not in chans and "carrier_pigeon" not in chans
        assert chans == {"inApp": True}
