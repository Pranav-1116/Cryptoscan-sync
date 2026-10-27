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
    def test_catalog_defaults_before_persistence(self, client):
        # Before any tenant override, GET serves the canonical catalog defaults
        # (not empty) and reports persisted=False.
        r = client.get(f"{API}/notifications/routing")
        assert r.status_code == 200
        body = r.json()
        assert body["persisted"] is False
        ids = [item["id"] for item in body["routing"]]
        assert "scanner_failure" in ids and "crypto_drift" in ids
        # catalog defaults: a CRITICAL class routes to all four channels
        sf = next(x for x in body["routing"] if x["id"] == "scanner_failure")
        assert sf["channels"] == {"inApp": True, "email": True, "webhook": True, "siem": True}

    def test_catalog_endpoint(self, client):
        r = client.get(f"{API}/notifications/catalog")
        assert r.status_code == 200
        assert r.json()["channels"] == ["inApp", "email", "webhook", "siem"]
        assert len(r.json()["catalog"]) >= 8

    def test_put_then_get_merges_overrides(self, client):
        # Flip scanner_failure email OFF; everything else stays at catalog default.
        catalog = client.get(f"{API}/notifications/routing").json()["routing"]
        for item in catalog:
            if item["id"] == "scanner_failure":
                item["channels"]["email"] = False
        r = client.put(f"{API}/notifications/routing", json={"routing": catalog})
        assert r.status_code == 200
        assert r.json()["ok"] is True

        g = client.get(f"{API}/notifications/routing").json()
        assert g["persisted"] is True
        by_id = {x["id"]: x for x in g["routing"]}
        assert by_id["scanner_failure"]["channels"]["email"] is False
        # untouched classes keep catalog defaults
        assert by_id["critical_crypto_change"]["channels"]["siem"] is True
        assert by_id["crypto_drift"]["channels"]["webhook"] is True

    def test_unknown_channels_are_stripped(self, client):
        r = client.put(f"{API}/notifications/routing", json={"routing": [
            {"id": "n9", "name": "x", "severity": "LOW",
             "channels": {"inApp": True, "pager": True, "carrier_pigeon": True}},
        ]})
        assert r.status_code == 200
        chans = r.json()["routing"][0]["channels"]
        assert "pager" not in chans and "carrier_pigeon" not in chans
        assert chans == {"inApp": True}
