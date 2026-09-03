"""Integration: deterministic policy-exception lifecycle (no AI/ML).

Risk-acceptance exceptions are time-boxed, HMAC-signed on approval, periodically
reviewed, and auto-expired — a deterministic governance control. This exercises
the full lifecycle end to end.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"


def _token(roles=("ciso",)):
    from api.security.session_manager import SessionManager

    return SessionManager(secret="test-secret-key-for-sessions-min-32-chars").create_session(
        "admin", roles=list(roles))


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "policy_exceptions_integration_test.db")
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


def _create(client, **overrides):
    body = {
        "exception_type": "RISK_ACCEPTANCE",
        "justification": "legacy mainframe cannot be migrated this quarter",
        "risk_statement": "3DES used in batch file transfer with compensating controls",
        "compensating_controls": "VPN tunnel + file integrity monitoring",
        "expiration_date": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
        "review_frequency": "QUARTERLY",
    }
    body.update(overrides)
    return client.post(f"{API}/exceptions", json=body)


class TestExceptionLifecycle:
    def test_create_starts_pending(self, client):
        r = _create(client)
        assert r.status_code == 200, r.text
        exc = r.json()
        assert exc["status"] == "PENDING"
        assert exc["approval_signature"] is None

    def test_approve_signs_exception(self, client):
        exc_id = _create(client).json()["id"]
        r = client.post(f"{API}/exceptions/{exc_id}/approve", json={"notes": "accepted for Q3"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "APPROVED"
        assert body["approved_by"]
        # deterministic HMAC approval signature must be present and stable-shaped
        assert body["approval_signature"] and len(body["approval_signature"]) == 64

    def test_reject(self, client):
        exc_id = _create(client).json()["id"]
        r = client.post(f"{API}/exceptions/{exc_id}/reject", json={"notes": "no budget"})
        assert r.status_code == 200
        assert r.json()["status"] == "REJECTED"

    def test_review_still_valid_keeps_approved(self, client):
        exc_id = _create(client).json()["id"]
        client.post(f"{API}/exceptions/{exc_id}/approve")
        r = client.post(f"{API}/exceptions/{exc_id}/review",
                        json={"still_valid": True, "notes": "controls still effective",
                              "action_taken": "RENEWED"})
        assert r.status_code == 200, r.text
        assert r.json()["still_valid"] in (True, "true", 1)

    def test_review_invalid_revokes(self, client):
        exc_id = _create(client).json()["id"]
        client.post(f"{API}/exceptions/{exc_id}/approve")
        client.post(f"{API}/exceptions/{exc_id}/review",
                    json={"still_valid": False, "notes": "system migrated"})
        g = client.get(f"{API}/exceptions/{exc_id}").json()
        assert g["status"] == "REVOKED"

    def test_expire_due_only_expires_past_dates(self, client):
        # one already-expired approved exception
        past = _create(client, expiration_date=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat())
        past_id = past.json()["id"]
        client.post(f"{API}/exceptions/{past_id}/approve")
        # one future-dated approved exception that must survive
        future_id = _create(client,
                            expiration_date=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
                            ).json()["id"]
        client.post(f"{API}/exceptions/{future_id}/approve")

        r = client.post(f"{API}/exceptions/expire-due")
        assert r.status_code == 200, r.text

        assert client.get(f"{API}/exceptions/{past_id}").json()["status"] == "EXPIRED"
        assert client.get(f"{API}/exceptions/{future_id}").json()["status"] == "APPROVED"

    def test_list_filter_by_status(self, client):
        r = client.get(f"{API}/exceptions?status=PENDING")
        assert r.status_code == 200
        assert all(e["status"] == "PENDING" for e in r.json()["exceptions"])

    def test_actions_on_unknown_404(self, client):
        assert client.post(f"{API}/exceptions/nope/approve").status_code == 404
        assert client.get(f"{API}/exceptions/nope").status_code == 404
