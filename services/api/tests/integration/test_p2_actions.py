"""Integration: interactive deterministic P2 action gates (no AI/ML).

Exercises the human-approval gate (governance decide), tamper-evident data-lake
seal/verify, and marketplace plugin enable/disable fail-closed enforcement —
the same operations the P2 frontend buttons drive.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"


def _token(roles=("superadmin",)):
    from api.security.session_manager import SessionManager

    return SessionManager(secret="test-secret-key-for-sessions-min-32-chars").create_session(
        "admin", roles=list(roles))


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "p2_actions_integration_test.db")
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


class TestGovernanceDecide:
    def _seed_pending(self, risk="LOW"):
        from db.connection.session import SessionLocal
        from db.models.p2 import GovernanceApproval

        db = SessionLocal()
        row = GovernanceApproval(request_type="config_change", requested_by="someone-else",
                                 status="PENDING", decision=None, risk_level=risk,
                                 rationale="test")
        db.add(row)
        db.commit()
        db.refresh(row)
        rid = row.id
        db.close()
        return rid

    def test_approve_pending_request(self, client):
        rid = self._seed_pending()
        r = client.post(f"{API}/governance/requests/{rid}/decide",
                        json={"approve": True, "note": "looks good"})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "APPROVED"

    def test_deny_pending_request(self, client):
        rid = self._seed_pending()
        r = client.post(f"{API}/governance/requests/{rid}/decide", json={"approve": False})
        assert r.status_code == 200
        assert r.json()["status"] == "DENIED"

    def test_cannot_decide_twice(self, client):
        rid = self._seed_pending()
        client.post(f"{API}/governance/requests/{rid}/decide", json={"approve": True})
        r2 = client.post(f"{API}/governance/requests/{rid}/decide", json={"approve": False})
        assert r2.status_code == 409


class TestDataLakeActions:
    def test_export_live_and_verify_chain(self, client):
        # seal a live batch (works even with zero evidence — empty, still chained)
        r = client.post(f"{API}/datalake/export/live",
                        json={"lake_id": "primary", "kind": "findings", "limit": 100})
        assert r.status_code == 200, r.text
        created = r.json()
        assert created.get("chain_digest") or created.get("batch_digest")

        batches = client.get(f"{API}/datalake/batches?lake_id=primary").json()["batches"]
        assert batches, "expected at least one sealed batch"
        # verify the newest batch cryptographically
        newest = batches[0]
        v = client.post(f"{API}/datalake/verify/{newest['id']}")
        assert v.status_code == 200, v.text
        assert v.json()["verified"] is True, v.json()


class TestPluginFailClosed:
    def _seed_plugin(self, state, trusted):
        from db.connection.session import SessionLocal
        from db.models.p2 import PluginPackage

        db = SessionLocal()
        import uuid
        row = PluginPackage(
            plugin_id=f"test-plugin-{uuid.uuid4().hex[:8]}", version="1.0.0",
            plugin_type="rules", name="test", state=state, trusted=trusted,
            content="rules: []", content_sha256="x" * 64)
        db.add(row)
        db.commit()
        db.refresh(row)
        pid = row.id
        db.close()
        return pid

    def test_trusted_uploaded_plugin_can_enable(self, client):
        pid = self._seed_plugin("UPLOADED", trusted=True)
        r = client.post(f"{API}/marketplace/plugins/{pid}/enable", json={})
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "ENABLED"

    def test_quarantined_plugin_cannot_enable_fail_closed(self, client):
        pid = self._seed_plugin("QUARANTINED", trusted=False)
        r = client.post(f"{API}/marketplace/plugins/{pid}/enable", json={})
        # fail-closed: a quarantined/untrusted plugin must never enable
        assert r.status_code in (403, 409)

    def test_disable_enabled_plugin(self, client):
        pid = self._seed_plugin("ENABLED", trusted=True)
        r = client.post(f"{API}/marketplace/plugins/{pid}/disable")
        assert r.status_code == 200
        assert r.json()["state"] == "DISABLED"
