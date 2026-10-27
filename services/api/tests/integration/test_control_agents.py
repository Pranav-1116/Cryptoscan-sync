"""Integration: control-plane agent fleet (list + upgrade/retire), no AI."""

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
    db_file = os.path.join(tempfile.gettempdir(), "control_agents_integration_test.db")
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


class TestAgentFleet:
    def test_enroll_then_list(self, client):
        # enroll through the real endpoint
        r = client.post(f"{API}/control/agents/enroll", json={
            "name": "ot-sensor-1", "region": "eu-west", "platform": "linux",
        })
        assert r.status_code in (201, 200), r.text
        agent_id = r.json().get("agent_id") or r.json().get("id")

        lst = client.get(f"{API}/control/agents").json()["agents"]
        assert lst, "expected at least one enrolled agent"
        assert agent_id in {a["id"] for a in lst}
        # token fingerprint must never be exposed
        assert all("enrollment_token_fingerprint" not in a for a in lst)

    def test_upgrade_schedules_target(self, client):
        agents = client.get(f"{API}/control/agents").json()["agents"]
        agent = agents[0]
        r = client.post(f"{API}/control/agents/{agent['id']}/upgrade",
                        json={"action": "upgrade", "target_version": "9.9.9"})
        assert r.status_code == 200, r.text
        assert r.json()["target_version"] == "9.9.9"

    def test_retire_action(self, client):
        agents = client.get(f"{API}/control/agents").json()["agents"]
        agent = agents[0]
        r = client.post(f"{API}/control/agents/{agent['id']}/upgrade",
                        json={"action": "retire"})
        assert r.status_code == 200, r.text

    def test_upgrade_unknown_agent_404(self, client):
        r = client.post(f"{API}/control/agents/nonexistent/upgrade",
                        json={"action": "upgrade", "target_version": "1.0.0"})
        assert r.status_code == 404
