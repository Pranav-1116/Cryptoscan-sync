"""Integration: deterministic operational health monitoring (no AI/ML)."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"
NOW = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)


def _token():
    from api.security.session_manager import SessionManager

    return SessionManager(secret="test-secret-key-for-sessions-min-32-chars").create_session(
        "admin", roles=["superadmin"])


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "automation_health_integration_test.db")
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


class TestPlatformHealth:
    def test_metrics_health_classification(self, client):
        r = client.post(f"{API}/automation/health/platform", json={"metrics": {
            "queue_depth": 600, "cpu_pct": 30, "success_rate_pct": 99.9,
        }})
        assert r.status_code == 200, r.text
        body = r.json()
        states = {t["target_id"]: t["state"] for t in body["targets"]}
        assert states["queue_depth"] == "UNHEALTHY"
        assert states["cpu_pct"] == "HEALTHY"
        assert states["success_rate_pct"] == "HEALTHY"
        assert body["alert_count"] >= 1

    def test_error_rate_healthy_below_warn(self, client):
        r = client.post(f"{API}/automation/health/platform", json={"metrics": {
            "error_rate_pct": 0.2, "api_latency_p95_ms": 100,
        }})
        body = r.json()
        assert body["alert_count"] == 0


class TestHealthSweep:
    def _seed_connector(self, client, name, status, **kw):
        body = {"kind": kw.get("kind", "aws"), "name": name, "method": "api",
                "mode": kw.get("mode", "passive"), "org_id": kw.get("org_id", "org-1"),
                "status": status}
        if "test_result" in kw:
            body["test_result"] = kw["test_result"]
        # use the onboarding connector endpoint if present; else create directly
        return client.post(f"{API}/onboarding/connectors", json=body)

    def test_sweep_runs_on_empty_fleet(self, client):
        r = client.post(f"{API}/automation/health/sweep")
        assert r.status_code == 200, r.text
        body = r.json()
        assert "connectors" in body and "agents" in body
        assert body["connectors"]["total"] == 0

    def test_sweep_flags_bad_connector_from_live_store(self, client):
        # seed a connector directly through the model for a deterministic bad row
        from db.connection.session import SessionLocal
        from db.models.onboarding import Connector

        db = SessionLocal()
        db.add(Connector(org_id="org-1", kind="hsm", name="hsm-conn",
                         status="error", test_result={"authentication_failure": True}))
        db.add(Connector(org_id="org-1", kind="aws", name="aws-conn",
                         status="connected", agent_link="encrypted", agent_healthy=True))
        db.commit()
        db.close()

        r = client.post(f"{API}/automation/health/sweep")
        assert r.status_code == 200
        conns = r.json()["connectors"]
        assert conns["total"] == 2
        alerts = {a["target_id"]: a for a in conns["alerts"]}
        # the HSM connector with auth failure must be a CRITICAL alert
        bad = [t for t in conns["targets"] if t["state"] == "UNHEALTHY"]
        assert any("authentication" in t["reasons"][0] for t in bad)
