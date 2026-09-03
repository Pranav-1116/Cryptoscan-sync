"""Integration: deterministic remediation-SLA tracking (no AI/ML)."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"
NOW = datetime(2026, 9, 3, tzinfo=timezone.utc)


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
    db_file = os.path.join(tempfile.gettempdir(), "sla_integration_test.db")
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


def _iso(days_ago):
    return (NOW - timedelta(days=days_ago)).isoformat()


class TestSla:
    def test_policy_table_exposed(self, client):
        r = client.get(f"{API}/sla/policy")
        assert r.status_code == 200
        body = r.json()
        assert body["sla_days"]["CRITICAL"] == 7
        assert "BREACHED" in body["states"]

    def test_evaluate_posted_findings(self, client):
        r = client.post(f"{API}/sla/evaluate", json={
            "findings": [
                {"id": "recent", "severity": "HIGH", "detected_at": _iso(2)},
                {"id": "breached", "severity": "HIGH", "detected_at": _iso(45)},
                {"id": "critical-breached", "severity": "CRITICAL",
                 "detected_at": _iso(200), "asset_criticality": "SAFETY"},
                {"id": "resolved", "severity": "LOW", "detected_at": _iso(100),
                 "resolved_at": _iso(90)},
            ],
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["breached"] == 2
        assert body["on_track"] == 1
        assert body["resolved"] == 1
        assert body["source"] == "posted"
        states = {i["finding_id"]: i["state"] for i in body["items"]}
        assert states["breached"] == "BREACHED"
        assert states["recent"] == "ON_TRACK"
        assert states["resolved"] == "RESOLVED"

    def test_custom_sla_days(self, client):
        r = client.post(f"{API}/sla/evaluate", json={
            "sla_days": {"HIGH": 5, "MEDIUM": 30, "LOW": 60, "CRITICAL": 1, "INFO": 365,
                         "UNKNOWN": 30},
            "findings": [{"id": "x", "severity": "HIGH", "detected_at": _iso(10)}],
        })
        assert r.status_code == 200
        assert r.json()["breached"] == 1  # 10 days > 5-day custom HIGH window

    def test_live_source_flag(self, client):
        # empty live store still returns a well-formed report
        r = client.post(f"{API}/sla/evaluate", json={"use_live": True})
        assert r.status_code == 200
        assert r.json()["source"] == "live_evidence"
