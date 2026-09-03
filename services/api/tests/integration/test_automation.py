"""Integration: deterministic automation engine (no AI/ML).

Covers scanner auto-selection preview, adaptive scheduling, rule CRUD/validation,
and end-to-end event processing -> plan with auto vs approval-gated actions.
"""

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
    db_file = os.path.join(tempfile.gettempdir(), "automation_integration_test.db")
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


class TestAutomation:
    def test_capabilities_listed(self, client):
        r = client.get(f"{API}/automation/capabilities")
        assert r.status_code == 200
        body = r.json()
        assert "quantum_vulnerable_detected" in body["event_kinds"]
        assert "create_alert" in body["actions"]
        assert any("pqc" in p["id"] for p in body["playbooks"])

    def test_scanner_selection_preview(self, client):
        r = client.post(f"{API}/automation/select-scanners", json={"assets": [
            {"id": "r1", "asset_kind": "router", "vendor": "Cisco", "exposes_tls": True},
            {"id": "i1", "asset_kind": "cloud_instance", "cloud_provider": "aws"},
        ]})
        assert r.status_code == 200
        sel = {s["asset_id"]: s["scanners"] for s in r.json()["selections"]}
        assert "network_scanner" in sel["r1"]
        assert "cloud_scanner" in sel["i1"]

    def test_schedule_preview(self, client):
        r = client.post(f"{API}/automation/schedule", json={"assets": [
            {"id": "changed", "criticality": "LOW",
             "last_scanned_at": (NOW - timedelta(days=5)).isoformat(),
             "last_changed_at": (NOW - timedelta(hours=1)).isoformat()},
            {"id": "stable-critical", "criticality": "CRITICAL",
             "last_scanned_at": (NOW - timedelta(minutes=5)).isoformat()},
        ]})
        assert r.status_code == 200
        due_ids = {s["asset_id"] for s in r.json()["due"]}
        assert "changed" in due_ids  # recent change -> immediate

    def test_rule_create_validates(self, client):
        r = client.post(f"{API}/automation/rules", json={
            "rule_id": "rsa-critical", "name": "RSA critical",
            "when": "crypto_asset_detected",
            "if": [{"field": "algorithm", "operator": "equals", "value": "RSA"},
                   {"field": "criticality", "operator": "equals", "value": "CRITICAL"}],
            "then": ["create_alert", "create_ticket", "add_pqc_queue"],
            "severity": "HIGH",
        })
        assert r.status_code == 201, r.text
        # invalid operator rejected
        bad = client.post(f"{API}/automation/rules", json={
            "rule_id": "bad", "when": "any",
            "if": [{"field": "x", "operator": "regex_destructive", "value": "y"}],
            "then": ["create_alert"],
        })
        assert bad.status_code == 422
        # invalid action rejected
        bad2 = client.post(f"{API}/automation/rules", json={
            "rule_id": "bad2", "when": "any", "then": ["rm_production"],
        })
        assert bad2.status_code == 422

    def test_rules_listed(self, client):
        r = client.get(f"{API}/automation/rules")
        assert r.status_code == 200
        ids = {x["rule_id"] for x in r.json()["rules"]}
        assert "rsa-critical" in ids

    def test_process_event_pqc_playbook_gates_execution(self, client):
        r = client.post(f"{API}/automation/process-event", json={
            "event_kind": "quantum_vulnerable_detected",
            "data": {"asset_id": "a-rsa", "algorithm": "RSA", "key_size": 2048,
                     "criticality": "CRITICAL"},
            "asset": {"id": "a-rsa", "asset_kind": "application", "exposes_tls": True},
        })
        assert r.status_code == 201, r.text
        body = r.json()
        plan = body["plan"]
        # PQC playbook matched
        assert plan["playbook"] is not None and "pqc" in plan["playbook"]["id"]
        # scanners auto-selected
        assert "crypto_scanner" in plan["scanners"]
        # auto actions present
        auto = {a["action"] for a in plan["auto_actions"]}
        assert "create_alert" in auto and "targeted_rescan" in auto and "update_cbom" in auto
        # execution gated (requires human approval)
        assert plan["needs_human"] is True
        gated = {a["action"] for a in plan["requires_approval"]}
        assert "request_approval" in gated
        # a governance approval gate was created
        assert body["governance_ref"] is not None

    def test_passive_event_runs_without_human(self, client):
        # a plain scan_completed with only observe/notify actions needs no gate
        r = client.post(f"{API}/automation/process-event", json={
            "event_kind": "scan_completed",
            "data": {"asset_id": "host-9"},
            "asset": {"id": "host-9", "asset_kind": "host"},
        })
        assert r.status_code == 201
        # playbook for scan_completed is None; no gated actions
        assert r.json()["plan"]["needs_human"] is False

    def test_runs_listed(self, client):
        r = client.get(f"{API}/automation/runs")
        assert r.status_code == 200
        assert r.json()["total_count"] >= 2

    def test_rule_delete(self, client):
        r = client.delete(f"{API}/automation/rules/rsa-critical")
        assert r.status_code == 200 and r.json()["deleted"] is True
        r2 = client.get(f"{API}/automation/rules")
        assert all(x["rule_id"] != "rsa-critical" for x in r2.json()["rules"])
