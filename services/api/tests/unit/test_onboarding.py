"""Enterprise onboarding workflow: org -> sector -> env -> scope -> connections
-> test -> discovery start.
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/onb.db")
    monkeypatch.setenv("NEO4J_URI", "")
    from api.config.settings import get_settings
    get_settings.cache_clear()
    from db.connection import engine as engine_mod
    engine_mod._ENGINE = None
    from api.events.bus import reset_event_bus
    reset_event_bus()
    from api.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c


def _admin(c):
    return c.post("/api/v1/auth/login",
                  json={"username": "admin", "password": "cryptoscan"}).json()["token"]


def _bootstrap(c, sector="banking"):
    h = {"Authorization": f"Bearer {_admin(c)}"}
    c.post("/api/v1/onboarding/organization", headers=h,
           json={"name": "Example Bank", "sector": sector})
    c.post("/api/v1/onboarding/environments", headers=h,
           json={"name": "Production", "env_type": "production"})
    c.post("/api/v1/onboarding/scope", headers=h, json={"kind": "network", "target": "10.10.0.0/16"})
    c.post("/api/v1/onboarding/scope", headers=h, json={"kind": "cloud", "target": "aws-acct-1"})
    conn = c.post("/api/v1/onboarding/connections", headers=h,
                  json={"kind": "aws", "name": "AWS-ro", "method": "iam_role",
                        "config": {"role_arn": "arn:aws:iam::1:role/ro"}}).json()
    c.post(f"/api/v1/onboarding/connections/{conn['id']}/test", headers=h)
    return h


def test_empty_state(client):
    t = _admin(client)
    state = client.get("/api/v1/onboarding/state", headers={"Authorization": f"Bearer {t}"}).json()
    assert state["organization"] is None
    assert state["ready"] is False
    assert state["stage"] == "organization"
    # all checklist steps pending except none
    assert all(not step["done"] for step in state["checklist"])


def test_full_journey_to_discovery(client):
    h = _bootstrap(client)
    r = client.post("/api/v1/onboarding/discovery/start", headers=h)
    assert r.status_code == 202
    body = r.json()
    assert body["sector"] == "banking"
    domains = {d["domain"] for d in body["plan"]}
    assert {"network", "cloud", "vendor"} <= domains
    state = client.get("/api/v1/onboarding/state", headers=h).json()
    assert state["ready"] is True
    assert state["stage"] == "discovery"


def test_sector_drives_context(client):
    h = _bootstrap(client, sector="energy")
    state = client.get("/api/v1/onboarding/state", headers=h).json()
    assert state["sector_context"]["sector"] == "energy"
    assert "NERC-CIP" in state["sector_context"]["compliance_frameworks"]


def test_ot_environment_forces_passive(client):
    h = _bootstrap(client)
    r = client.post("/api/v1/onboarding/environments", headers=h,
                    json={"name": "OT", "env_type": "ot", "active_probing": True})
    assert r.status_code == 201
    assert r.json()["scan_mode"] == "passive"
    assert r.json()["active_probing"] is False


def test_scope_validation_rejects_bad_cidr(client):
    h = _bootstrap(client)
    r = client.post("/api/v1/onboarding/scope", headers=h,
                    json={"kind": "network", "target": "garbage!!"})
    assert r.status_code == 422
    good = client.post("/api/v1/onboarding/scope", headers=h,
                       json={"kind": "network", "target": "192.168.0.0/24"})
    assert good.status_code == 201


def test_secret_never_persisted(client):
    h = {"Authorization": f"Bearer {_admin(client)}"}
    client.post("/api/v1/onboarding/organization", headers=h, json={"name": "Sec Co", "sector": "generic"})
    conn = client.post("/api/v1/onboarding/connections", headers=h, json={
        "kind": "aws", "name": "aws", "method": "iam_role",
        "config": {"role_arn": "arn:x", "aws_secret_access_key": "LEAKED-SECRET"},
    }).json()
    assert conn["config"]["aws_secret_access_key"] == "<redacted-secret-not-stored>"
    # listing excludes config entirely
    listed = client.get("/api/v1/onboarding/connections", headers=h).json()["connections"]
    assert all("config" not in c for c in listed)


def test_discovery_blocked_until_ready(client):
    h = {"Authorization": f"Bearer {_admin(client)}"}
    # no org -> start discovery 404s/409s
    # with only an org and no environments/scope/connections, discovery is blocked
    client.post("/api/v1/onboarding/organization", headers=h, json={"name": "X", "sector": "generic"})
    r = client.post("/api/v1/onboarding/discovery/start", headers=h)
    assert r.status_code in (409, 404)  # blocked until environments + scope + a connection exist


def test_duplicate_org_rejected(client):
    h = {"Authorization": f"Bearer {_admin(client)}"}
    client.post("/api/v1/onboarding/organization", headers=h, json={"name": "One", "sector": "generic"})
    r = client.post("/api/v1/onboarding/organization", headers=h, json={"name": "Two", "sector": "generic"})
    assert r.status_code == 409


def test_discovery_executes_and_registers_engine_targets(client):
    h = _bootstrap(client)
    r = client.post("/api/v1/onboarding/discovery/start", headers=h)
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "complete"
    # authorized scope is materialized into the universal engine's tables
    assert body["registered"]["cloud_accounts"] >= 1
    # the declared CIDR (10.10.0.0/16) is authorization scope and must NOT
    # be materialized as a TLS probe target; only concrete hosts are
    assert body["registered"].get("network_scope_ranges", 0) >= 1
    assert body["assets_estimate"] > 0
    # run is persisted and retrievable
    run = client.get(f"/api/v1/onboarding/discovery/{body['run_id']}", headers=h).json()
    assert run["status"] == "complete"
    runs = client.get("/api/v1/onboarding/discovery/runs", headers=h).json()["runs"]
    assert any(x["id"] == body["run_id"] for x in runs)
    # engine tables actually received the scope
    from db.connection.session import SessionLocal
    from db.repositories.cloud_account_repository import CloudAccountRepository
    from db.repositories.network_scan_target_repository import (
        NetworkScanTargetRepository,
    )
    s = SessionLocal()
    try:
        assert any(a.account_identifier for a in CloudAccountRepository(s).list_accounts())
        # the CIDR never enters the due-scan rotation (ranges are scope, not
        # targets); a /16 sitting here as an enabled TLS target is the
        # active-sweep-without-authorization bug, not a success
        assert not any(t.endpoint == "10.10.0.0/16"
                       for t in NetworkScanTargetRepository(s).list_targets())
    finally:
        s.close()


def test_agent_heartbeat(client):
    h = {"Authorization": f"Bearer {_admin(client)}"}
    client.post("/api/v1/onboarding/organization", headers=h, json={"name": "OT Co", "sector": "energy"})
    # unknown agent -> 404
    assert client.post("/api/v1/onboarding/agent/heartbeat", headers=h,
                       json={"agent_id": "ghost"}).status_code == 404
    conn = client.post("/api/v1/onboarding/connections", headers=h, json={
        "kind": "hardware", "name": "plant-agent", "method": "agent",
        "config": {"agent_id": "agent-9", "host": "hsm-1"}}).json()
    hb = client.post("/api/v1/onboarding/agent/heartbeat", headers=h,
                     json={"agent_id": "agent-9", "version": "1.2.3", "healthy": True, "link": "encrypted"})
    assert hb.status_code == 200
    assert hb.json()["healthy"] is True
    assert hb.json()["status"] == "connected"
    state = client.get("/api/v1/onboarding/state", headers=h).json()
    agent = next(c for c in state["connections"] if c["id"] == conn["id"])
    assert agent["agent_healthy"] is True
    assert agent["agent_link"] == "encrypted"


def test_maintenance_window_and_ot_active_probe_lock(client):
    h = {"Authorization": f"Bearer {_admin(client)}"}
    client.post("/api/v1/onboarding/organization", headers=h, json={"name": "Grid", "sector": "energy"})
    env = client.post("/api/v1/onboarding/environments", headers=h,
                      json={"name": "ICS", "env_type": "ot"}).json()
    upd = client.patch(f"/api/v1/onboarding/environments/{env['id']}", headers=h, json={
        "maintenance_window_enabled": True, "maintenance_timezone": "UTC",
        "maintenance_windows": [{"day": "sun", "start": "01:00", "duration_minutes": 120}]}).json()
    assert upd["maintenance_window_enabled"] is True
    assert upd["maintenance_windows"][0]["day"] == "sun"
    # OT can never enable active probing even via PATCH
    forced = client.patch(f"/api/v1/onboarding/environments/{env['id']}", headers=h,
                          json={"active_probing": True}).json()
    assert forced["active_probing"] is False


def test_scope_and_connection_management(client):
    h = _bootstrap(client)
    entry = client.post("/api/v1/onboarding/scope", headers=h,
                        json={"kind": "hardware", "target": "hsm-01"}).json()
    rd = client.delete(f"/api/v1/onboarding/scope/{entry['id']}", headers=h)
    assert rd.status_code == 204
    conn = client.post("/api/v1/onboarding/connections", headers=h, json={
        "kind": "siem", "name": "splunk", "method": "syslog", "config": {"endpoint": "https://siem"}}).json()
    rc = client.delete(f"/api/v1/onboarding/connections/{conn['id']}", headers=h)
    assert rc.status_code == 204
    assert client.delete("/api/v1/onboarding/scope/does-not-exist", headers=h).status_code == 404
