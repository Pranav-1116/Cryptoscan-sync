"""Integration tests for the ZELNX Control Plane (P0) API surface.

Covers tenancy + ABAC scope grants (fail-closed), vault-referenced
credentials (no secret material), agent enrollment/heartbeat/upgrade,
safe-scanning policies + emergency stop, asset identity resolution, the
durable event outbox, and detection benchmarking.
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/cp.db")
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


def _h(c):
    return {"Authorization": f"Bearer {_admin(c)}"}


# ------------------------------------------------------------- tenancy/IAM
def test_tenant_and_fail_closed_authz(client):
    h = _h(client)
    t = client.post("/api/v1/control/tenants", headers=h,
                    json={"name": "GlobalBank", "data_residency_region": "uae",
                          "processing_regions": ["uae"]})
    assert t.status_code == 201
    tenant_id = t.json()["id"]

    # no grant yet -> fail closed
    deny = client.post("/api/v1/control/authorize", headers=h, json={
        "username": "analyst1", "roles": ["security_analyst"], "action": "read",
        "region": "uae", "tenant_id": tenant_id})
    assert deny.json()["authorized"] is False

    # grant region read
    client.post("/api/v1/control/grants", headers=h, json={
        "subject": "analyst1", "actions": ["read"], "region": "uae", "tenant_id": tenant_id})
    allow = client.post("/api/v1/control/authorize", headers=h, json={
        "username": "analyst1", "roles": [], "action": "read",
        "region": "uae", "business_unit": "retail", "environment": "prod", "tenant_id": tenant_id})
    assert allow.json()["authorized"] is True

    # residency violation: analyst tries eu region
    res = client.post("/api/v1/control/authorize", headers=h, json={
        "username": "analyst1", "action": "read", "region": "eu", "tenant_id": tenant_id})
    assert res.json()["authorized"] is False
    assert "residency" in res.json()["reason"]


def test_role_grant_and_deny(client):
    h = _h(client)
    client.post("/api/v1/control/grants", headers=h, json={
        "subject": "auditor", "subject_type": "role", "actions": ["*"], "region": "eu"})
    client.post("/api/v1/control/grants", headers=h, json={
        "subject": "bob", "actions": ["*"], "effect": "deny",
        "region": "eu", "environment": "secret"})
    ok = client.post("/api/v1/control/authorize", headers=h, json={
        "username": "carol", "roles": ["auditor"], "action": "read", "region": "eu"})
    assert ok.json()["authorized"] is True
    denied = client.post("/api/v1/control/authorize", headers=h, json={
        "username": "bob", "roles": ["auditor"], "action": "read",
        "region": "eu", "environment": "secret"})
    assert denied.json()["authorized"] is False


# ---------------------------------------------------------- credentials
def test_credential_registration_rejects_secret_material(client):
    h = _h(client)
    # attempting to send an actual secret field is refused
    r = client.post("/api/v1/control/credentials", headers=h, json={
        "name": "aws-ro", "kind": "cloud", "vault_provider": "aws_secrets_manager",
        "secret_ref": "arn:aws:secretsmanager:us-east-1:1:secret:zelnx-ro",
        "aws_secret_access_key": "LEAKED-KEY"})
    assert r.status_code == 422

    ok = client.post("/api/v1/control/credentials", headers=h, json={
        "name": "aws-ro", "kind": "cloud", "vault_provider": "aws_secrets_manager",
        "secret_ref": "arn:aws:secretsmanager:us-east-1:1:secret:zelnx-ro",
        "least_privilege_scope": "ReadOnlyAccess"})
    assert ok.status_code == 201
    # the locator is not echoed back in full
    listed = client.get("/api/v1/control/credentials", headers=h).json()["credentials"]
    cred = listed[0]
    assert "secret_ref" not in cred or cred.get("secret_ref") == "<vault-reference>"
    assert cred["health"]["status"] == "active"


def test_credential_rotation(client):
    h = _h(client)
    cred = client.post("/api/v1/control/credentials", headers=h, json={
        "name": "hsm", "kind": "hsm", "vault_provider": "kms_onprem",
        "secret_ref": "vault://hsm/partition1"}).json()
    r = client.post(f"/api/v1/control/credentials/{cred['id']}/rotate", headers=h)
    assert r.status_code == 200 and r.json()["rotated"] is True


# ---------------------------------------------------------------- agents
def test_agent_lifecycle(client):
    h = _h(client)
    enr = client.post("/api/v1/control/agents/enroll", headers=h, json={
        "name": "uae-agent", "region": "uae", "environment": "ot", "platform": "ot_gateway"})
    assert enr.status_code == 201
    agent_id = enr.json()["agent_id"]
    token = enr.json()["enrollment_token"]
    assert token  # one-time token returned

    # wrong token denied
    bad = client.post("/api/v1/control/agents/heartbeat", headers=h, json={
        "agent_id": agent_id, "enrollment_token": "wrong", "version": "1.0"})
    assert bad.status_code == 403

    # correct heartbeat connects
    hb = client.post("/api/v1/control/agents/heartbeat", headers=h, json={
        "agent_id": agent_id, "enrollment_token": token,
        "version": "1.2.0", "link": "encrypted", "offline_events_buffered": 0})
    assert hb.status_code == 200 and hb.json()["status"] == "connected"

    # upgrade schedule
    up = client.post(f"/api/v1/control/agents/{agent_id}/upgrade", headers=h,
                     json={"target_version": "1.3.0", "action": "upgrade"})
    assert up.json()["target_version"] == "1.3.0"

    # fingerprint never returned
    listing = client.get("/api/v1/control/agents", headers=h).json()["agents"]
    assert all("enrollment_token_fingerprint" not in a for a in listing)


def test_unknown_agent_heartbeat_404(client):
    r = client.post("/api/v1/control/agents/heartbeat", headers=_h(client),
                    json={"agent_id": "ghost"})
    assert r.status_code == 404


# ------------------------------------------------------------- safe scan
def test_safe_scan_policy_and_emergency_stop(client):
    h = _h(client)
    client.put("/api/v1/control/safe-scan/policy", headers=h, json={
        "name": "uae-ot", "scope_region": "uae", "scope_environment": "ot",
        "mode": "passive", "rate_limit_qps": 2, "excluded_ports": [22]})

    ev = client.post("/api/v1/control/safe-scan/evaluate", headers=h, json={
        "region": "uae", "environment": "ot", "is_ot": True, "port": 443})
    body = ev.json()
    assert body["permitted"] is True and body["mode"] == "passive"

    excluded = client.post("/api/v1/control/safe-scan/evaluate", headers=h, json={
        "region": "uae", "environment": "ot", "port": 22})
    assert excluded.json()["permitted"] is False

    # emergency stop blocks everything
    client.post("/api/v1/control/safe-scan/emergency-stop", headers=h, json={"engaged": True})
    stopped = client.post("/api/v1/control/safe-scan/evaluate", headers=h, json={
        "region": "uae", "environment": "ot", "port": 443})
    assert stopped.json()["permitted"] is False
    # disengage
    client.post("/api/v1/control/safe-scan/emergency-stop", headers=h, json={"engaged": False})


# --------------------------------------------------------- asset identity
def test_asset_identity_resolution_confidence(client):
    h = _h(client)
    r = client.post("/api/v1/control/assets/resolve", headers=h, json={
        "observations": [
            {"source": "network", "asset_type": "hsm", "criticality": "tier1",
             "owner": "security", "identifiers": {"serial": "HSM-123"}},
            {"source": "cmdb", "asset_type": "hsm", "criticality": "tier1",
             "owner": "security", "identifiers": {"serial": "HSM-123"}}]})
    assert r.status_code == 200
    ident = r.json()["identity"]
    assert ident["confidence"] == "CONFIRMED"
    assert ident["asset_type"] == "hsm"
    assert set(ident["evidence_sources"]) == {"network", "cmdb"}


# ----------------------------------------------------------------- events
def test_event_outbox_priority(client):
    h = _h(client)
    client.post("/api/v1/control/events/enqueue", headers=h,
                json={"event_type": "scan.complete", "priority": "normal"})
    client.post("/api/v1/control/events/enqueue", headers=h,
                json={"event_type": "alert.critical", "priority": "critical"})
    q = client.get("/api/v1/control/events/queue?status_filter=queued", headers=h).json()["events"]
    assert q[0]["priority"] == "critical"  # highest priority first


# ------------------------------------------------------------- benchmark
def test_benchmark_scoring(client):
    h = _h(client)
    ds = client.post("/api/v1/control/benchmark/datasets", headers=h,
                     json={"name": "tls-ground-truth", "sector": "banking"}).json()
    client.post("/api/v1/control/benchmark/cases", headers=h, json={
        "dataset_id": ds["id"],
        "cases": [
            {"case_ref": "c1", "ground_truth": "RSA-2048", "expected_detection": True},
            {"case_ref": "c2", "ground_truth": "benign", "expected_detection": False}]})
    score = client.post("/api/v1/control/benchmark/score", headers=h, json={
        "dataset_id": ds["id"], "scanner_id": "universal-crypto", "scanner_version": "1.0",
        "predictions": [
            {"expected_detection": True, "predicted_detection": True},
            {"expected_detection": False, "predicted_detection": False}]})
    assert score.status_code == 200
    m = score.json()
    assert m["accuracy"] == 1.0 and m["meets_95_target"] is True
    runs = client.get("/api/v1/control/benchmark/runs", headers=h).json()["runs"]
    assert len(runs) == 1
