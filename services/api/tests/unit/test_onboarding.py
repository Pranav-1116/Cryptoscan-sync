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
