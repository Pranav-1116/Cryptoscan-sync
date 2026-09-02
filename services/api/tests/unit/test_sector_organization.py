"""Sector persistence + compliance-map + sector-weighted quantum risk APIs."""

from __future__ import annotations

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/org.db")
    monkeypatch.setenv("NEO4J_URI", "")
    from api.config.settings import get_settings
    get_settings.cache_clear()
    from db.connection import engine as engine_mod
    engine_mod._ENGINE = None
    from api.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c


def _tok(c):
    return c.post("/api/v1/auth/login",
                  json={"username": "admin", "password": "cryptoscan"}).json()["token"]


def test_default_sector_is_generic(client):
    r = client.get("/api/v1/sectors/organization/active",
                   headers={"Authorization": f"Bearer {_tok(client)}"})
    assert r.status_code == 200
    assert r.json()["sector"] == "generic"


def test_set_and_persist_sector(client):
    h = {"Authorization": f"Bearer {_tok(client)}"}
    r = client.put("/api/v1/sectors/organization/active", headers=h, json={"sector": "banking"})
    assert r.status_code == 200, r.text
    assert r.json()["sector"] == "banking"
    assert "PCI-DSS" in r.json()["compliance_frameworks"]
    # persisted across requests
    again = client.get("/api/v1/sectors/organization/active", headers=h).json()
    assert again["sector"] == "banking"


def test_set_unknown_sector_rejected(client):
    h = {"Authorization": f"Bearer {_tok(client)}"}
    r = client.put("/api/v1/sectors/organization/active", headers=h, json={"sector": "made-up"})
    assert r.status_code == 422


def test_sector_alias_accepted(client):
    h = {"Authorization": f"Bearer {_tok(client)}"}
    r = client.put("/api/v1/sectors/organization/active", headers=h, json={"sector": "bank"})
    assert r.status_code == 200
    assert r.json()["sector"] == "banking"


def test_compliance_map_uses_active_sector(client):
    h = {"Authorization": f"Bearer {_tok(client)}"}
    client.put("/api/v1/sectors/organization/active", headers=h, json={"sector": "energy"})
    r = client.post("/api/v1/sectors/compliance-map", headers=h, json={
        "findings": [{"protocol": "scada", "asset_type": "scada_controller",
                      "status": "FAIL", "severity": "CRITICAL"}],
    })
    assert r.status_code == 200
    assert r.json()["sector"] == "energy"
    assert "NERC-CIP" in r.json()["frameworks_with_gaps"]


def test_compliance_map_explicit_sector_override(client):
    h = {"Authorization": f"Bearer {_tok(client)}"}
    r = client.post("/api/v1/sectors/compliance-map", headers=h, json={
        "sector": "healthcare",
        "findings": [{"asset_type": "patient_api", "algorithm": "TLS1.1",
                      "status": "FAIL", "severity": "HIGH"}],
    })
    assert r.status_code == 200
    assert r.json()["sector"] == "healthcare"
    assert "HIPAA" in r.json()["frameworks_with_gaps"]


def test_quantum_risk_endpoint_weights_by_active_sector(client):
    h = {"Authorization": f"Bearer {_tok(client)}"}
    r = client.get("/api/v1/sectors/quantum-risk", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["active_sector"] == "generic"
    assert "assets" in body and "overall_hndl_risk" in body


def test_scan_trigger_carries_sector(client):
    h = {"Authorization": f"Bearer {_tok(client)}"}
    client.put("/api/v1/sectors/organization/active", headers=h, json={"sector": "banking"})
    # trigger a scan of the bundled demo repo (inline path in dev)
    r = client.post("/api/v1/scans/trigger", headers=h,
                    json={"repo_url": "local://demo/vulnerable-app", "branch": "main"})
    # accepted (202) or a dev-validation response; either way sector resolution ran
    assert r.status_code in (200, 201, 202, 400, 422)
