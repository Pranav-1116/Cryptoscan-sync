"""Sector Layer API endpoints."""

from __future__ import annotations

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/sectors.db")
    monkeypatch.setenv("NEO4J_URI", "")
    from api.config.settings import get_settings
    get_settings.cache_clear()
    from db.connection import engine as engine_mod
    engine_mod._ENGINE = None
    from api.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c


def _token(c):
    return c.post("/api/v1/auth/login",
                  json={"username": "admin", "password": "cryptoscan"}).json()["token"]


def test_requires_auth(client):
    assert client.get("/api/v1/sectors").status_code == 401


def test_list_sectors(client):
    r = client.get("/api/v1/sectors", headers={"Authorization": f"Bearer {_token(client)}"})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 10
    ids = {s["id"] for s in body["sectors"]}
    assert {"banking", "healthcare", "energy", "generic"} <= ids


def test_get_sector_detail(client):
    h = {"Authorization": f"Bearer {_token(client)}"}
    r = client.get("/api/v1/sectors/banking", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == "banking"
    assert "PCI-DSS" in body["compliance_frameworks"]
    assert "pci_dss" in body["policy_packs"]
    # OT-aware modes include passive-first
    assert body["recommended_modes_ot"][0]["id"] == "passive" or \
        body["recommended_modes_ot"][0]["ot_safe"]


def test_sector_alias_resolves(client):
    h = {"Authorization": f"Bearer {_token(client)}"}
    r = client.get("/api/v1/sectors/bank", headers=h)
    assert r.status_code == 200
    assert r.json()["id"] == "banking"


def test_unknown_sector_404(client):
    h = {"Authorization": f"Bearer {_token(client)}"}
    r = client.get("/api/v1/sectors/made-up-sector", headers=h)
    assert r.status_code == 404


def test_criticality_endpoint(client):
    h = {"Authorization": f"Bearer {_token(client)}"}
    r = client.post("/api/v1/sectors/criticality", headers=h, json={
        "sector": "banking",
        "assets": [
            {"asset_type": "payment_hsm", "payment_path": True, "production": True},
            {"asset_type": "dev_workstation", "production": False, "environment": "dev"},
        ],
    })
    assert r.status_code == 200
    by_type = {a["asset_type"]: a for a in r.json()["assets"]}
    assert by_type["payment_hsm"]["criticality"] == "MISSION_CRITICAL"
    assert by_type["dev_workstation"]["criticality"] in {"VERY_LOW", "LOW"}


def test_criticality_differs_by_sector(client):
    # The sector layer changes the BASE criticality from asset type: energy
    # maps scada -> MISSION_CRITICAL; the generic profile has no such mapping.
    h = {"Authorization": f"Bearer {_token(client)}"}
    payload = {"assets": [{"asset_type": "scada_controller", "production": True}]}
    energy = client.post("/api/v1/sectors/criticality", headers=h,
                         json={"sector": "energy", **payload}).json()
    generic = client.post("/api/v1/sectors/criticality", headers=h,
                          json={"sector": "generic", **payload}).json()
    e_tier = energy["assets"][0]["criticality"]
    g_tier = generic["assets"][0]["criticality"]
    assert e_tier == "MISSION_CRITICAL"
    assert e_tier != g_tier  # same asset, different sector -> different priority


def test_scan_modes(client):
    h = {"Authorization": f"Bearer {_token(client)}"}
    all_modes = client.get("/api/v1/sectors/scan-modes", headers=h).json()["modes"]
    assert {m["id"] for m in all_modes} >= {"discovery", "passive", "deep", "continuous", "pqc"}
    ot_only = client.get("/api/v1/sectors/scan-modes?ot_safe_only=true", headers=h).json()["modes"]
    assert all(m["ot_safe"] for m in ot_only)
    assert any(m["id"] == "passive" for m in ot_only)
    assert not any(m["id"] == "deep" for m in ot_only)


def test_context_endpoint_ot(client):
    h = {"Authorization": f"Bearer {_token(client)}"}
    r = client.post("/api/v1/sectors/context", headers=h, json={
        "sector": "energy", "ot_environment": True,
        "assets": [{"asset_type": "plc", "safety_critical": True}],
    })
    assert r.status_code == 200
    body = r.json()
    assert body["active_probing_permitted"] is False
    assert body["recommended_modes"][0]["id"] == "passive"
    assert "IT" in body["environment_separation"] and "OT" in body["environment_separation"]
