"""Hardware and vendor rows a stored estate observation contributes to the BOMs.

An imported estate is not an estate without devices. These tests pin both halves of
that sentence: when an observation carries HARDWARE/HSM/VENDOR assets the HBOM and the
TechBOM layers see them, labelled with their own source; when nothing has been
observed the BOMs stay empty and say so.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.models.base import Base


@pytest.fixture
def api():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "tester"
    app.dependency_overrides[get_db_session] = lambda: session
    try:
        yield TestClient(app), session
    finally:
        session.close()
        app.dependency_overrides.clear()


def _observation() -> dict:
    """One synthetic bank estate: a payment HSM, a firewall, a vendor, a package."""
    assets = [
        {"ref": "hsm-1", "type": "HSM", "name": "bank-hsm-0",
         "identity": {"vendor": "SYNTHETIC-Vendor-000", "partition": "payment-hsm"},
         "attributes": {"kind": "payment-hsm", "model": "LAB-0",
                        "interface": "PKCS#11-SIMULATED", "lifecycle": "ACTIVE",
                        "actual_execution": False}},
        {"ref": "fw-1", "type": "HARDWARE", "name": "bank-fw-0",
         "identity": {"vendor": "SYNTHETIC-FW", "serial_number": "SN-1"},
         "attributes": {"kind": "firewall", "model": "FW-LAB", "firmware": "1.0-LAB",
                        "crypto_capabilities": ["TLS1.2"], "risk_level": "LOW"}},
        {"ref": "v-1", "type": "VENDOR", "name": "SYNTHETIC-Vendor-000",
         "identity": {"name": "SYNTHETIC-Vendor-000", "product": "SYNTHETIC-HSM-0"},
         "attributes": {"support_lifecycle": "EXPIRED", "version": "1.0"}},
        {"ref": "pkg-1", "type": "PACKAGE", "name": "bcrypt",
         "identity": {"name": "bcrypt", "version": "4.1.2", "ecosystem": "pypi"}},
    ]
    evidence = [
        {"source": "bank-sandbox", "collector": "bank-sandbox:public-fixtures",
         "evidence_type": "CONFIGURED", "target": "hsm-1", "layer": "HSM",
         "facts": {"operations": ["RSA-PSS"], "actual_execution": False}},
        {"source": "bank-sandbox", "collector": "bank-sandbox:public-fixtures",
         "evidence_type": "IMPORTED", "target": "fw-1", "layer": "PLATFORM",
         "facts": {"inventory_record": "hardware", "model": "FW-LAB"}},
        {"source": "bank-sandbox", "collector": "bank-sandbox:public-fixtures",
         "evidence_type": "VENDOR_DECLARED", "target": "v-1", "layer": "PLATFORM",
         "facts": {"product": "SYNTHETIC-HSM-0"}},
        {"source": "bank-sandbox", "collector": "bank-sandbox:public-fixtures",
         "evidence_type": "IMPORTED", "target": "pkg-1", "layer": "APPLICATION",
         "facts": {"package": "bcrypt", "declared_version": "4.1.2"}},
    ]
    return {
        "estate": "bank-0001",
        "scope": "SYNTHETIC Zelnx Institution 0001 — synthetic bank sandbox",
        "assets": assets,
        "evidence": evidence,
        "relationships": [],
        "collectors": [{"plane": "INVENTORY", "status": "COMPLETE", "expected": 2,
                        "collected": 2, "reason": "bank inventory imported", "impact": None}],
        "coverage": [],
    }


def test_no_observation_leaves_the_hbom_empty_and_says_so(api):
    client, _ = api

    hbom = client.get("/api/v1/hbom")
    assert hbom.status_code == 200
    document = hbom.json()
    assert document["components"] == []
    assert document["metadata"]["component_count"] == 0
    assert document["metadata"]["sources"] == ["live hardware inventory (hardware_assets)"]
    assert any("empty, not fabricated" in note for note in document["metadata"]["notes"])

    bom = client.get("/api/v1/technology-bom").json()
    assert bom["components_by_layer"]["hbom"] == 0
    assert bom["components_by_layer"]["vendor"] == 0
    assert bom["scan"]["estate_observation"]["source"] is None


def test_observation_hardware_reaches_hbom_with_its_own_source(api):
    client, _ = api
    stored = client.post("/api/v1/ingestion/observations", json=_observation())
    assert stored.status_code == 201, stored.text

    document = client.get("/api/v1/hbom").json()
    assert document["metadata"]["component_count"] == 2
    assert document["metadata"]["hsm_count"] == 1
    assert "estate observation (HARDWARE/HSM assets)" in document["metadata"]["sources"]
    assert any("stored estate observation" in note for note in document["metadata"]["notes"])

    by_id = {component["asset_id"]: component for component in document["components"]}
    hsm = next(c for c in by_id.values() if c["device_type"] == "payment-hsm")
    assert hsm["evidence"]["source"] == "estate observation (HARDWARE/HSM assets)"
    # the evidence that established the device travels with it: declared, not fingerprinted
    assert hsm["evidence"]["evidence_ids"]
    assert hsm["security_modules"]["hsm"]["declared_only"] is True
    firewall = next(c for c in by_id.values() if c["device_type"] == "firewall")
    assert firewall["firmware"]["details"] == "1.0-LAB"
    assert firewall["manufacturer"] == "SYNTHETIC-FW"


def test_observation_hardware_and_vendors_reach_the_techbom_layers(api):
    client, _ = api
    assert client.post("/api/v1/ingestion/observations", json=_observation()).status_code == 201

    bom = client.get("/api/v1/technology-bom").json()
    assert bom["components_by_layer"]["hbom"] == 2
    assert bom["components_by_layer"]["vendor"] == 1
    observation = bom["scan"]["estate_observation"]
    assert observation["hardware"] == 2
    assert observation["vendors"] == 1
    assert "estate observation" in observation["source"]
    assert "not live-agent fingerprints" in observation["note"]
    # the hbom layer's own components are hardware, never re-typed as something else
    hardware = bom["layers"]["hbom"]["components"]
    assert {component["type"] for component in hardware} == {"hardware"}
    assert {component["device_type"] for component in hardware} == {"firewall", "payment-hsm"}


def test_a_second_identical_observation_does_not_double_count(api):
    client, _ = api
    assert client.post("/api/v1/ingestion/observations", json=_observation()).status_code == 201
    again = client.post("/api/v1/ingestion/observations", json=_observation())
    assert again.status_code == 200, again.text
    assert again.json()["state"] == "NO_CHANGE"

    document = client.get("/api/v1/hbom").json()
    assert document["metadata"]["component_count"] == 2
    bom = client.get("/api/v1/technology-bom").json()
    assert bom["components_by_layer"]["hbom"] == 2
    assert bom["components_by_layer"]["vendor"] == 1
