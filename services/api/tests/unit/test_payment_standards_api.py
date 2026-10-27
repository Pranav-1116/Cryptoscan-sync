"""/api/v1/payment-crypto — ISO 9564, ISO 8583 and EMV standards analysis.

These endpoints read declarations, not payment data. The last test asserts
that: a caller must not be able to push a PIN block or key material through
them and get it analysed (or echoed back).
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

BASE = "/api/v1/payment-crypto"
AUTH = {"Authorization": "Bearer test-session-token"}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "auditor-1"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    with TestClient(app) as c:
        yield c
    session.close()
    engine.dispose()


def test_pin_block_estate_reports_the_tdes_backlog(client):
    r = client.post(f"{BASE}/pin-blocks/analyse", headers=AUTH, json={"declarations": [
        {"system": "atm-switch", "format": "ISO-0"},
        {"system": "new-rail", "format": "ISO-4", "key_algorithm": "AES"},
        {"system": "legacy", "format": "IBM3624"},
    ]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 3
    assert body["aes_ready"] == 1
    assert body["tdes_bound"] == 2
    assert body["non_compliant"] == 1


def test_iso8583_link_without_a_mac_is_reported(client):
    r = client.post(f"{BASE}/iso8583/analyse", headers=AUTH, json={"links": [
        {"link": "legacy-atm", "fields": [2, 52]},
        {"link": "visa-base1", "fields": [2, 52, 64], "mac_algorithm": "AES-CMAC",
         "pin_block_format": "ISO-4"},
    ]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pin_links"] == 2
    assert body["unmaced_links"] == 1
    legacy = next(x for x in body["results"] if x["link"] == "legacy-atm")
    assert any(i["code"] == "PIN_WITHOUT_MAC" for i in legacy["issues"])


def test_emv_portfolio_flags_undiversified_session_keys(client):
    r = client.post(f"{BASE}/emv/analyse", headers=AUTH, json={"applications": [
        {"application": "VISA-DEBIT", "cvn": "10", "key_algorithm": "TDES", "key_bits": 112},
        {"application": "VISA-CREDIT", "cvn": "18", "key_algorithm": "AES", "key_bits": 256},
    ]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["undiversified_session_keys"] == 1
    assert body["aes_applications"] == 1
    assert body["quantum_vulnerable"] == 1


@pytest.mark.parametrize("path,key", [
    ("pin-blocks/analyse", "declarations"),
    ("iso8583/analyse", "links"),
    ("emv/analyse", "applications"),
])
def test_empty_input_is_rejected(client, path, key):
    r = client.post(f"{BASE}/{path}", headers=AUTH, json={key: []})
    assert r.status_code == 400


def test_pin_block_data_and_key_material_are_refused_not_analysed(client):
    """The endpoints take declarations; real payment secrets must bounce."""
    pin_block = "A1B2C3D4E5F60718"
    imk = "0123456789ABCDEF0123456789ABCDEF"

    r = client.post(f"{BASE}/pin-blocks/analyse", headers=AUTH,
                    json={"declarations": [{"system": "s", "format": pin_block}]})
    assert r.status_code == 200
    row = r.json()["results"][0]
    assert row["iso_format"] is None
    assert any("refused" in e for e in row["errors"])

    r = client.post(f"{BASE}/emv/analyse", headers=AUTH,
                    json={"applications": [{"application": "a", "cvn": imk}]})
    assert r.status_code == 200
    row = r.json()["results"][0]
    assert row["cipher"] is None
    assert any("refused" in e for e in row["errors"])
