"""HBOM workspace API (docs/boms/01_PRODUCT_SPEC.md §3).

Real sqlite + real sessions. The workspace answers what hardware exists and
what backs each record — and the working rules are pinned as behaviour: the
HBOM never exposes HSM key material, private keys, secrets or device
credentials (agent metadata blobs are projected through a safe-key
allowlist and serial references are masked); a hardware capability is never
drawn as use; an unrecorded lifecycle is UNKNOWN, never assumed SUPPORTED;
empty estates get honest empty states.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from api.main import create_app
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, SessionLocal, configure_session
from db.models.hardware_live import HardwareAsset, HardwareAgentRow, HardwareEventRow
from db.models.hbom_snapshot import HbomSnapshot
from db.repositories.user_repository import UserRepository

NOW = datetime.now(timezone.utc)

HSM_SECRET = "PKCS11-SLOT-KEY-MATERIAL-MUST-NEVER-LEAVE"
TPM_SECRET = "EK-PRIVATE-KEY-MUST-NEVER-LEAVE"
CRED_SECRET = "device-password-MUST-NEVER-LEAVE"
FULL_SERIAL = "SER-99887766554433221100"


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    configure_session(engine)
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def client(session):
    repo = UserRepository(session)
    repo.create_user("viewer", hash_password("x"), ["viewer"])
    session.commit()
    app = create_app()
    c = TestClient(app)
    token = SessionManager().create_session("viewer", roles=["viewer"])
    repo.create_session(token, "viewer", NOW + timedelta(hours=1), ip="127.0.0.1")
    session.commit()
    c.cookies.set("cryptoscan_session", token)
    return c


def _seed_estate(session):
    session.add(HardwareAsset(
        asset_id="hw-hsm-1", manufacturer="Utimaco", model="CryptoServer",
        device_type="hsm", serial_reference=FULL_SERIAL,
        firmware={"version": "4.2.1", "vendor": "Utimaco", "end_of_life": False},
        hsm={"vendor": "Utimaco", "model": "CryptoServer", "fips_level": 3,
             "slot_keys": HSM_SECRET, "password": CRED_SECRET},
        tpm={"version": "2.0", "present": True, "private": TPM_SECRET},
        capabilities={"location": "dc-north", "secure_boot": True},
        crypto_capabilities={"algorithms": ["RSA-4096", "AES-256"], "acceleration": True},
        agent_id="agent-dc-1", last_seen=NOW - timedelta(days=1),
        last_firmware_check=NOW - timedelta(days=10),
        current_fingerprint="a" * 64))
    session.add(HardwareAsset(
        asset_id="hw-server-1", manufacturer="Dell", model="R760",
        device_type="server", firmware=None,
        capabilities={"location": "dc-north"},
        last_seen=NOW - timedelta(days=200)))
    session.add(HardwareAsset(
        asset_id="hw-tpm-1", manufacturer="Infineon", model="SLB 9670",
        device_type="tpm", tpm={"version": "2.0", "present": True, "secure_boot": True}))
    session.add(HardwareAgentRow(agent_id="agent-dc-1", last_heartbeat=NOW))
    session.add(HardwareEventRow(
        event_type="firmware_change", asset_id="hw-hsm-1", agent_id="agent-dc-1",
        source="agent", observed_at=NOW - timedelta(days=5), change_class="firmware",
        evidence_id="ev-1"))
    session.add(HbomSnapshot(
        environment="prod", content_hash="b" * 64, format="json", generator="api",
        payload={"components": []}, component_count=3, created_by="viewer",
        snapshotted_at=NOW))
    session.commit()


def test_empty_estate_reports_honest_empty_state(client):
    body = client.get("/api/v1/hbom/workspace/overview").json()
    assert body["state"] == "NO_RECORDS"
    assert body["assets"] == 0
    inv = client.get("/api/v1/hbom/workspace/assets").json()
    assert inv["rows"] == []


def test_spec_columns_masked_serial_and_never_key_material(client, session):
    _seed_estate(session)
    endpoints = ["/api/v1/hbom/workspace/overview", "/api/v1/hbom/workspace/assets",
                 "/api/v1/hbom/workspace/assets/hw-hsm-1", "/api/v1/hbom/workspace/hsm",
                 "/api/v1/hbom/workspace/tpm", "/api/v1/hbom/workspace/crypto",
                 "/api/v1/hbom/workspace/firmware", "/api/v1/hbom/workspace/evidence"]
    texts = ""
    for ep in endpoints:
        r = client.get(ep)
        assert r.status_code == 200, ep
        texts += r.text
    # the hard rule: no key material, private keys, secrets or credentials
    for secret in (HSM_SECRET, TPM_SECRET, CRED_SECRET, FULL_SERIAL):
        assert secret not in texts, secret
    rows = client.get("/api/v1/hbom/workspace/assets").json()["rows"]
    by_id = {r["asset_id"]: r for r in rows}
    hsm = by_id["hw-hsm-1"]
    for column in ("asset_id", "manufacturer", "model", "serial_reference", "firmware",
                   "category", "location", "crypto_capabilities", "lifecycle", "evidence"):
        assert column in hsm, column
    # serial masked: tail only
    assert hsm["serial_reference"] == "••••" + FULL_SERIAL[-4:]
    # safe metadata from the same blob still reads
    assert hsm["category"] == "HSM"
    assert hsm["location"] == "dc-north"
    detail = client.get("/api/v1/hbom/workspace/assets/hw-hsm-1").json()
    assert detail["hsm"].get("fips_level") == 3
    assert "password" not in detail["hsm"]
    assert "slot_keys" not in detail["hsm"]


def test_capabilities_are_never_drawn_as_use_and_lifecycle_is_honest(client, session):
    _seed_estate(session)
    caps = client.get("/api/v1/hbom/workspace/crypto").json()["rows"]
    for row in caps:
        assert row["usage_state"] == "capability_detected"
        assert "never drawn as use" in row["basis"]
    life = client.get("/api/v1/hbom/workspace/lifecycle").json()["rows"]
    by_id = {r["asset_id"]: r for r in life}
    # firmware recorded end_of_life=False → supported, with its basis
    assert by_id["hw-hsm-1"]["lifecycle"] == "SUPPORTED"
    assert "firmware record" in by_id["hw-hsm-1"]["lifecycle_basis"]
    # no firmware record → UNKNOWN, never assumed supported
    assert by_id["hw-server-1"]["lifecycle"] == "UNKNOWN"
    assert by_id["hw-tpm-1"]["lifecycle"] == "UNKNOWN"


def test_evidence_coverage_and_unknown_asset(client, session):
    _seed_estate(session)
    body = client.get("/api/v1/hbom/workspace/evidence").json()
    assert body["total"] == 1
    assert body["collection_coverage"]["assets"] == 3
    assert body["collection_coverage"]["assets_with_fingerprint"] == 1
    assert body["collection_coverage"]["agents_reporting"] == 1
    rows = body["rows"]
    assert rows[0]["event_type"] == "firmware_change"
    assert rows[0]["freshness"] == "CURRENT"
    assert client.get("/api/v1/hbom/workspace/assets/no-such-device").status_code == 404
