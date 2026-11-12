"""Shared asset detail API (docs/boms/01_PRODUCT_SPEC.md §7).

Real sqlite + real sessions. One canonical detail surface for every BOM
record: header record, asset information fields, the cross-BOM
relationships panel (linked / not established / unknown / primary record —
never conflated) and the nine detail tabs. The working rules are pinned as
behaviour: relationships exist only where stored evidence establishes
them; usage states are never equated; unobserved network crypto renders
`unknown`; hardware detail never emits firmware, TPM, HSM, key, secret or
credential material (serials masked).
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
from db.models.crypto_asset import CryptoAsset
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.runtime_finding import RuntimeFinding
from db.models.evidence_record import EvidenceRecord
from db.models.hardware_live import HardwareAsset
from db.models.network_scan_run import NetworkScanRun
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.models.system_dependency import SystemDependency
from db.models.vendor import SystemVendor, Vendor
from db.models.vendor_profile import VendorProfileRevision
from db.repositories.user_repository import UserRepository

NOW = datetime.now(timezone.utc)


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


def _seed(session) -> None:
    session.add(System(id="sys-pay", name="payments", owner="payments-team",
                       environment="Production", criticality="HIGH",
                       description="Payment API Server"))
    session.add(System(id="sys-lone", name="lone-app", owner="x", environment="UAT"))

    crypto = CryptoAsset(id="cr-linked", algorithm="AES", key_size=256, mode="GCM",
                         purpose="encrypt", file_path="/opt/pay/libcrypto.so",
                         line_number=10, confidence="HIGH", occurrence_count=1)
    session.add(crypto)
    session.add(SystemAsset(system_id="sys-pay", asset_id="cr-linked"))

    session.add(EvidenceRecord(
        id="ev-1", scan_id="scan-1", content_hash="b" * 64, chain_hash="c" * 64,
        chain_position=1, algorithm="AES", key_size=256, confidence="HIGH",
        file_path="/opt/pay/libcrypto.so", line_number=10, finding_data={}))
    session.add(CryptoAssetEvidence(asset_id="cr-linked", evidence_id="ev-1"))
    session.add(RuntimeFinding(
        scanner_id="rt-1", kind="session", hostname="payments-1", process_name="payd",
        algorithm="AES", key_size=256, observation_count=1,
        dedup_key="payments-1:payd:AES"))

    session.add(HardwareAsset(
        asset_id="hsm-1", manufacturer="Thales", model="payHSM", device_type="hsm",
        serial_reference="HSM-9876543210",
        firmware={"version": "7.4", "update_channel": "stable"},
        tpm={"ek_cert": "TPM-SECRET-MATERIAL"}, hsm={"key_store": "HSM-KEY-MATERIAL"},
        last_verified=NOW - timedelta(days=10), evidence_history=[{"state": "MEASURED"}]))

    session.add(Vendor(id="ven-thales", name="Thales", criticality="HIGH",
                       vendor_type="hardware", data_classifications=[]))
    session.add(SystemVendor(system_id="sys-pay", vendor_id="ven-thales"))
    session.add(VendorProfileRevision(
        vendor_id="ven-thales", revision=1, schema_version=1, status="DRAFT",
        profile_json={}, completeness_json={}, content_sha256="a" * 64,
        captured_at=NOW - timedelta(days=5)))

    session.add(SystemDependency(parent_id="sys-pay", child_id="sys-lone"))
    session.add(NetworkScanRun(
        target_kind="hosts", verdict="TLS_OK", probed=1, ok=1,
        result={"probes": [
            {"endpoint": "payments-1:443", "status": "TLS_OK",
             "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384",
             "alpn": "h2", "certificates": [{"subject": "CN=payments", "fingerprint_sha256": "d" * 64}]},
            {"endpoint": "dark-1:443", "status": "FAILED"},
        ]}))
    session.commit()


def test_header_record_and_cross_bom_panel_states(client, session):
    _seed(session)
    r = client.get("/api/v1/asset-detail/app:sys-pay")
    assert r.status_code == 200
    body = r.json()
    # header record fields (spec: Asset ID · Environment · Category · Owner · Source · Last observed)
    for field in ["asset_ref", "name", "status", "description", "asset_id",
                  "environment", "category", "owner", "source", "last_observed"]:
        assert field in body, field
    assert body["name"] == "payments"
    assert body["environment"] == "Production"
    assert body["description"] == "Payment API Server"

    states = {rel["bom"]: rel["state"] for rel in body["related"]}
    assert states["TechBOM"] == "PRIMARY_RECORD"
    assert states["SBOM"] == "LINKED"   # materializes into the SBOM layer
    assert states["CBOM"] == "LINKED"   # stored system_assets link
    assert states["VBOM"] == "LINKED"   # stored SystemVendor link
    assert states["HBOM"] == "NOT_ESTABLISHED"
    assert states["NBOM"] == "NOT_ESTABLISHED"
    for rel in body["related"]:
        assert rel["basis"]
    assert "SBOM linked" in body["chips"]
    assert "TechBOM primary record" in body["chips"]


def test_nine_tabs_exist_and_stay_honest(client, session):
    _seed(session)
    for tab in ["overview", "components", "cryptography", "hardware", "network",
                "vendors", "dependencies", "evidence", "history"]:
        r = client.get(f"/api/v1/asset-detail/app:sys-pay/{tab}")
        assert r.status_code == 200, tab
        body = r.json()
        assert body["tab"] == tab
        assert "rows" in body and "note" in body

    # cryptography: linked crypto renders capability vs operation apart
    r = client.get("/api/v1/asset-detail/app:sys-pay/cryptography")
    rows = r.json()["rows"]
    assert rows[0]["usage_state"] == "operation_observed"  # runtime observation named it
    assert "capability is never operation" in r.json()["note"] or "never equated" in r.json()["note"]

    # hardware for a software asset: not established, never invented
    r = client.get("/api/v1/asset-detail/app:sys-pay/hardware")
    assert r.json()["rows"] == []
    assert "not established" in r.json()["note"]


def test_network_unknown_and_hardware_secrets_never_emit(client, session):
    _seed(session)
    # observed endpoint: negotiated facts
    r = client.get("/api/v1/asset-detail/net:payments-1:443/network")
    row = r.json()["rows"][0]
    assert row["tls_version"] == "TLSv1.3"
    assert row["observed"] is True
    # unobserved endpoint: literal unknown — a port scan proves nothing
    r = client.get("/api/v1/asset-detail/net:dark-1:443/network")
    row = r.json()["rows"][0]
    assert row["tls_version"] == "unknown"
    assert row["cipher_suite"] == "unknown"
    assert "port scan alone" in row["basis"]

    # hardware detail: masked serial, no secret blobs anywhere in the body
    r = client.get("/api/v1/asset-detail/hw:hsm-1/hardware")
    body_text = r.text
    row = r.json()["rows"][0]
    assert row["serial"] == "••••3210"
    assert row["firmware_version"] == "7.4"
    for leak in ["TPM-SECRET-MATERIAL", "HSM-KEY-MATERIAL", "update_channel",
                 "9876543210", "ek_cert", "key_store"]:
        assert leak not in body_text, leak
    # the hardware tab is its own primary record in the panel
    r = client.get("/api/v1/asset-detail/hw:hsm-1")
    states = {rel["bom"]: rel["state"] for rel in r.json()["related"]}
    assert states["HBOM"] == "LINKED"
    assert states["TechBOM"] == "PRIMARY_RECORD"
    assert states["SBOM"] == "NOT_ESTABLISHED"


def test_vendor_evidence_and_404(client, session):
    _seed(session)
    # vendor detail: verified bank assets only, never a public association
    r = client.get("/api/v1/asset-detail/vendor:ven-thales/vendors")
    row = r.json()["rows"][0]
    assert row["supplies_system"] == "app:sys-pay"
    assert "not a public association" in row["basis"]
    # vendor evidence: profile revision with freshness
    r = client.get("/api/v1/asset-detail/vendor:ven-thales/evidence")
    assert r.json()["rows"][0]["freshness"] in ("CURRENT", "STALE", "EXPIRED")
    # crypto evidence: the linked evidence record with its digest
    r = client.get("/api/v1/asset-detail/crypto:cr-linked/evidence")
    row = r.json()["rows"][0]
    assert row["content_hash"] == "b" * 64
    assert row["freshness"] == "CURRENT"

    r = client.get("/api/v1/asset-detail/app:nope")
    assert r.status_code == 404
    r = client.get("/api/v1/asset-detail/bogus:1")
    assert r.status_code == 404
