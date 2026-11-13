"""VBOM workspace API (docs/boms/01_PRODUCT_SPEC.md §5).

Real sqlite + real sessions. The workspace answers which suppliers provide
technology and what backs each relationship — and the working rule is
pinned as behaviour: a bank does not use a vendor product just because the
vendor is publicly associated with the bank. CONFIRMED, IMPORTED,
PUBLICLY_REPORTED and UNKNOWN stay separate states; bank-asset counts
include verified links only; a vendor PQC claim is REPORTED until the bank
verifies it. Empty estates get honest empty states.
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
from db.models.system import System
from db.models.vendor import SystemVendor, Vendor
from db.models.vendor_crypto import VendorCryptoInventory
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


def _seed_estate(session):
    system = System(name="payments-core")
    session.add(system)
    session.flush()
    confirmed = Vendor(name="Thales", vendor_type="HSM", criticality="CRITICAL")
    reported = Vendor(name="PressVendor", vendor_type="software",
                      extra_json={"association_state": "PUBLICLY_REPORTED",
                                  "source": "press report naming the bank"})
    imported = Vendor(name="ImportVendor", vendor_type="cloud")
    unknown = Vendor(name="QuietVendor", vendor_type="service")
    for v in (confirmed, reported, imported, unknown):
        session.add(v)
    session.flush()
    session.add(SystemVendor(system_id=system.id, vendor_id=confirmed.id,
                             dependency_type="critical"))
    session.add(VendorProfileRevision(
        vendor_id=confirmed.id, revision=1, schema_version="cryptoscan.vendor-profile/1",
        status="APPROVED", source="operator",
        profile_json={
            "identity": {"legal_name": "Thales SA", "vendor_id": confirmed.id},
            "components": [{"component_id": "c1", "name": "CryptoServer", "version": "4.2",
                            "component_type": "hardware", "support_level": "GA",
                            "eol_date": None, "replacement_product": None}],
            "contracts": [{"contract_id": "ct-1", "contract_type": "support"}],
            "evidence": [{"evidence_id": "ev-1", "evidence_type": "SOC2",
                          "evidence_reference": "soc2-2026.pdf", "status": "accepted",
                          "source_system": "grc", "collection_method": "import",
                          "captured_at": (NOW - timedelta(days=10)).isoformat(),
                          "expires_at": None}],
        },
        completeness_json={}, content_sha256="a" * 64,
        captured_at=NOW - timedelta(days=10), created_by="viewer"))
    session.add(VendorProfileRevision(
        vendor_id=imported.id, revision=1, schema_version="cryptoscan.vendor-profile/1",
        status="DRAFT", source="imported",
        profile_json={"identity": {"legal_name": "ImportVendor Inc", "vendor_id": imported.id}},
        completeness_json={}, content_sha256="b" * 64,
        captured_at=NOW - timedelta(days=5), created_by="importer"))
    # Thales published a PQC claim the bank verified; ImportVendor only published one
    session.add(VendorCryptoInventory(
        vendor_id=confirmed.id, algorithm="ML-KEM", key_size=768, pqc_ready=True,
        discovery_method="vendor-doc", confidence="HIGH",
        source_document="vendor-pqc-roadmap-2026.pdf",
        discovered_at=NOW - timedelta(days=30), verified_at=NOW - timedelta(days=3)))
    session.add(VendorCryptoInventory(
        vendor_id=imported.id, algorithm="RSA", key_size=2048, pqc_ready=True,
        discovery_method="vendor-doc", confidence="MEDIUM",
        source_document="imported-roadmap.pdf", discovered_at=NOW - timedelta(days=20)))
    session.commit()
    return system.id


def test_empty_estate_reports_honest_empty_state(client):
    body = client.get("/api/v1/vbom/workspace/overview").json()
    assert body["state"] == "NO_RECORDS"
    assert body["vendors"] == 0
    inv = client.get("/api/v1/vbom/workspace/vendors").json()
    assert inv["rows"] == []


def test_association_states_are_never_collapsed(client, session):
    _seed_estate(session)
    rows = client.get("/api/v1/vbom/workspace/vendors").json()["rows"]
    by_vendor = {}
    for r in rows:
        by_vendor.setdefault(r["vendor"], r)
    # the linked vendor is CONFIRMED and counts verified bank assets
    assert by_vendor["Thales"]["association_state"] == "CONFIRMED"
    assert by_vendor["Thales"]["bank_assets"] == 1
    # the publicly associated vendor is NOT bank use: no link, no assets, not CONFIRMED
    reported = by_vendor["PressVendor"]
    assert reported["association_state"] == "PUBLICLY_REPORTED"
    assert reported["bank_assets"] == 0
    assert reported["association_state"] != "CONFIRMED"
    # the imported record is IMPORTED, the bare one UNKNOWN with the rule's basis
    assert by_vendor["ImportVendor"]["association_state"] == "IMPORTED"
    quiet = by_vendor["QuietVendor"]
    assert quiet["association_state"] == "UNKNOWN"
    assert "public association never implies bank use" in quiet["association_basis"]
    rels = client.get("/api/v1/vbom/workspace/relationships").json()["rows"]
    press = next(r for r in rels if r["vendor"] == "PressVendor")
    assert press["system_id"] is None
    assert press["association_state"] == "PUBLICLY_REPORTED"


def test_pqc_claim_reported_until_verified(client, session):
    _seed_estate(session)
    rows = client.get("/api/v1/vbom/workspace/pqc").json()["rows"]
    by_vendor = {r["vendor"]: r for r in rows}
    assert by_vendor["Thales"]["pqc_roadmap"] == "CONFIRMED"
    assert by_vendor["ImportVendor"]["pqc_roadmap"] == "REPORTED"
    assert "no bank verification" in by_vendor["ImportVendor"]["basis"]
    assert by_vendor["QuietVendor"]["pqc_roadmap"] == "UNKNOWN"
    assert by_vendor["PressVendor"]["pqc_roadmap"] == "UNKNOWN"


def test_spec_columns_detail_and_unknown_vendor(client, session):
    _seed_estate(session)
    rows = client.get("/api/v1/vbom/workspace/vendors").json()["rows"]
    thales = next(r for r in rows if r["vendor"] == "Thales")
    for column in ("vendor", "product", "version", "category", "bank_assets",
                   "support_lifecycle", "crypto_dependency", "pqc_roadmap",
                   "evidence", "last_reviewed"):
        assert column in thales, column
    assert thales["product"] == "CryptoServer"
    assert thales["support_lifecycle"] == "SUPPORTED"
    # detail: contract metadata, evidence, approval history; cross-BOM links honest
    detail = client.get(f"/api/v1/vbom/workspace/vendors/{thales['vendor_id']}").json()
    assert detail["vendor"]["legal_name"] == "Thales SA"
    assert detail["contracts"][0]["contract_id"] == "ct-1"
    assert detail["evidence"][0]["evidence_id"] == "ev-1"
    assert detail["approval_history"][0]["revision"] == 1
    assert detail["links"]["_note"]
    assert client.get("/api/v1/vbom/workspace/vendors/no-such").status_code == 404
