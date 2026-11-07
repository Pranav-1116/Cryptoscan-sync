"""Global search: vendor, certificate and evidence term search (gap analysis
§A: "Global asset, vendor, certificate and evidence search").

Each store is searched SERVER-side across the whole store with the term —
never a page-local filter of loaded rows.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def session(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 — registers every model on the metadata
    from db.models.base import Base
    from db.models.certificate import Certificate
    from db.models.evidence_record import EvidenceRecord
    from db.models.scan import Scan
    from db.models.tenant import TenantMembership
    from db.models.user import User
    from db.models.vendor import SystemVendor, Vendor
    from db.models.vendor_profile import VendorProfileRevision

    engine = create_engine(f"sqlite:///{tmp_path / 'search.db'}")
    Base.metadata.create_all(engine, tables=[
        Scan.__table__, EvidenceRecord.__table__, Certificate.__table__,
        Vendor.__table__, VendorProfileRevision.__table__,
        TenantMembership.__table__, User.__table__, SystemVendor.__table__,
    ])
    factory = sessionmaker(bind=engine)
    db = factory()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def _evidence(db, *, evidence_id: str, algorithm: str, file_path: str):
    from db.models.evidence_record import EvidenceRecord
    db.add(EvidenceRecord(
        id=evidence_id, scan_id="scan-1", algorithm=algorithm,
        key_size=None, mode=None, padding=None, purpose=None,
        confidence="HIGH", is_hardcoded_key=False,
        file_path=file_path, line_number=1, class_name=None, method_name=None,
        content_hash="ab" * 32, chain_hash="cd" * 32, chain_position=0,
        previous_hash=None, finding_data={"snippet": file_path},
    ))


def _scan(db):
    from datetime import datetime, timezone

    from db.models.scan import Scan
    db.add(Scan(id="scan-1", status="COMPLETED", target_location="repo",
                scan_start=datetime.now(timezone.utc)))


# ------------------------------------------------------------- evidence q
@pytest.fixture()
def findings_api(session):
    from api import dependencies
    from api.routers import findings
    from db.repositories.evidence_repository import EvidenceRepository

    _scan(session)
    _evidence(session, evidence_id="ev-rsa", algorithm="RSA-2048",
              file_path="src/keys/Payments.java")
    _evidence(session, evidence_id="ev-aes", algorithm="AES-256",
              file_path="src/crypto/Storage.kt")
    session.commit()

    app = FastAPI()
    app.include_router(findings.router, prefix="/api/v1")
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_current_user] = lambda: "auditor"
    app.dependency_overrides[dependencies.get_evidence_repository] = (
        lambda: EvidenceRepository(session))
    return TestClient(app)


def test_evidence_term_search_hits_identity_fields_and_counts(findings_api):
    hit = findings_api.get("/api/v1/findings", params={"q": "payments"})
    assert hit.status_code == 200
    body = hit.json()
    assert body["total_count"] == 1
    assert [row["evidence_id"] for row in body["findings"]] == ["ev-rsa"]

    by_algo = findings_api.get("/api/v1/findings", params={"q": "AES"}).json()
    assert by_algo["total_count"] == 1
    assert by_algo["findings"][0]["evidence_id"] == "ev-aes"

    by_hash = findings_api.get(
        "/api/v1/findings", params={"q": "ab" * 32}).json()
    assert by_hash["total_count"] == 2, "content hash is an identity field"


def test_evidence_term_search_with_no_match_is_an_empty_result(findings_api):
    miss = findings_api.get("/api/v1/findings", params={"q": "no-such-term"}).json()
    assert miss["total_count"] == 0
    assert miss["findings"] == []


# ----------------------------------------------------------- certificates q
@pytest.fixture()
def certs_api(session):
    from api import dependencies
    from api.routers import network

    session.add(_cert("aa" * 32, "CN=payments.acme.test", "CN=ACME Internal CA"))
    session.add(_cert("bb" * 32, "CN=storage.acme.test", "CN=ACME Internal CA"))
    session.commit()

    app = FastAPI()
    app.include_router(network.router, prefix="/api/v1")
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_current_user] = lambda: "auditor"
    return TestClient(app)


def _cert(fingerprint, subject, issuer):
    from db.models.certificate import Certificate
    return Certificate(fingerprint_sha256=fingerprint, subject=subject,
                       issuer=issuer, serial_number="01", is_self_signed=False)


def test_certificate_term_search_hits_subject_issuer_and_fingerprint(certs_api):
    by_subject = certs_api.get("/api/v1/certificates",
                               params={"q": "payments"}).json()
    assert by_subject["total_count"] == 1
    assert by_subject["certificates"][0]["subject"] == "CN=payments.acme.test"

    by_issuer = certs_api.get("/api/v1/certificates",
                              params={"q": "internal ca"}).json()
    assert by_issuer["total_count"] == 2

    by_fp = certs_api.get("/api/v1/certificates",
                          params={"q": "aa" * 32}).json()
    assert by_fp["total_count"] == 1

    miss = certs_api.get("/api/v1/certificates", params={"q": "no-such"}).json()
    assert miss["total_count"] == 0
    assert miss["certificates"] == []


# ---------------------------------------------------------------- vendors q
@pytest.fixture()
def vendors_api(session):
    from api import dependencies
    from api.routers import business
    from db.models.vendor import Vendor

    session.add(Vendor(name="ACME HSM", criticality="HIGH",
                       vendor_type="hardware"))
    session.add(Vendor(name="Globex Crypto Cloud", criticality="MEDIUM",
                       vendor_type="cloud"))
    session.commit()

    app = FastAPI()
    app.include_router(business.router, prefix="/api/v1")
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_current_user] = lambda: "auditor"
    return TestClient(app)


def test_vendor_term_search_hits_name_type_and_criticality(vendors_api):
    by_name = vendors_api.get("/api/v1/vendors", params={"q": "acme"}).json()
    assert [row["name"] for row in by_name["vendors"]] == ["ACME HSM"]

    by_type = vendors_api.get("/api/v1/vendors", params={"q": "cloud"}).json()
    assert [row["name"] for row in by_type["vendors"]] == ["Globex Crypto Cloud"]

    by_crit = vendors_api.get("/api/v1/vendors", params={"q": "HIGH"}).json()
    assert [row["name"] for row in by_crit["vendors"]] == ["ACME HSM"]

    miss = vendors_api.get("/api/v1/vendors", params={"q": "no-such"}).json()
    assert miss["vendors"] == []
