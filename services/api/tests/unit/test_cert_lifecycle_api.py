"""Certificate lifecycle API — issue / renew / revoke / renewal-queue.

Real sqlite + real sessions (same pattern as test_api_keys.py): the X.509
objects are produced by the `cryptography` lib and validated on the way out.
Private keys appear in responses exactly once and are never stored — the
inventory row only ever holds metadata.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from api.main import create_app
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, SessionLocal, configure_session
from db.repositories.certificate_repository import CertificateRepository
from db.repositories.user_repository import UserRepository

from cryptography import x509


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


def _mint_session(db, username: str, roles: list[str]) -> str:
    manager = SessionManager()
    token = manager.create_session(username, roles=roles)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    UserRepository(db).create_session(token, username, expires, ip="127.0.0.1")
    db.commit()
    return token


@pytest.fixture()
def ciso_client(session):
    repo = UserRepository(session)
    repo.create_user("ciso", hash_password("x"), ["ciso"])
    session.commit()
    app = create_app()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", _mint_session(session, "ciso", ["ciso"]))
    return client


@pytest.fixture()
def viewer_client(session):
    repo = UserRepository(session)
    repo.create_user("viewer", hash_password("x"), ["viewer"])
    session.commit()
    app = create_app()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", _mint_session(session, "viewer", ["viewer"]))
    return client


# ------------------------------------------------------------- issuance

def test_issue_self_signed_via_api(ciso_client, session):
    r = ciso_client.post(
        "/api/v1/certificates/lifecycle/issue",
        json={
            "subject": {"CN": "api.payments.internal"},
            "san": ["api.payments.internal"],
            "validity_days": 90,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert body["private_key_pem"].startswith("-----BEGIN PRIVATE KEY-----")
    assert len(body["fingerprint_sha256"]) == 64
    cert = x509.load_pem_x509_certificate(body["certificate_pem"].encode())
    assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "api.payments.internal"
    assert cert.subject == cert.issuer  # self-signed

    # inventory row exists and holds metadata only — no key material anywhere
    row = CertificateRepository(session).get_by_fingerprint(body["fingerprint_sha256"])
    assert row is not None
    assert row.extra["certificate_pem"] == body["certificate_pem"]
    assert body["private_key_pem"] not in str(row.extra)


def test_renewal_queue_via_api(ciso_client, session):
    _repo = CertificateRepository(session)
    r = ciso_client.post(
        "/api/v1/certificates/lifecycle/issue",
        json={"subject": {"CN": "soon.example"}, "validity_days": 5},
    )
    fp = r.json()["fingerprint_sha256"]
    q = ciso_client.get("/api/v1/certificates/lifecycle/renewal-queue?lead_days=30")
    assert q.status_code == 200
    due = q.json()["due"]
    assert any(d["fingerprint_sha256"] == fp for d in due)
    # the expired/expiring cert itself shows as due
    soon = next(d for d in due if d["fingerprint_sha256"] == fp)
    assert soon["subject"] == "soon.example"


def test_renew_via_api(ciso_client, session):
    r = ciso_client.post(
        "/api/v1/certificates/lifecycle/issue",
        json={
            "subject": {"CN": "renew.me"},
            "san": ["renew.me"],
            "validity_days": 20,
        },
    )
    old = r.json()
    repo = CertificateRepository(session)
    repo.update_renewal(old["fingerprint_sha256"], "PLANNED", ticket="CR-999")
    session.commit()

    r2 = ciso_client.post(
        f"/api/v1/certificates/{old['fingerprint_sha256']}/renew",
        json={"rotate_key": True},
    )
    assert r2.status_code == 200, r2.text
    new = r2.json()
    assert new["fingerprint_sha256"] != old["fingerprint_sha256"]
    assert new["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")
    cert = x509.load_pem_x509_certificate(new["certificate_pem"].encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "renew.me" in [s.value for s in san]
    # renewal workflow marked DONE with a note referencing the old cert
    row = repo.get_by_fingerprint(new["fingerprint_sha256"])
    assert row.renewal_status == "DONE"
    assert old["fingerprint_sha256"][:12] in (row.renewal_note or "")


def test_revoke_via_api_without_ca_is_manual(ciso_client, session):
    r = ciso_client.post(
        "/api/v1/certificates/lifecycle/issue",
        json={"subject": {"CN": "bye.example"}, "validity_days": 100},
    )
    fp = r.json()["fingerprint_sha256"]
    r2 = ciso_client.post(f"/api/v1/certificates/{fp}/revoke", json={"reason": "decommission"})
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["revocation_status"] == "REVOKED"
    assert body["revocation_method"] == "MANUAL"  # no CA key configured in tests
    row = CertificateRepository(session).get_by_fingerprint(fp)
    assert row.revocation_status == "REVOKED"
    assert row.extra["revocation"]["reason"] == "decommission"
    # revoked certs drop out of the renewal queue
    q = ciso_client.get("/api/v1/certificates/lifecycle/renewal-queue?lead_days=200").json()
    assert fp not in [d["fingerprint_sha256"] for d in q["due"]]


def test_rbac_gates_lifecycle_management(viewer_client, session):
    # viewers cannot issue / renew / revoke
    r = viewer_client.post(
        "/api/v1/certificates/lifecycle/issue",
        json={"subject": {"CN": "nope.example"}},
    )
    assert r.status_code == 403
    r2 = viewer_client.post("/api/v1/certificates/whatever/renew", json={})
    assert r2.status_code == 403
    r3 = viewer_client.post("/api/v1/certificates/whatever/revoke", json={})
    assert r3.status_code == 403
    # but the read-only queue is fine
    q = viewer_client.get("/api/v1/certificates/lifecycle/renewal-queue")
    assert q.status_code == 200


def test_ca_issuance_requires_configured_ca(ciso_client, session, monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_CA_CERT", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_CA_KEY", raising=False)
    r = ciso_client.post(
        "/api/v1/certificates/lifecycle/issue",
        json={"subject": {"CN": "ca-signed.example"}, "signed_by_ca": True},
    )
    assert r.status_code == 503  # refuse rather than guess
    assert "CRYPTOSCAN_CA_CERT" in r.json()["detail"]
