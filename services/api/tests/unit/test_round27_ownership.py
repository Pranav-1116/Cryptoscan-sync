"""Round 27 (audit 55 P0#3-5): direct ownership on assets, certs, vendors.

Ownership used to live only on the System row. These tests exercise the
three assignment endpoints (auditor-gated, audited, reason required) and
the inventory/listing surfaces that now carry the fields.
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
from db.repositories.certificate_repository import CertificateRepository
from db.repositories.user_repository import UserRepository

SECRET = "r27-ownership-secret-" + "z" * 20


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
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
def admin_client(session):
    repo = UserRepository(session)
    repo.create_user("root", hash_password("x"), ["admin"])
    session.commit()
    app = create_app()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", _mint_session(session, "root", ["admin"]))
    return client


@pytest.fixture()
def viewer_client(session):
    repo = UserRepository(session)
    repo.create_user("looker", hash_password("x"), ["viewer"])
    session.commit()
    app = create_app()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", _mint_session(session, "looker", ["viewer"]))
    return client


def _seed_asset(session) -> str:
    from db.models.crypto_asset import CryptoAsset

    asset = CryptoAsset(algorithm="RSA", purpose="ENCRYPTION",
                        file_path="k.java", line_number=1)
    session.add(asset)
    session.commit()
    return asset.id


def _seed_certificate(session) -> str:
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "r27.example")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(der).hexdigest()
    repo = CertificateRepository(session)
    repo.upsert({
        "fingerprint_sha256": fingerprint,
        "subject": "CN=r27.example",
        "issuer": "CN=r27.example",
        "public_key_algorithm": "ECDSA",
        "public_key_size": 256,
        "not_before": now,
        "not_after": now + timedelta(days=30),
        "is_self_signed": True,
    })
    session.commit()
    return fingerprint


def _seed_vendor(session) -> str:
    from db.models.vendor import Vendor

    vendor = Vendor(name="r27-vendor", criticality="HIGH",
                    primary_contact="sales@vendor.example")
    session.add(vendor)
    session.commit()
    return vendor.id


# ------------------------------------------------------------------ #
# Crypto asset ownership (P0#3)
# ------------------------------------------------------------------ #

def test_asset_ownership_assignment_and_inventory_surface(session, admin_client):
    asset_id = _seed_asset(session)
    r = admin_client.post(f"/api/v1/inventory/assets/{asset_id}/ownership",
                          json={"owner": "payments-team",
                                "technical_owner": "alice",
                                "security_owner": "bob",
                                "reason": "r27: direct accountability"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["owner"] == "payments-team"
    assert body["technical_owner"] == "alice"
    assert body["security_owner"] == "bob"

    # the unified inventory now carries the fields on crypto rows
    inv = admin_client.get("/api/v1/inventory/assets")
    assert inv.status_code == 200
    row = next(a for a in inv.json()["assets"] if a["id"] == f"crypto:{asset_id}")
    assert row["owner"] == "payments-team"
    assert row["technical_owner"] == "alice"
    assert row["security_owner"] == "bob"

    # partial update: only the supplied field changes, nothing cleared
    r2 = admin_client.post(f"/api/v1/inventory/assets/{asset_id}/ownership",
                           json={"technical_owner": "carol",
                                 "reason": "r27: tech owner changed"})
    assert r2.status_code == 200
    assert r2.json()["technical_owner"] == "carol"
    assert r2.json()["owner"] == "payments-team"


def test_asset_ownership_requires_reason_and_known_asset(session, admin_client):
    asset_id = _seed_asset(session)
    r = admin_client.post(f"/api/v1/inventory/assets/{asset_id}/ownership",
                          json={"owner": "x"})
    assert r.status_code == 422  # reason is mandatory

    r404 = admin_client.post("/api/v1/inventory/assets/no-such-asset/ownership",
                             json={"owner": "x", "reason": "r"})
    assert r404.status_code == 404


def test_asset_ownership_denied_to_viewer(session, viewer_client):
    asset_id = _seed_asset(session)
    r = viewer_client.post(f"/api/v1/inventory/assets/{asset_id}/ownership",
                           json={"owner": "x", "reason": "r"})
    assert r.status_code == 403


# ------------------------------------------------------------------ #
# Certificate ownership (P0#4)
# ------------------------------------------------------------------ #

def test_certificate_ownership_assignment(session, admin_client):
    fingerprint = _seed_certificate(session)
    r = admin_client.post(f"/api/v1/certificates/{fingerprint}/ownership",
                          json={"owner": "pki-team",
                                "technical_contact": "dave@corp",
                                "reason": "r27: expiry notifications"})
    assert r.status_code == 200, r.text
    assert r.json()["owner"] == "pki-team"
    assert r.json()["technical_contact"] == "dave@corp"

    # the certificate listing (to_dict) carries the fields
    listing = admin_client.get("/api/v1/certificates")
    assert listing.status_code == 200
    row = next(c for c in listing.json()["certificates"]
               if c["fingerprint_sha256"] == fingerprint)
    assert row["owner"] == "pki-team"
    assert row["technical_contact"] == "dave@corp"

    r404 = admin_client.post("/api/v1/certificates/" + "0" * 64 + "/ownership",
                             json={"owner": "x", "reason": "r"})
    assert r404.status_code == 404


def test_certificate_ownership_denied_to_viewer(session, viewer_client):
    fingerprint = _seed_certificate(session)
    r = viewer_client.post(f"/api/v1/certificates/{fingerprint}/ownership",
                           json={"owner": "x", "reason": "r"})
    assert r.status_code == 403


# ------------------------------------------------------------------ #
# Vendor contacts (P0#5)
# ------------------------------------------------------------------ #

def test_vendor_ownership_assignment(session, admin_client):
    vendor_id = _seed_vendor(session)
    r = admin_client.post(f"/api/v1/vendors/{vendor_id}/ownership",
                          json={"technical_contact": "crypto@vendor.example",
                                "reason": "r27: who answers crypto questions"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["technical_contact"] == "crypto@vendor.example"
    # pre-existing commercial contact untouched by a partial update
    assert body["primary_contact"] == "sales@vendor.example"

    listing = admin_client.get("/api/v1/vendors")
    assert listing.status_code == 200
    row = next(v for v in listing.json()["vendors"] if v["id"] == vendor_id)
    assert row["technical_contact"] == "crypto@vendor.example"

    r404 = admin_client.post("/api/v1/vendors/no-such-vendor/ownership",
                             json={"technical_contact": "x", "reason": "r"})
    assert r404.status_code == 404


def test_vendor_ownership_denied_to_viewer(session, viewer_client):
    vendor_id = _seed_vendor(session)
    r = viewer_client.post(f"/api/v1/vendors/{vendor_id}/ownership",
                           json={"technical_contact": "x", "reason": "r"})
    assert r.status_code == 403
