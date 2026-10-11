"""Composite-certificate inventory surface (advanced/59, round 32).

Repository ingest stores the detection in ``extra["composite"]``; the API
surface is a read projection over it.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register all tables
from api.config.settings import get_settings


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    db_url = f"sqlite:///{tmp_path}/composite.db"
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()

    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None

    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, db_url


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _seed_certs(db_url):
    eng = create_engine(db_url)
    Session = sessionmaker(bind=eng)
    session = Session()
    from db.repositories.certificate_repository import CertificateRepository

    repo = CertificateRepository(session)
    repo.upsert({
        "fingerprint_sha256": "a" * 64,
        "subject": "CN=hybrid-migration",
        "issuer": "CN=test-ca",
        "signature_algorithm": "id-ML-DSA65-RSA2048-PSS-SHA512",
        "public_key_algorithm": "ML-DSA-65",
        "public_key_size": 1952,
        "days_until_expiry": 30,
    })
    repo.upsert({
        "fingerprint_sha256": "b" * 64,
        "subject": "CN=kem-hybrid",
        "issuer": "CN=test-ca",
        "signature_algorithm": "ML-KEM-768+ECDH-P384",
        "days_until_expiry": 90,
    })
    repo.upsert({
        "fingerprint_sha256": "c" * 64,
        "subject": "CN=plain-rsa",
        "issuer": "CN=test-ca",
        "signature_algorithm": "sha256WithRSAEncryption",
        "public_key_algorithm": "RSA",
        "public_key_size": 2048,
        "days_until_expiry": 200,
    })
    session.commit()
    session.close()
    eng.dispose()


def test_composite_ingest_and_listing(sqlite_app):
    client, db_url = sqlite_app
    _seed_certs(db_url)

    # unauthenticated listing rejected before login primes cookies
    r = client.get("/api/v1/certificates/composite")
    assert r.status_code == 401

    _login(client)

    # the plain listing still carries all three, with the composite block
    r = client.get("/api/v1/certificates")
    assert r.status_code == 200, r.text
    by_subject = {c["subject"]: c for c in r.json()["certificates"]}
    assert len(by_subject) == 3
    assert (by_subject["CN=hybrid-migration"]["extra"] or {}).get("composite", {}).get(
        "scheme") == "composite-signature"
    assert not (by_subject["CN=plain-rsa"]["extra"] or {}).get("composite")

    # composite projection: exactly the two hybrid certs, with scheme counts
    r = client.get("/api/v1/certificates/composite")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "composite-certificates/read-projection-v1"
    assert body["count"] == 2
    assert body["scheme_counts"] == {"composite-signature": 1, "composite-kem": 1}
    subjects = {c["subject"] for c in body["certificates"]}
    assert subjects == {"CN=hybrid-migration", "CN=kem-hybrid"}
    hybrid = next(c for c in body["certificates"]
                  if c["subject"] == "CN=hybrid-migration")
    assert len(hybrid["composite"]["components"]) >= 2
    assert "registered composite OID arcs" in body["detection"]


def test_composite_listing_empty_is_empty(sqlite_app):
    client, _ = sqlite_app
    _login(client)
    r = client.get("/api/v1/certificates/composite")
    assert r.status_code == 200
    assert r.json()["count"] == 0 and r.json()["certificates"] == []
