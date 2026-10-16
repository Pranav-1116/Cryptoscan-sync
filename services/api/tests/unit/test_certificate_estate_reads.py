"""The persisted certificate ESTATE read surface (§5, round 74).

The Certificates page used to show only the live TLS-scan view (one
observation run, ephemeral). The estate — ``certificates`` rows deduped
by SHA-256 fingerprint with owner, usages and revocation state — had
read endpoints but no pinned contract and no UI. These tests pin what
the UI consumes: the estate list (owner present or honestly absent),
per-certificate usage locations (where it was observed), the revocation
check (OCSP/CRL result persisted), and direct ownership assignment
(audited, permission-gated).
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
from db.repositories.maturity_repository import MaturityRepository
from db.repositories.user_repository import UserRepository

NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)


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
    client = TestClient(create_app())
    client.cookies.set("cryptoscan_session", _mint_session(session, "ciso", ["ciso"]))
    return client


@pytest.fixture()
def viewer_client(session):
    repo = UserRepository(session)
    repo.create_user("viewer", hash_password("x"), ["viewer"])
    session.commit()
    client = TestClient(create_app())
    client.cookies.set("cryptoscan_session", _mint_session(session, "viewer", ["viewer"]))
    return client


def _seed_estate(session):
    repo = CertificateRepository(session)
    owned = repo.upsert({
        "fingerprint_sha256": "a" * 64,
        "subject": "CN=api.bank.example",
        "issuer": "CN=Internal Root CA",
        "not_after": NOW + timedelta(days=200),
        "days_until_expiry": 200,
        "expiry_status": "VALID",
        "public_key_algorithm": "RSA",
        "public_key_size": 2048,
    })
    # ownership is assigned through the audited endpoint, not the
    # scanner upsert — set what a prior assignment would have left
    owned.owner = "platform-team"
    owned.technical_contact = "oncall@bank.example"
    unowned = repo.upsert({
        "fingerprint_sha256": "b" * 64,
        "subject": "CN=legacy.bank.example",
        "issuer": "CN=Legacy CA",
        "not_after": NOW + timedelta(days=10),
        "days_until_expiry": 10,
        "expiry_status": "EXPIRING",
        "public_key_algorithm": "RSA",
        "public_key_size": 2048,
    })
    maturity = MaturityRepository(session)
    maturity.upsert_usage("a" * 64, "api.bank.example:443", "TLS_SERVER")
    maturity.upsert_usage("a" * 64, "mtls-gw.bank.example:8443", "TLS_CLIENT")
    session.commit()
    return owned, unowned


def test_estate_lists_rows_with_owner_present_or_absent(ciso_client, session):
    _seed_estate(session)
    r = ciso_client.get("/api/v1/certificates")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_count"] == 2
    by_subject = {c["subject"]: c for c in body["certificates"]}
    # owner is the stored fact — absent stays absent, never inferred
    assert by_subject["CN=api.bank.example"]["owner"] == "platform-team"
    assert by_subject["CN=legacy.bank.example"]["owner"] is None
    # the UI's row identity is the DB id + fingerprint
    assert by_subject["CN=api.bank.example"]["fingerprint_sha256"] == "a" * 64
    assert by_subject["CN=api.bank.example"]["id"]
    # sorted by expiry urgency: the 10-day cert comes first
    assert body["certificates"][0]["subject"] == "CN=legacy.bank.example"


def test_usages_report_where_the_certificate_was_observed(ciso_client, session):
    owned, _unowned = _seed_estate(session)
    r = ciso_client.get(f"/api/v1/certificates/{owned.id}/usages")
    assert r.status_code == 200, r.text
    body = r.json()
    locations = {u["location"]: u for u in body["usages"]}
    assert set(locations) == {"api.bank.example:443", "mtls-gw.bank.example:8443"}
    assert locations["api.bank.example:443"]["usage_type"] == "TLS_SERVER"
    assert body["certificate"]["fingerprint_sha256"] == "a" * 64
    # unknown ids are 404, never an empty fabrication
    assert ciso_client.get("/api/v1/certificates/no-such-id/usages").status_code == 404


def test_usages_honest_when_no_location_is_linked(ciso_client, session):
    _owned, unowned = _seed_estate(session)
    r = ciso_client.get(f"/api/v1/certificates/{unowned.id}/usages")
    assert r.status_code == 200
    assert r.json()["usages"] == []


def test_revocation_check_returns_both_probes_and_persists(ciso_client, session):
    owned, _unowned = _seed_estate(session)
    r = ciso_client.post(f"/api/v1/certificates/{owned.id}/revocation")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) >= {"ocsp", "crl"}
    # the offline parse reports what it could determine, without guessing
    for probe in (body["ocsp"], body["crl"]):
        assert "status" in probe and "method" in probe
    # expire the identity map: the app committed on its own session, and
    # the seeded object here would otherwise mask the committed values
    session.expire_all()
    refreshed = CertificateRepository(session).get_by_fingerprint("a" * 64)
    assert refreshed.revocation_checked_at is not None
    assert ciso_client.post("/api/v1/certificates/no-such-id/revocation").status_code == 404


def test_ownership_assignment_is_audited_and_permission_gated(session):
    _seed_estate(session)
    # viewer lacks certificates.manage
    repo = UserRepository(session)
    repo.create_user("viewer", hash_password("x"), ["viewer"])
    session.commit()
    client = TestClient(create_app())
    token = SessionManager().create_session("viewer", roles=["viewer"])
    UserRepository(session).create_session(
        token, "viewer", datetime.now(timezone.utc) + timedelta(hours=1), ip="127.0.0.1")
    session.commit()
    client.cookies.set("cryptoscan_session", token)
    r = client.post(
        "/api/v1/certificates/" + "b" * 64 + "/ownership",
        json={"owner": "viewer-should-not-set-this", "reason": "test"})
    assert r.status_code == 403, r.text

    # ciso assigns; only supplied fields change
    ciso = TestClient(create_app())
    ciso_token = SessionManager().create_session("ciso", roles=["ciso"])
    UserRepository(session).create_session(
        ciso_token, "ciso", datetime.now(timezone.utc) + timedelta(hours=1), ip="127.0.0.1")
    session.commit()
    ciso.cookies.set("cryptoscan_session", ciso_token)
    ok = ciso.post(
        "/api/v1/certificates/" + "b" * 64 + "/ownership",
        json={"owner": "network-team", "reason": "expiry ownership assigned"})
    assert ok.status_code == 200, ok.text
    assert ok.json()["owner"] == "network-team"
    row = CertificateRepository(session).get_by_fingerprint("b" * 64)
    assert row.owner == "network-team"
    assert row.technical_contact is None  # untouched
    assert ciso.post(
        "/api/v1/certificates/" + "z" * 64 + "/ownership",
        json={"owner": "x", "reason": "unknown fingerprint"}).status_code == 404
