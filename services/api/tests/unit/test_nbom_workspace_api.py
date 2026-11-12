"""NBOM workspace API (docs/boms/01_PRODUCT_SPEC.md §4).

Real sqlite + real sessions. The workspace answers what is exposed on the
wire and what backs each record — and the working rule is pinned as
behaviour: a port scan or endpoint inventory alone does not prove the
negotiated cryptographic configuration. Negotiated TLS version and cipher
suite render only where a handshake was actually observed; everywhere else
the state is `unknown` — never "none", never "plaintext", never a healthy
default. Empty estates get honest empty states.
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
from db.models.certificate import Certificate
from db.models.network_scan_run import NetworkScanRun
from db.repositories.user_repository import UserRepository

NOW = datetime.now(timezone.utc)

CERT_FP = "ab" * 32


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


def _seed_scan(session):
    session.add(NetworkScanRun(
        target_kind="hosts", verdict="PARTIAL", probed=3, ok=1,
        created_at=NOW - timedelta(days=1),
        result={"probes": [
            # a handshake actually completed: negotiated crypto is observed
            {"endpoint": "payments-1:443", "status": "TLS_OK",
             "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384",
             "alpn": "h2",
             "certificates": [{"subject": "CN=payments", "issuer": "CN=ca",
                               "fingerprint_sha256": CERT_FP,
                               "public_key_algorithm": "RSA",
                               "public_key_size": 2048, "expiry_status": "VALID"}]},
            # refused and timed out: inventoried, negotiation unknown
            {"endpoint": "legacy-1:443", "status": "REFUSED"},
            {"endpoint": "legacy-1:22", "status": "TIMEOUT", "starttls": "ssh"},
        ]}))
    session.add(Certificate(
        fingerprint_sha256=CERT_FP, subject="CN=payments", issuer="CN=ca",
        public_key_algorithm="RSA", public_key_size=2048,
        expiry_status="VALID", not_after=NOW + timedelta(days=100)))
    session.commit()


def test_empty_estate_reports_honest_empty_state(client):
    body = client.get("/api/v1/nbom/workspace/overview").json()
    assert body["state"] == "NO_RECORDS"
    assert body["endpoints"] == 0
    inv = client.get("/api/v1/nbom/workspace/endpoints").json()
    assert inv["rows"] == []


def test_negotiated_crypto_only_where_a_handshake_was_observed(client, session):
    _seed_scan(session)
    rows = client.get("/api/v1/nbom/workspace/endpoints").json()["rows"]
    by_ep = {r["endpoint"]: r for r in rows}
    assert len(rows) == 3
    # observed handshake: negotiated facts as recorded
    ok = by_ep["payments-1:443"]
    assert ok["tls_version"] == "TLSv1.3"
    assert ok["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert ok["negotiation"]["state"] == "OBSERVED"
    # refused / timed out: the collector cannot establish it — `unknown`
    for ep in ("legacy-1:443", "legacy-1:22"):
        row = by_ep[ep]
        assert row["tls_version"] == "unknown", ep
        assert row["cipher_suite"] == "unknown", ep
        assert row["negotiation"]["state"] == "unknown", ep
        assert "port scan or endpoint inventory alone does not prove" in row["negotiation"]["basis"]
        # never a healthy or plaintext default
        assert row["tls_version"] not in {"none", "plaintext", ""}


def test_spec_columns_and_detail_evidence(client, session):
    _seed_scan(session)
    rows = client.get("/api/v1/nbom/workspace/endpoints").json()["rows"]
    row = next(r for r in rows if r["endpoint"] == "payments-1:443")
    for column in ("endpoint", "port", "protocol", "service", "tls_version",
                   "cipher_suite", "certificate", "source", "first_observed", "last_observed"):
        assert column in row, column
    assert row["certificate"]["fingerprint_sha256"] == CERT_FP
    detail = client.get("/api/v1/nbom/workspace/endpoints/payments-1:443").json()
    assert detail["evidence"]["method"].startswith("active probe")
    assert detail["certificate_detail"]["subject"] == "CN=payments"
    assert detail["dependencies"] == [{"type": "served_by", "target": f"certificate:{CERT_FP}"}]
    certs = client.get("/api/v1/nbom/workspace/certificates").json()
    assert certs["rows"][0]["in_store"] is True


def test_unknown_endpoint_and_protocol_sections(client, session):
    _seed_scan(session)
    assert client.get("/api/v1/nbom/workspace/endpoints/nope:1").status_code == 404
    ssh = client.get("/api/v1/nbom/workspace/ssh").json()
    assert ssh["total"] == 1
    assert ssh["rows"][0]["tls_version"] == "unknown"  # timed-out SSH probe stays unknown
    tls = client.get("/api/v1/nbom/workspace/tls").json()
    assert tls["observed"] == 1
    assert tls["unknown"] == 1
    ipsec = client.get("/api/v1/nbom/workspace/ipsec").json()
    assert ipsec["state"] == "NO_IPSEC_OBSERVATIONS"
