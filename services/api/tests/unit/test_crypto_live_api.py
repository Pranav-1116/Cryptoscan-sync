"""Universal Crypto Scanner live API — events, state, risk, timeline,
versioned CBOM, accuracy, RBAC."""

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
from db.repositories.crypto_repository import CryptoRepository
from db.repositories.user_repository import UserRepository


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
    # detach the global bind so later tests (e.g. auth fallback paths) are
    # not left pointing at this test's closed in-memory database
    SessionLocal.configure(bind=None)


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
    repo.create_user("admin", hash_password("x"), ["admin"])
    session.commit()
    app = create_app()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", _mint_session(session, "admin", ["admin"]))
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


# ── ingestion + state (§34) ────────────────────────────────────────────

def test_ingest_cert_and_read_state(admin_client, session):
    r = admin_client.post("/api/v1/crypto/live/events", json={
        "event_type": "CERT_NEW",
        "asset_id": "payments",
        "source": "scanner",
        "payload": {
            "certificate_id": "cert-1",
            "subject": "payments.internal",
            "signature_algorithm": "RSA-PSS",
            "public_key_algorithm": "RSA",
            "key_size": 2048,
        },
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["changed"] is True
    assert body["cbom_version"] >= 1
    assert body["readiness"] == "QUANTUM_VULNERABLE"
    assert body["risk"]["level"] == "HIGH"

    state = admin_client.get("/api/v1/crypto/live/state/payments")
    assert state.status_code == 200
    data = state.json()
    assert data["certificates"]["cert-1"]["status"] == "VALID"
    assert data["quantum_status"]["RSA-PSS"] == "QUANTUM_VULNERABLE"


def test_cert_renewal_recalculates_pqc(admin_client, session):
    admin_client.post("/api/v1/crypto/live/events", json={
        "event_type": "CERT_NEW", "asset_id": "payments",
        "payload": {"certificate_id": "cert-1",
                    "signature_algorithm": "RSA-PSS"}})
    r = admin_client.post("/api/v1/crypto/live/events", json={
        "event_type": "CERT_RENEWED", "asset_id": "payments",
        "payload": {"certificate_id": "cert-1",
                    "previous_signature_algorithm": "RSA-PSS",
                    "signature_algorithm": "ML-DSA-65",
                    "public_key_algorithm": "ML-DSA-65"}})
    assert r.status_code == 200
    body = r.json()
    assert body["readiness"] == "PQC_READY"
    assert body["risk"]["level"] == "NONE"

    state = admin_client.get("/api/v1/crypto/live/state/payments").json()
    assert state["certificates"]["cert-1"]["status"] == "RENEWED"
    assert "RSA-PSS" not in state["quantum_status"]


def test_risk_summary_and_timeline(admin_client, session):
    admin_client.post("/api/v1/crypto/live/events", json={
        "event_type": "ALGORITHM_DETECTED", "asset_id": "svc",
        "payload": {"algorithm": "ML-KEM-768", "operation": "kem"}})
    summary = admin_client.get("/api/v1/crypto/live/risk-summary")
    assert summary.status_code == 200
    assert summary.json()["total_count"] == 1

    timeline = admin_client.get(
        "/api/v1/crypto/live/timeline", params={"asset_id": "svc"})
    assert timeline.status_code == 200
    events = timeline.json()["events"]
    assert len(events) == 1
    assert events[0]["event_type"] == "ALGORITHM_DETECTED"


def test_cbom_endpoint_cyclonedx(admin_client, session):
    admin_client.post("/api/v1/crypto/live/events", json={
        "event_type": "TLS_POLICY_CHANGED", "asset_id": "gw",
        "payload": {"protocol": "TLS", "min_version": "TLS 1.3", "pfs": True}})
    r = admin_client.get("/api/v1/crypto/live/gw/cbom")
    assert r.status_code == 200
    cbom = r.json()["cbom"]
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert r.json()["version"] >= 1


def test_state_404(admin_client):
    r = admin_client.get("/api/v1/crypto/live/state/nope")
    assert r.status_code == 404


def test_accuracy_endpoint(admin_client):
    r = admin_client.get("/api/v1/crypto/accuracy")
    assert r.status_code == 200
    data = r.json()
    assert "known_crypto" in data
    assert data["known_crypto"]["f1"] == 1.0
    assert data["known_noncrypto"]["false_positive_rate"] == 0.0


# ── RBAC ───────────────────────────────────────────────────────────────

def test_viewer_can_read_state_but_not_ingest(viewer_client):
    r = viewer_client.post("/api/v1/crypto/live/events", json={
        "event_type": "CERT_NEW", "asset_id": "svc",
        "payload": {"certificate_id": "c"}})
    assert r.status_code == 403
    r = viewer_client.get("/api/v1/crypto/live/state")
    assert r.status_code == 200


def test_ingest_persists_to_repository(session, admin_client):
    admin_client.post("/api/v1/crypto/live/events", json={
        "event_type": "ALGORITHM_DETECTED", "asset_id": "svc",
        "payload": {"algorithm": "AES-GCM", "operation": "encrypt"}})
    repo = CryptoRepository(session)
    row = repo.get_state("svc")
    assert row is not None
    assert row.algorithms.get("AES-GCM")
    assert row.risk_score is not None
    events, total = repo.list_events(asset_id="svc")
    assert total == 1
    assert events[0].event_type == "ALGORITHM_DETECTED"


# ── one-shot scan + simulate (§36) ─────────────────────────────────────

def test_oneshot_scan_endpoint(admin_client):
    r = admin_client.post("/api/v1/crypto/scan", json={
        "inputs": {"source_code": [{"language": "python",
                                    "text": "import hashlib\nh = hashlib.sha256(x)",
                                    "asset_id": "svc"}],
                   "policy": "NIST"}})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["observations"]
    assert any(o["algorithm"] == "SHA-256" for o in data["observations"])
    assert data["findings"]
    assert data["graph"]["nodes"]


def test_simulate_endpoint(admin_client):
    r = admin_client.post("/api/v1/crypto/simulate", json={
        "current_algorithm": "RSA", "target_algorithm": "ML-KEM-768",
        "protocol": "TLS", "library": "OpenSSL", "hardware": "HSM",
        "usage": True})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["projected_quantum_status"] == "QUANTUM_SAFE"
    assert data["risk_impact"]["risk_reduction"] == "HIGH"
    assert data["migration_readiness"] == "READY"
    assert data["compatible"] is True


def test_accuracy_endpoint_covers_policy_and_pqc_datasets(admin_client):
    r = admin_client.get("/api/v1/crypto/accuracy")
    assert r.status_code == 200
    data = r.json()
    assert "weak_crypto" in data
    assert data["weak_crypto"]["f1"] == 1.0
    assert "pqc_classification" in data
    assert data["pqc_classification"]["f1"] == 1.0
