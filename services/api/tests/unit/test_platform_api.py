"""§32 ZELNX control-plane API — unified discovery, combined CBOM+HBOM,
drift, risk, blast radius, what-if, security enforcement, evidence chain,
plus the existing platform-scope endpoint (must keep working)."""

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
    client.cookies.set("cryptoscan_session",
                       _mint_session(session, "admin", ["admin"]))
    return client


def _domains() -> dict:
    return {
        "network": {"assets": [
            {"asset_type": "load_balancer", "identity": "lb-1",
             "ip": "10.0.0.5", "certificates": ["svc.internal"]},
        ]},
        "crypto": {
            "observations": [{"algorithm": "RSA", "operation": "sign"}],
            "certificates": [{"subject": "CN=svc.internal",
                              "signature_algorithm": "RSA-PSS"}],
        },
        "hardware": {"assets": [
            {"asset_type": "hsm", "identity": "hsm-1", "host": "srv-1",
             "crypto_capabilities": ["mlkem768"]},
        ]},
        "cloud": {"assets": [
            {"asset_type": "cloud_resource", "identity": "aws-lb-1",
             "provider": "aws", "certificates": ["svc.internal"]},
        ]},
        "vendor": {"assets": [
            {"asset_type": "vendor", "identity": "Acme",
             "pqc_support": "ml-kem"},
        ]},
    }


def test_platform_scope_still_served(admin_client):
    resp = admin_client.get("/api/v1/platform/scope")
    assert resp.status_code == 200
    assert "mission" in resp.json() and "platform" in resp.json()


def test_platform_discover_combines_five_domains(admin_client):
    resp = admin_client.post("/api/v1/platform/discover",
                             json={"domains": _domains()})
    assert resp.status_code == 200
    body = resp.json()
    assert set(body["sources_run"]) == {"network", "crypto", "hardware",
                                        "cloud", "vendor"}
    assert body["asset_count"] >= 5
    kinds = {r["kind"] for r in body["relationships"]}
    assert "uses_cert" in kinds


def test_platform_combined_bom(admin_client):
    admin_client.post("/api/v1/platform/discover", json={"domains": _domains()})
    resp = admin_client.get("/api/v1/platform/bom")
    assert resp.status_code == 200
    bom = resp.json()
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert any(c["type"] == "cryptography" for c in bom["components"])
    assert any(c["type"] == "device" for c in bom["components"])


def test_platform_drift_and_risk(admin_client):
    resp = admin_client.post("/api/v1/platform/drift", json={
        "baseline": {"crypto": ["RSA"]},
        "live": {"crypto": ["RSA", "ML-KEM-768"]},
    })
    assert resp.status_code == 200
    assert resp.json()["drift_detected"] is True

    resp = admin_client.post("/api/v1/platform/risk", json={"domains": _domains()})
    assert resp.status_code == 200
    assert resp.json()["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_platform_blast_whatif_security_evidence(admin_client):
    resp = admin_client.post("/api/v1/platform/blast", json={
        "domains": _domains(), "seed": "svc.internal"})
    assert resp.status_code == 200
    assert resp.json()["affected_count"] >= 2

    resp = admin_client.post("/api/v1/platform/whatif", json={
        "domains": _domains(), "current": "RSA", "target": "ML-KEM-768"})
    assert resp.status_code == 200
    assert resp.json()["migration_plan"]["steps"]

    resp = admin_client.post("/api/v1/platform/security",
                             json={"request": {"mode": "AGGRESSIVE"}})
    assert resp.status_code == 200
    assert resp.json()["allowed"] is False

    resp = admin_client.get("/api/v1/platform/evidence")
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


def test_platform_rbac_viewer_cannot_discover(session):
    repo = UserRepository(session)
    repo.create_user("viewer", hash_password("x"), ["viewer"])
    session.commit()
    app = create_app()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session",
                       _mint_session(session, "viewer", ["viewer"]))
    resp = client.post("/api/v1/platform/discover",
                       json={"domains": _domains()})
    assert resp.status_code == 403
    # read-only endpoints stay available to the viewer
    assert client.get("/api/v1/platform/bom").status_code == 200
