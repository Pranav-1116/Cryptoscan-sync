"""Signed fixture capture -> tenant-owned metrics -> Twin simulation context.

The source is a local reconstructed exporter payload, not a bank endpoint. This
runs the real FastAPI auth/tenancy routes on SQLite and a freshly migrated,
disposable PostgreSQL database; no bank probe or customer qualification is claimed.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

import db.models  # noqa: F401 — register all migration-owned models
from api.main import create_app
from api.middleware.tenant_scope import TenantScopeMiddleware
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, SessionLocal, configure_session
from db.models.system import System
from db.models.tenant import Tenant, TenantMembership
from db.repositories.user_repository import UserRepository
from db.testing import drop_engine, estate_engine
from shared_models.performance_capture import SCHEMA, payload_sha256

TENANT_A, TENANT_B = "bank-a", "bank-b"
ASSET = "app:pay-1"
CHANGE = datetime.now(timezone.utc) - timedelta(hours=2)


@pytest.fixture()
def bank_app(request, tmp_path: Path, monkeypatch):
    previous = SessionLocal.kw.get("bind")
    if getattr(request, "param", "sqlite") == "postgresql":
        # The CI migration lane supplies an explicit disposable PostgreSQL
        # service; this helper creates and later drops only a unique test DB.
        test_url = os.environ.get("CRYPTOSCAN_TEST_DATABASE_URL")
        assert test_url, "live Performance test requires an explicitly configured test PostgreSQL"
        target = make_url(test_url)
        socket = target.query.get("host")
        assert (target.get_backend_name() == "postgresql"
                and target.database in {"postgres", "cs_ci_parity"}
                and (target.host in {"127.0.0.1", "localhost"}
                     or (target.host is None and isinstance(socket, str)
                         and socket.startswith("/tmp/")))), (
            "live Performance test accepts only a local disposable PostgreSQL service")
        engine = estate_engine("postgresql")
        assert engine is not None
        root = Path(__file__).resolve().parents[4]
        packages = [str(path) for base in (root / "services", root / "shared")
                    for path in base.iterdir() if path.is_dir()]
        env = dict(os.environ, DATABASE_URL=engine.url.render_as_string(hide_password=False),
                   PYTHONPATH=os.pathsep.join(packages))
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", "migrations/alembic.ini",
             "upgrade", "head"], cwd=root / "services/database", env=env,
            capture_output=True, text=True, timeout=600)
        if result.returncode:
            drop_engine(engine)
            pytest.fail(f"fresh PostgreSQL migration failed: {result.stderr[-3000:]}")
    else:
        engine = create_engine(f"sqlite:///{tmp_path / 'bank-performance.db'}",
                               connect_args={"check_same_thread": False, "timeout": 10})
        Base.metadata.create_all(engine)
    request.addfinalizer(lambda: drop_engine(engine))
    configure_session(engine)
    session = SessionLocal()
    users = UserRepository(session)
    for username, role in (("analyst-a", "security_analyst"),
                           ("reader-b", "readonly")):
        users.create_user(username, hash_password("fixture-not-a-login"), [role])
    for tenant in (TENANT_A, TENANT_B):
        session.add(Tenant(id=tenant, name=f"Fixture {tenant}", slug=tenant))
    session.add(TenantMembership(tenant_id=TENANT_A, username="analyst-a",
                                 tenant_role="member"))
    session.add(TenantMembership(tenant_id=TENANT_B, username="reader-b",
                                 tenant_role="viewer"))
    session.add(System(id="pay-1", tenant_id=TENANT_A, name="Fixture payments",
                       environment="test"))
    session.commit()

    key = Ed25519PrivateKey.generate()  # test process only — no private key file
    public = tmp_path / "fixture-capture-public.pem"
    public.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setenv("PERFORMANCE_CAPTURE_PUBLIC_KEY_FILE", str(public))
    monkeypatch.setenv("ENVIRONMENT", "test")

    manager = SessionManager()
    clients = {}
    app = create_app()
    app.add_middleware(TenantScopeMiddleware)
    for username, tenant in (("analyst-a", TENANT_A), ("reader-b", TENANT_B)):
        token = manager.create_session(username, roles=[])
        users.create_session(token, username, datetime.now(timezone.utc) + timedelta(hours=1),
                             ip="127.0.0.1")
        client = TestClient(app, headers={"X-Tenant-ID": tenant})
        client.cookies.set("cryptoscan_session", token)
        clients[tenant] = client
    session.commit()
    try:
        yield clients, session, key
    finally:
        for client in clients.values():
            client.close()
        session.close()
        SessionLocal.configure(bind=previous)


def _signed_capture(key, *, observed_at: datetime, value: int) -> dict:
    payload = {"metrics": {"http.server.active_requests": [
        {"value": value, "labels": {}}]}}
    body = {"tenant_id": TENANT_A, "asset_ref": ASSET,
            "source_id": "fixture-otlp-exporter", "source_type": "otlp",
            "authorization_ref": "fixture-approved-scope", "observed_at": observed_at.isoformat(),
            "payload": payload}
    signed = {"schema": SCHEMA, "algorithm": "Ed25519", "key_id": "fixture-only",
              "issuer": "fixture-collector", "tenant_id": TENANT_A, "asset_ref": ASSET,
              "source_id": body["source_id"], "source_type": body["source_type"],
              "observed_at": observed_at.isoformat(), "previous_observed_at": None,
              "authorization_ref": body["authorization_ref"],
              "payload_sha256": payload_sha256(payload), "previous_sha256": None}
    message = json.dumps(signed, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode()
    body["attestation"] = {"schema": SCHEMA, "algorithm": "Ed25519",
                           "key_id": "fixture-only", "issuer": "fixture-collector",
                           "signature": base64.b64encode(key.sign(message)).decode()}
    return body


@pytest.mark.parametrize("bank_app", [
    "sqlite", pytest.param("postgresql", marks=pytest.mark.live),
], indirect=True)
def test_signed_capture_reaches_tenant_twin_simulation_only(bank_app):
    clients, db, key = bank_app
    own, foreign = clients[TENANT_A], clients[TENANT_B]
    change = own.post("/api/v1/cryptolog/events", json={
        "event_id": "fixture-change", "event_type": "CRYPTO_CONFIGURATION_CHANGED",
        "category": "CONFIGURATION", "logging_kind": "CHANGE",
        "tenant_id": TENANT_A, "severity": "INFO", "asset_id": ASSET,
        "source": {"collector_id": "fixture-config", "collector_version": "1",
                   "source_type": "CONFIGURATION_OBSERVATION"},
        "cryptographic_context": {"protocol": "TLS", "evidence_level": "CONFIGURED"},
        "observation": {"observed_at": CHANGE.isoformat()},
        "evidence": {"evidence_ids": ["fixture-unverified-change-evidence"]},
    })
    assert change.status_code == 201, change.text

    discovery = own.post("/api/v1/estate/evidence/discover", json={
        "estate": "fixture-bank-performance", "assets": [{
            "ref": "payment", "type": "APPLICATION", "name": "Fixture payments",
            "identity": {"system_id": "pay-1"}}],
        "evidence": [{"source": "fixture-static", "evidence_type": "STATIC_OBSERVED",
                      "target": "payment", "layer": "APPLICATION",
                      "facts": {"algorithm": "RSA", "purpose": "sign"}}],
    })
    assert discovery.status_code == 200, discovery.text
    before_twin = own.get("/api/v1/estate/evidence/summary").json()

    for is_before in (True, False):
        for index in range(5):
            stamp = CHANGE + timedelta(minutes=-10 if is_before else 10,
                                       seconds=index)
            capture = own.post("/api/v1/performance/captures/import",
                               json=_signed_capture(key, observed_at=stamp,
                                                    value=20 if is_before else 30))
            assert capture.status_code == 200, capture.text
            assert capture.json()["accepted"] == 1
            assert capture.json()["provenance_state"] == "SIGNED_SOURCE_ASSERTION"
    samples = own.get("/api/v1/performance/samples", params={
        "tenant_id": TENANT_A, "asset_id": ASSET}).json()["samples"]
    assert len(samples) == 10
    assert all(str(row["evidence_id"]).startswith("signed-capture:")
               for row in samples)
    receipt_id = samples[0]["evidence_id"].removeprefix("signed-capture:")
    receipt = own.get(f"/api/v1/performance/captures/{receipt_id}",
                      params={"tenant_id": TENANT_A})
    assert receipt.status_code == 200 and receipt.json()["signature"]
    assert foreign.get(f"/api/v1/performance/captures/{receipt_id}",
                       params={"tenant_id": TENANT_B}).status_code == 404

    performance = {"tenant_id": TENANT_A, "asset_ref": ASSET,
                   "metric_name": "api.concurrent_requests",
                   "source_id": "fixture-otlp-exporter",
                   "change_event_id": "fixture-change",
                   "before_start": (CHANGE - timedelta(minutes=30)).isoformat(),
                   "before_end": (CHANGE - timedelta(minutes=1)).isoformat(),
                   "after_start": (CHANGE + timedelta(minutes=1)).isoformat(),
                   "after_end": (CHANGE + timedelta(minutes=30)).isoformat()}
    run = own.post("/api/v1/estate/evidence/simulation/run", json={
        "kind": "REPLACE_ALGORITHM", "from": "RSA", "to": "ML-DSA",
        "persist": False, "performance_context": performance})
    assert run.status_code == 200, run.text
    result = run.json()
    assert result["status"] == "SIMULATED"
    measured = result["performance_context"]
    assert measured["purpose"] == "SIMULATION_INPUT"
    assert measured["status"] == "MEASURED_COMPARISON"
    assert measured["before"]["signed_capture_samples"] == 5
    assert measured["after"]["signed_capture_samples"] == 5
    assert measured["delta_percent"] == 50
    assert measured["link"]["state"] == "AFFECTED_EXACT_IDENTITY"
    assert measured["causation"] == "UNPROVEN"
    assert "migration_plan" not in measured
    assert result["live_state_modified"] is False
    assert own.get("/api/v1/estate/evidence/summary").json() == before_twin

    # A different bank cannot select this tenant or submit a capture for it.
    assert foreign.get("/api/v1/performance/samples", params={
        "tenant_id": TENANT_A}).status_code == 403
    forged = foreign.post("/api/v1/performance/captures/import",
                          json=_signed_capture(key, observed_at=CHANGE, value=100))
    assert forged.status_code == 403
    assert db.query(System).filter_by(id="pay-1").one().tenant_id == TENANT_A
