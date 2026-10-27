"""Stream + live-CBOM tenancy: every scope sees only its own partition.

The event-stream bus (raw observations, normalized events, attack
detections, audit trail) and the live-CBOM version store used to be
process-global stores: any tenant's ingest was readable by every other
tenant (/attacks, /stream/events, /cbom/*), and two tenants using the same
system id shared one CBOM chain. These tests run the real stack — session
cookies, TenantScopeMiddleware — and pin the partition contract.

Partition semantics (2026-10): an unscoped request (single-tenant install,
platform operator) uses the base directories — behaviour unchanged from
before tenancy. A tenant-scoped request uses
<base>/tenants/<tenant-id>/ for both stores, and each scope sees ONLY its
own partition: no cross-visibility in either direction.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from api.main import create_app
from api.middleware.tenant_scope import TenantScopeMiddleware
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, configure_session, SessionLocal
from db.models.tenant import Tenant, TenantMembership
from db.repositories.user_repository import UserRepository

TLS_OK = {"kind": "tls_finding", "system": "core-1", "endpoint": "api.core:443",
          "crypto": {"tls_version": "TLSv1.3", "key_size": 256}}
TLS_DOWNGRADE = {"kind": "tls_finding", "system": "core-1", "endpoint": "api.core:443",
                 "crypto": {"tls_version": "TLSv1.0"}}


@pytest.fixture()
def stream_tenancy(tmp_path, monkeypatch):
    import eventstream.bus as bus_mod
    import services.api.api.routers.stream as stream_router

    monkeypatch.setenv("STREAM_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("CBOM_STORE_DIR", str(tmp_path / "cbom"))
    bus_mod.reset_bus()
    stream_router.reset_stream_singletons()

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False},
        poolclass=StaticPool)
    Base.metadata.create_all(engine)
    configure_session(engine)
    session = SessionLocal()

    users = UserRepository(session)
    users.create_user("acme_soc", hash_password("x"), ["soc"])
    users.create_user("globex_soc", hash_password("x"), ["soc"])
    users.create_user("platform_ops", hash_password("x"), ["admin"])
    session.add_all([
        Tenant(id="acme", name="Acme Bank", slug="acme"),
        Tenant(id="globex", name="Globex", slug="globex"),
        TenantMembership(tenant_id="acme", username="acme_soc",
                         tenant_role="member"),
        TenantMembership(tenant_id="globex", username="globex_soc",
                         tenant_role="member"),
    ])
    session.commit()

    app = create_app()
    # the real production stack (create_app skips tenant middleware in tests)
    app.add_middleware(TenantScopeMiddleware)

    def login(username: str, tenant: str | None = None) -> TestClient:
        manager = SessionManager()
        token = manager.create_session(username, roles=[])
        UserRepository(session).create_session(
            token, username, datetime.now(timezone.utc) + timedelta(hours=1),
            ip="127.0.0.1")
        session.commit()
        client = TestClient(app)
        client.cookies.set("cryptoscan_session", token)
        if tenant:
            client.headers["X-Tenant-ID"] = tenant
        return client

    try:
        yield {"acme": login("acme_soc", "acme"),
               "globex": login("globex_soc", "globex"),
               "ops": login("platform_ops"), "tmp_path": tmp_path}
    finally:
        session.close()
        engine.dispose()
        app.dependency_overrides.clear()
        bus_mod.reset_bus()
        stream_router.reset_stream_singletons()


def test_ingest_is_partitioned_by_tenant(stream_tenancy):
    acme, globex = stream_tenancy["acme"], stream_tenancy["globex"]

    # acme ingests a clean baseline, then a downgrade
    r = acme.post("/api/v1/stream/ingest", json={"payload": TLS_OK, "source": "t"})
    assert r.status_code == 200, r.text
    r2 = acme.post("/api/v1/stream/ingest",
                   json={"payload": TLS_DOWNGRADE, "source": "t"})
    assert r2.status_code == 200
    assert any(d["rule"] == "crypto_downgrade"
               for d in r2.json()["recent_detections"])

    # acme sees its own pipeline: attacks, audit trail, CBOM
    attacks = acme.get("/api/v1/attacks").json()["detections"]
    assert any(a["rule"] == "crypto_downgrade" for a in attacks)
    live = acme.get("/api/v1/cbom/live/core-1").json()
    assert live["version_no"] == 2

    # globex sees NONE of it — same system id, other partition
    assert globex.get("/api/v1/attacks").json()["detections"] == []
    assert globex.get("/api/v1/attacks/summary").json() == {
        "by_rule": {}, "by_severity": {}}
    assert globex.get("/api/v1/cbom/live/core-1").status_code == 404
    events = globex.get("/api/v1/stream/events",
                        params={"topic": "raw-events"}).json()["events"]
    assert events == []
    stats = globex.get("/api/v1/stream/stats").json()
    assert stats["topics"]["raw-events"]["last_seq"] == 0
    acme_stats = acme.get("/api/v1/stream/stats").json()
    assert acme_stats["topics"]["raw-events"]["last_seq"] == 2


def test_same_system_id_two_tenants_two_chains(stream_tenancy):
    acme, globex = stream_tenancy["acme"], stream_tenancy["globex"]

    for client in (acme, globex):
        r = client.post("/api/v1/stream/ingest",
                        json={"payload": TLS_OK, "source": "t"})
        assert r.status_code == 200

    # both have their own v1 chain for "core-1" — independent files, both valid
    for client in (acme, globex):
        live = client.get("/api/v1/cbom/live/core-1").json()
        assert live["version_no"] == 1
        verdict = client.get("/api/v1/cbom/verify/core-1").json()
        assert verdict["chain_valid"] is True and verdict["versions"] == 1

    # a second acme version must not bump globex's chain
    acme.post("/api/v1/stream/ingest", json={"payload": TLS_DOWNGRADE, "source": "t"})
    assert acme.get("/api/v1/cbom/live/core-1").json()["version_no"] == 2
    assert globex.get("/api/v1/cbom/live/core-1").json()["version_no"] == 1
    assert globex.get("/api/v1/cbom/verify/core-1").json()["chain_valid"] is True


def test_unscoped_requests_use_the_platform_partition(stream_tenancy):
    ops, acme = stream_tenancy["ops"], stream_tenancy["acme"]

    r = ops.post("/api/v1/stream/ingest", json={"payload": TLS_OK, "source": "t"})
    assert r.status_code == 200
    # the operator (no tenant) sees it — platform partition, unchanged paths
    assert any(a["rule"] for a in ops.get("/api/v1/attacks").json()["detections"])
    assert ops.get("/api/v1/cbom/live/core-1").json()["version_no"] == 1

    # and no tenant sees the platform partition — strict isolation both ways
    assert acme.get("/api/v1/attacks").json()["detections"] == []
    assert acme.get("/api/v1/cbom/live/core-1").status_code == 404


def test_compliance_retention_reads_the_callers_partition(stream_tenancy):
    acme, globex = stream_tenancy["acme"], stream_tenancy["globex"]

    acme.post("/api/v1/stream/ingest", json={"payload": TLS_OK, "source": "t"})
    # acme's own processing wrote an audit trail into its partition
    mine = acme.get("/api/v1/compliance/retention").json()
    assert mine["oldest_audit_record_epoch"] is not None
    # globex's partition has no audit records yet
    theirs = globex.get("/api/v1/compliance/retention").json()
    assert theirs["oldest_audit_record_epoch"] is None


def test_files_are_physically_partitioned(stream_tenancy):
    """The partition is on disk, not just filtered reads: a tenant's events
    never land in another tenant's log file."""
    acme, globex = stream_tenancy["acme"], stream_tenancy["globex"]
    acme.post("/api/v1/stream/ingest", json={"payload": TLS_OK, "source": "t"})
    globex.post("/api/v1/stream/ingest",
                json={"payload": TLS_DOWNGRADE, "source": "t"})

    logs = stream_tenancy["tmp_path"] / "logs"
    acme_dir = logs / "tenants" / "acme"
    globex_dir = logs / "tenants" / "globex"
    assert (acme_dir / "raw-events.jsonl").exists()
    assert (globex_dir / "raw-events.jsonl").exists()
    assert not (logs / "raw-events.jsonl").exists()  # platform dir stays empty

    cbom = stream_tenancy["tmp_path"] / "cbom"
    assert (cbom / "tenants" / "acme" / "core-1.jsonl").exists()
    assert (cbom / "tenants" / "globex" / "core-1.jsonl").exists()
    assert not (cbom / "core-1.jsonl").exists()
