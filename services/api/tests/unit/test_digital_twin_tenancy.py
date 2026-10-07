"""Digital-twin API under multi-tenancy — the isolation is tested, not asserted.

Two tenants and a platform estate share one store. Everything here runs the
real stack: real session cookies, real TenantScopeMiddleware (which resolves
membership via the real SessionLocal), the real ORM tenant guard. No
dependency overrides — if the twin leaks another tenant's row through any of
its six endpoints, these tests see it as it would ship.

The sharpest probes are the scenario endpoints: `affected.assets` names asset
ids, so a cross-tenant row is not a count that might be coincidentally right,
it is a name that should not be there.
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
from db.connection.session import Base, SessionLocal, configure_session
from db.models.certificate import Certificate
from db.models.crypto_live import CryptoLiveEventRow, CryptoLiveState
from db.models.evidence_record import EvidenceRecord
from db.models.hardware_live import HardwareAsset
from db.models.network_scan_run import NetworkScanRun
from db.models.network_scan_target import NetworkScanTarget
from db.models.system import System
from db.models.tenant import Tenant, TenantMembership
from db.models.user import User
from db.repositories.user_repository import UserRepository

NOW = datetime.now(timezone.utc)


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


def _login(session, app, username: str) -> TestClient:
    """A client with a real session cookie — the middleware validates it."""
    manager = SessionManager()
    token = manager.create_session(username, roles=[])
    UserRepository(session).create_session(
        token, username, datetime.now(timezone.utc) + timedelta(hours=1),
        ip="127.0.0.1")
    session.commit()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", token)
    return client


@pytest.fixture()
def clients(session):
    """acme_viewer (member of acme only) and root (superadmin, platform)."""
    users = UserRepository(session)
    users.create_user("acme_viewer", hash_password("x"), ["viewer"])
    users.create_user("root", hash_password("x"), ["superadmin"])
    session.add(Tenant(id="acme", name="Acme Bank", slug="acme"))
    session.add(Tenant(id="globex", name="Globex", slug="globex"))
    session.add(TenantMembership(tenant_id="acme", username="acme_viewer",
                                 tenant_role="member"))
    session.commit()

    app = create_app()
    # create_app skips TenantScopeMiddleware under ENVIRONMENT=test (set by
    # the suite conftest), but production installs it. Tenancy is the point
    # of this file, so install it explicitly and run the real stack.
    app.add_middleware(TenantScopeMiddleware)
    yield _login(session, app, "acme_viewer"), _login(session, app, "root"), app
    app.dependency_overrides.clear()


def _seed(session) -> None:
    """Three estates in one store: acme, globex, and platform (NULL tenant).

    Every tenant's data is distinguishable by name so a leak is a name that
    should not be in the response, never a plausible count.
    """
    session.add(CryptoLiveState(
        tenant_id="acme", asset_id="acme-hsm-01", cbom_version=3,
        algorithms={"RSA-2048": 5},
        quantum_status={"status": "vulnerable"},
        protocols={"tls": "1.1"}, usage={"signing": "hsm"},
    ))
    session.add(CryptoLiveEventRow(
        tenant_id="acme", event_type="CBOM_UPDATED", asset_id="acme-hsm-01",
        observed_at=NOW - timedelta(minutes=5), cbom_version=3, risk_score=70,
    ))
    session.add(CryptoLiveState(
        tenant_id="globex", asset_id="globex-pay-01", cbom_version=2,
        algorithms={"ECDSA-P256": 4},
        quantum_status={"status": "ready"},
        protocols={"tls": "1.3"},
    ))
    session.add(CryptoLiveState(
        asset_id="platform-edge-01", cbom_version=1,  # platform estate
        algorithms={"AES-256-GCM": 9},
        quantum_status={"status": "ready"},
    ))

    session.add(System(tenant_id="acme", id="sys-acme", name="Acme Core"))
    session.add(System(tenant_id="globex", id="sys-globex", name="Globex Core"))

    session.add(EvidenceRecord(
        tenant_id="acme", scan_id="s-acme", content_hash="a" * 64,
        chain_hash="", chain_position=0, algorithm="RSA-2048",
        file_path="src/Acme.java", line_number=1, finding_data={},
    ))
    session.add(EvidenceRecord(
        tenant_id="globex", scan_id="s-globex", content_hash="b" * 64,
        chain_hash="", chain_position=0, algorithm="ECDSA-P256",
        file_path="src/Globex.java", line_number=1, finding_data={},
    ))

    session.add(Certificate(
        tenant_id="acme", fingerprint_sha256="a" * 64,
        subject="CN=acme", not_after=NOW + timedelta(days=30),
    ))
    session.add(Certificate(
        tenant_id="globex", fingerprint_sha256="g" * 64,
        subject="CN=globex", not_after=NOW + timedelta(days=30),
    ))
    session.add(Certificate(
        fingerprint_sha256="p" * 64, subject="CN=platform",
        not_after=NOW + timedelta(days=30),
    ))

    session.add(HardwareAsset(
        tenant_id="acme", asset_id="hsm-acme", manufacturer="Thales",
        model="Luna 7", device_type="hsm",
        hsm={"device_type": "hsm", "manufacturer": "Thales",
             "model": "Luna 7", "pqc_capability": "READY"},
    ))
    session.add(HardwareAsset(
        tenant_id="globex", asset_id="hsm-globex", manufacturer="Utimaco",
        model="Se Gen2", device_type="hsm",
        hsm={"device_type": "hsm", "manufacturer": "Utimaco",
             "model": "Se Gen2", "pqc_capability": "NOT_READY"},
    ))

    session.add(NetworkScanRun(
        tenant_id="acme", target_kind="hosts", verdict="OK", probed=1, ok=1,
        result={"probes": [{"endpoint": "old.acme.bank:443", "status": "TLS_OK",
                            "tls_version": "TLSv1.0"}]},
    ))
    session.add(NetworkScanRun(
        tenant_id="globex", target_kind="hosts", verdict="OK", probed=1, ok=1,
        result={"probes": [{"endpoint": "new.globex.bank:443", "status": "TLS_OK",
                            "tls_version": "TLSv1.3"}]},
    ))
    session.add(NetworkScanTarget(tenant_id="acme", endpoint="reg.acme.bank:443"))
    session.commit()


# ------------------------------------------------------------ overview

def test_tenant_sees_own_and_platform_rows_never_another_tenants(clients, session):
    acme, _root, _app = clients
    _seed(session)

    body = acme.get("/api/v1/digital-twin").json()
    assert body["twin_assets"] == 2  # acme-hsm-01 + platform-edge-01
    assert body["systems"] == 1      # sys-acme
    assert body["certificates"] == 2
    assert body["evidence_records"] == 1
    assert body["hardware_hsms"] == 1
    # acme's probe (observed) + acme's registered target; globex's endpoint
    # must not appear.
    assert body["network_endpoints"] == 2
    assert body["network_endpoints_observed"] == 1
    assert body["fidelity"]["twin"]["journal_events"] == 1


def test_platform_admin_without_header_sees_the_whole_store(clients, session):
    _acme, root, _app = clients
    _seed(session)
    body = root.get("/api/v1/digital-twin").json()
    assert body["twin_assets"] == 3
    assert body["systems"] == 2
    assert body["certificates"] == 3
    assert body["hardware_hsms"] == 2


def test_platform_admin_header_scopes_into_one_tenant(clients, session):
    _acme, root, _app = clients
    _seed(session)
    body = root.get("/api/v1/digital-twin",
                    headers={"X-Tenant-ID": "globex"}).json()
    assert body["twin_assets"] == 2  # globex-pay-01 + platform-edge-01
    assert body["hardware_hsms"] == 1


# ------------------------------------------------------------ simulate

def test_scenario_names_never_cross_tenants(clients, session):
    """affected.assets is a name list — the sharpest leak detector."""
    acme, root, _app = clients
    _seed(session)

    r = acme.post("/api/v1/digital-twin/simulate", json={
        "scenario": "algorithm_migration",
        "params": {"from_algo": "RSA", "to_algo": "ML-KEM-768"},
    })
    assert r.status_code == 200, r.text
    assert r.json()["affected"]["assets"] == ["acme-hsm-01"]

    # Platform admin scoped into globex sees globex names only.
    r = root.post("/api/v1/digital-twin/simulate", json={
        "scenario": "algorithm_migration",
        "params": {"from_algo": "ECDSA", "to_algo": "ML-KEM-768"},
    }, headers={"X-Tenant-ID": "globex"})
    assert r.status_code == 200, r.text
    assert r.json()["affected"]["assets"] == ["globex-pay-01"]


def test_hsm_fleet_is_tenant_scoped(clients, session):
    acme, _root, _app = clients
    _seed(session)
    r = acme.post("/api/v1/digital-twin/simulate", json={
        "scenario": "hsm_outage", "params": {},
    })
    assert r.status_code == 200, r.text
    fleet = r.json()["affected"]["hardware_hsms"]
    assert [d["asset_id"] for d in fleet] == ["hsm-acme"]
    assert r.json()["impact"]["hsm_fleet"] == ["Thales Luna 7"]


def test_wire_evidence_is_tenant_scoped(clients, session):
    acme, _root, _app = clients
    _seed(session)
    r = acme.post("/api/v1/digital-twin/simulate", json={
        "scenario": "protocol_deprecation",
        "params": {"protocol": "TLS", "min_version": "1.2"},
    })
    assert r.status_code == 200, r.text
    assert r.json()["affected"]["endpoints"] == ["old.acme.bank:443"]


# ------------------------------------------------------- fidelity / reconcile

def test_fidelity_and_reconciliation_are_tenant_scoped(clients, session):
    acme, _root, _app = clients
    _seed(session)

    fid = acme.get("/api/v1/digital-twin/fidelity").json()
    assert fid["twin"]["assets"] == 2
    assert fid["twin"]["journal_events"] == 1

    rec = acme.get("/api/v1/digital-twin/reconciliation").json()
    # acme twin: RSA (acme) + AES (platform). acme evidence: RSA only.
    assert rec["twin_algorithm_families"] == {"aes-256-gcm": 1, "rsa-2048": 1}
    assert rec["evidence_algorithm_families"] == {"rsa-2048": 1}
    assert rec["verdict"] == "EVIDENCE_LAGS_TWIN"
    # globex's ECDSA must not appear anywhere in acme's diff.
    assert "ecdsa-p256" not in str(rec)


# ------------------------------------------------------------- timeline

def test_timeline_cannot_see_another_tenants_asset(clients, session):
    acme, _root, _app = clients
    _seed(session)
    # A cross-tenant asset id is answered as absent — its existence is not
    # acme's to learn.
    r = acme.get("/api/v1/digital-twin/timeline/globex-pay-01")
    assert r.status_code == 404
    # Own asset is served, with its journal.
    r = acme.get("/api/v1/digital-twin/timeline/acme-hsm-01")
    assert r.status_code == 200
    assert len(r.json()["events"]) == 1


def test_forged_tenant_header_is_refused_not_redirected(clients, session):
    """acme_viewer claims to be globex: 404 before any twin query runs."""
    acme, _root, _app = clients
    _seed(session)
    r = acme.get("/api/v1/digital-twin", headers={"X-Tenant-ID": "globex"})
    assert r.status_code == 404
    r = acme.post("/api/v1/digital-twin/simulate",
                  json={"scenario": "pqc_migration", "params": {}},
                  headers={"X-Tenant-ID": "globex"})
    assert r.status_code == 404


def test_member_without_membership_is_refused_not_unscoped(clients, session):
    """A user with no membership and no platform role must not fall through
    to the unscoped (every tenant's rows) path — the guard fails closed."""
    session.query(User).filter(User.username == "root").first()  # keep root
    users = UserRepository(session)
    users.create_user("orphan", hash_password("x"), ["viewer"])
    session.commit()

    from api.security.session_manager import SessionManager
    manager = SessionManager()
    token = manager.create_session("orphan", roles=[])
    UserRepository(session).create_session(
        token, "orphan", datetime.now(timezone.utc) + timedelta(hours=1),
        ip="127.0.0.1")
    session.commit()

    _acme, _root, app = clients
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", token)
    _seed(session)
    r = client.get("/api/v1/digital-twin")
    assert r.status_code == 403
    assert "membership" in r.json()["detail"].lower()
