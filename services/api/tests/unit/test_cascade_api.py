"""Cross-BOM cascade API — the unified "what breaks if X changes?" endpoints.

Three endpoints on the technology-bom router: run a cascade (over the live
digital-twin snapshot, persisted as an audit trail), list the history, and
fetch one past answer exactly as it was returned.

The tenancy half runs the real stack — real session cookies, real
TenantScopeMiddleware — because a cascade names systems, and a name that
should not be in the answer is the sharpest possible leak detector.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from api.middleware.tenant_scope import TenantScopeMiddleware
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, configure_session, SessionLocal
from db.models import (
    Certificate,
    CryptoAsset,
    CryptoAssetEvidence,
    EvidenceRecord,
    System,
    SystemAsset,
    SystemDependency,
    SystemVendor,
    Vendor,
)
from db.models.cascade_run import CascadeRun
from db.models.network_scan_target import NetworkScanTarget
from db.models.tenant import Tenant, TenantMembership
from db.repositories.user_repository import UserRepository

NOW = datetime.now(timezone.utc)


# ------------------------------------------------------------ functional

@pytest.fixture()
def app_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    application.state.test_session = session

    _seed_estate(session)
    try:
        yield application
    finally:
        session.close()
        engine.dispose()


def _seed_estate(session) -> None:
    """A small estate with every layer: systems, edges, assets, evidence,
    certificates, a vendor link and a registered endpoint."""
    session.add_all([
        System(id="sys-web", name="web-frontend", criticality="TIER-1"),
        System(id="sys-pay", name="payment-api", criticality="TIER-1"),
        System(id="sys-db", name="customer-db", criticality="TIER-2"),
        CryptoAsset(id="ca-rsa", algorithm="RSA-2048", file_path="src/Pay.java",
                    purpose="signing", key_size=2048, confidence=1.0),
        EvidenceRecord(scan_id="s-1", content_hash="a" * 64, chain_hash="",
                       chain_position=0, algorithm="RSA-2048",
                       file_path="src/Pay.java", line_number=1,
                       finding_data={}),
        Vendor(id="vendor-thales", name="Thales", criticality="HIGH",
               vendor_type="hsm"),
        Certificate(fingerprint_sha256="ab" * 32, subject="CN=payment-api",
                    not_after=NOW + timedelta(days=200)),
        NetworkScanTarget(endpoint="api.bank:443", system_id="sys-pay"),
    ])
    session.flush()
    session.add_all([
        SystemDependency(parent_id="sys-web", child_id="sys-pay"),
        SystemDependency(parent_id="sys-pay", child_id="sys-db"),
        SystemAsset(system_id="sys-pay", asset_id="ca-rsa"),
        CryptoAssetEvidence(asset_id="ca-rsa", evidence_id="ev-1"),
        SystemVendor(id="sv-1", system_id="sys-pay", vendor_id="vendor-thales",
                     dependency_type="runtime"),
    ])
    # the evidence row gets its id after flush; link via the query-safe route
    ev = session.query(EvidenceRecord).filter_by(algorithm="RSA-2048").first()
    link = session.query(CryptoAssetEvidence).first()
    if ev and link:
        link.evidence_id = ev.id
    session.commit()


def test_system_cascade_persists_and_answers(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "payment-api"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "AFFECTED"
    assert body["target"]["kind"] == "system"
    assert body["run_id"]
    assert body["schema"] == "cryptoscan.unified-cascade/1"
    # both graph directions: web-frontend calls payment-api calls customer-db
    assert body["layers"]["system"]["dependents_by_depth"] == {"1": ["sys-web"]}
    assert body["layers"]["system"]["downstream_by_depth"] == {"1": ["sys-db"]}
    assert body["impact"]["affected_system_count"] == 3
    assert body["honest_unknowns"]


def test_algorithm_cascade_reaches_code_evidence(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "RSA-2048"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["target"]["kind"] == "algorithm"
    assert body["verdict"] == "AFFECTED"
    assert body["layers"]["code"]["systems"] == ["sys-pay"]
    assert body["layers"]["code"]["evidence_ids"]
    assert body["layers"]["code"]["files"] == ["src/Pay.java"]


def test_endpoint_cascade_names_owner_system(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "api.bank:443"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["target"]["kind"] == "endpoint"
    # registered target carries the owning system through the snapshot
    assert body["layers"]["system"]["systems"] == ["sys-pay"]


def test_unknown_target_is_not_found_but_persisted(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "no-such-thing"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "NOT_FOUND"
    assert body["run_id"]
    with TestClient(app_db) as client:
        listed = client.get("/api/v1/technology-bom/cascade/runs").json()
    assert any(r["target"] == "no-such-thing" and r["verdict"] == "NOT_FOUND"
               for r in listed["runs"])


def test_bad_kind_is_a_400(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "RSA-2048", "kind": "nonsense"})
    assert resp.status_code == 400


def test_depth_out_of_bounds_is_a_422(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "payment-api", "max_depth": 13})
    assert resp.status_code == 422


def test_history_lists_runs_newest_first(app_db):
    with TestClient(app_db) as client:
        first = client.post("/api/v1/technology-bom/cascade",
                            json={"target": "payment-api"}).json()
        second = client.post("/api/v1/technology-bom/cascade",
                             json={"target": "RSA-2048"}).json()
        listed = client.get("/api/v1/technology-bom/cascade/runs").json()
    assert listed["count"] == 2
    assert listed["runs"][0]["id"] == second["run_id"]
    assert listed["runs"][1]["id"] == first["run_id"]
    assert listed["runs"][0]["affected_system_count"] is not None


def test_run_fetch_returns_the_persisted_answer(app_db):
    with TestClient(app_db) as client:
        posted = client.post("/api/v1/technology-bom/cascade",
                             json={"target": "payment-api", "max_depth": 2}).json()
        fetched = client.get(
            f"/api/v1/technology-bom/cascade/runs/{posted['run_id']}").json()
    assert fetched["id"] == posted["run_id"]
    assert fetched["target"] == "payment-api"
    assert fetched["target_kind"] == "system"
    assert fetched["max_depth"] == 2
    assert fetched["verdict"] == "AFFECTED"
    # the persisted result is the exact answer, honest unknowns included
    assert fetched["result"]["impact"]["affected_system_count"] == 3
    assert fetched["result"]["honest_unknowns"] == posted["honest_unknowns"]


def test_missing_run_is_a_404(app_db):
    with TestClient(app_db) as client:
        resp = client.get("/api/v1/technology-bom/cascade/runs/nope")
    assert resp.status_code == 404


# ------------------------------------------- P2 read-model honesty (2026-10)

def test_replay_run_persists_replay_provenance(app_db):
    """A point-in-time replay must be auditable as one: the persisted run —
    not just the HTTP response — records which twin snapshot it replayed."""
    with TestClient(app_db) as client:
        cap = client.post("/api/v1/digital-twin/snapshot").json()
        assert cap["recorded"] is True
        version = cap["version"]

        posted = client.post("/api/v1/technology-bom/cascade",
                             params={"version": version},
                             json={"target": "payment-api"}).json()
        # the live answer names the replayed version...
        assert posted["replayed_over"] == {"twin_snapshot_version": version}

        # ...and so does the persisted audit trail — read the row back from
        # the database (a fresh session, not the request session's identity
        # map, which would hand back the same mutated dict)
        from sqlalchemy.orm import sessionmaker

        fresh = sessionmaker(bind=app_db.state.test_session.get_bind(),
                             expire_on_commit=False)()
        try:
            row = fresh.query(CascadeRun).filter(
                CascadeRun.id == posted["run_id"]).one()
            assert (row.result or {}).get("replayed_over") == {
                "twin_snapshot_version": version}
        finally:
            fresh.close()
        fetched = client.get(
            f"/api/v1/technology-bom/cascade/runs/{posted['run_id']}").json()
        assert fetched["result"]["replayed_over"] == {
            "twin_snapshot_version": version}
        # and the history list carries it too — replay runs are identifiable
        # without fetching each one
        listed = client.get("/api/v1/technology-bom/cascade/runs").json()
        entry = next(r for r in listed["runs"] if r["id"] == posted["run_id"])
        assert entry["replayed_over"] == {"twin_snapshot_version": version}
        # replaying a version that was never captured is a 404
        missing = client.post("/api/v1/technology-bom/cascade",
                              params={"version": 999},
                              json={"target": "payment-api"})
        assert missing.status_code == 404


def test_algorithm_cascade_keeps_secondary_system_sharing_evidence(app_db):
    """One evidence record linked (via its crypto asset) to assets of two
    systems: the second system must not fall out of the blast radius."""
    session = app_db.state.test_session
    # ca-rsa already belongs to sys-pay; give the SAME asset to sys-db too
    session.add(SystemAsset(system_id="sys-db", asset_id="ca-rsa"))
    session.commit()
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "RSA-2048"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["target"]["kind"] == "algorithm"
    # evidence id appears once (deduped), but both owning systems survive
    assert len(body["layers"]["code"]["evidence_ids"]) == 1
    assert set(body["layers"]["code"]["systems"]) == {"sys-db", "sys-pay"}
    assert set(body["impact"]["affected_systems"]) >= {"sys-db", "sys-pay"}


def test_watch_run_due_flags_disappeared_target(app_db):
    """A watched target that has since left the estate is reported as
    missing — explicitly, not as an unexplained zero-impact answer."""
    with TestClient(app_db) as client:
        watch = client.post("/api/v1/technology-bom/cascade/watch",
                            json={"target": "payment-api", "kind": "system",
                                  "max_depth": 6}).json()
        assert watch["watched"] is True

        # first run-due: the target exists
        first = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()
        entry = first["watches"][0]
        assert entry["verdict"] == "AFFECTED"
        assert "target_missing" not in entry

        # the system leaves the estate
        session = app_db.state.test_session
        system = session.query(System).filter_by(id="sys-pay").one()
        session.delete(system)
        session.commit()

        second = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()
        entry = second["watches"][0]
        assert entry["verdict"] == "NOT_FOUND"
        assert entry["target_missing"] is True
        assert entry["affected_system_count"] == 0
        assert entry["run_id"]  # the disappearance is itself an auditable run
        # the blast radius collapsing to zero is reported as a change
        assert entry["blast_radius_changed"] is True
        assert entry["diff"]["removed"]  # the previous systems are named

        # a third run is stable: still missing, no crash, no repeated alert
        third = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()
        entry = third["watches"][0]
        assert entry["verdict"] == "NOT_FOUND"
        assert entry["target_missing"] is True
        assert "blast_radius_changed" not in entry

        # the watch stays active — the operator decides when to retire it
        listed = client.get("/api/v1/technology-bom/cascade/watches").json()
        assert listed["watches"][0]["active"] is True


# ------------------------------------------------------------ tenancy

@pytest.fixture()
def tenancy_session():
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
def tenants(tenancy_session):
    users = UserRepository(tenancy_session)
    users.create_user("acme_viewer", hash_password("x"), ["viewer"])
    tenancy_session.add(Tenant(id="acme", name="Acme Bank", slug="acme"))
    tenancy_session.add(Tenant(id="globex", name="Globex", slug="globex"))
    tenancy_session.add(TenantMembership(tenant_id="acme", username="acme_viewer",
                                         tenant_role="member"))
    tenancy_session.add_all([
        System(tenant_id="acme", id="sys-acme", name="Acme Core"),
        System(tenant_id="globex", id="sys-globex", name="Globex Core"),
        SystemDependency(tenant_id="acme", parent_id="sys-acme",
                         child_id="sys-acme-child"),
        SystemDependency(tenant_id="globex", parent_id="sys-globex",
                         child_id="sys-globex-child"),
        System(tenant_id="acme", id="sys-acme-child", name="Acme Child"),
        System(tenant_id="globex", id="sys-globex-child", name="Globex Child"),
    ])
    tenancy_session.commit()

    app = create_app()
    # the real production stack: TenantScopeMiddleware is the thing under test
    app.add_middleware(TenantScopeMiddleware)
    yield _login(tenancy_session, app, "acme_viewer"), app
    app.dependency_overrides.clear()


def test_cascade_never_names_another_tenants_systems(tenants):
    acme, _ = tenants
    resp = acme.post("/api/v1/technology-bom/cascade",
                     json={"target": "Acme Core"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "AFFECTED"
    assert body["layers"]["system"]["downstream_by_depth"] == {"1": ["sys-acme-child"]}
    # globex systems are invisible to this tenant — as dependents, as names,
    # anywhere in the answer
    assert "globex" not in resp.text.lower()


def test_run_history_is_tenant_scoped(tenants, tenancy_session):
    acme, app = tenants
    # a globex-owned run, written directly with the globex tenant stamp
    tenancy_session.add(CascadeRun(
        tenant_id="globex", target="Globex Core", target_kind="system",
        max_depth=6, verdict="AFFECTED",
        result={"impact": {"affected_system_count": 2}}))
    tenancy_session.commit()

    mine = acme.post("/api/v1/technology-bom/cascade",
                     json={"target": "Acme Core"}).json()
    listed = acme.get("/api/v1/technology-bom/cascade/runs").json()
    assert listed["count"] == 1
    assert listed["runs"][0]["id"] == mine["run_id"]
    assert all(r["target"] != "Globex Core" for r in listed["runs"])

    # and the globex run is not fetchable by id either — 404, never a leak
    globex_run = tenancy_session.query(CascadeRun).filter_by(
        tenant_id="globex").first()
    resp = acme.get(f"/api/v1/technology-bom/cascade/runs/{globex_run.id}")
    assert resp.status_code == 404


# ---------------------------------------------------- system CBOM real edges

def test_system_cbom_carries_real_estate_dependencies(app_db):
    """The system CBOM must carry registered edges, not a root fan-out.

    Regression guard for the wiring itself: if the router loses the
    build_estate_dependencies import/call, this fails with a NameError or a
    fan-out shape — either way it cannot pass silently again.
    """
    with TestClient(app_db) as client:
        resp = client.get("/api/v1/cbom/system/sys-pay")
    assert resp.status_code == 200
    bom = resp.json()
    deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    # the system depends on its crypto asset and its registered child system
    assert "ca-rsa" in deps["system:sys-pay"]
    assert "system:sys-db" in deps["system:sys-pay"]
    # the upstream caller keeps its true direction
    assert deps["system:sys-web"] == ["system:sys-pay"]
    props = {p["name"]: p["value"] for p in bom["metadata"].get("properties", [])}
    assert props.get("cryptoscan:dependencies") == "estate-linkage"
