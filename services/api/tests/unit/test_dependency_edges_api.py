"""Dependency-edge management + asset-level blast radius + scan CBOM edges.

The graph's read side (blast radius, impact, cascade) was already real; this
file proves the parts that were missing:

- edges could not be registered, listed or removed through the API at all —
  everything downstream read a table nothing could write
- blast radius started only from systems; a shared crypto asset breaks every
  system that uses it
- the scan CBOM ignored the scanner's observed cascade that the export
  already rendered
- the twin snapshot now feeds the cascade real CertificateUsage links,
  business processes, vendor crypto inventory and the library catalog
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
from db.connection.session import Base, SessionLocal, configure_session
from db.models import (
    BusinessProcess,
    Certificate,
    CertificateUsage,
    CryptoAsset,
    EvidenceRecord,
    Scan,
    System,
    SystemAsset,
    SystemBusinessProcess,
    SystemDependency,
    SystemVendor,
    Vendor,
)
from db.models.vendor_crypto import VendorCryptoInventory
from db.models.tenant import Tenant, TenantMembership
from db.repositories.user_repository import UserRepository

NOW = datetime.now(timezone.utc)


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

    session.add_all([
        System(id="sys-a", name="web-frontend", criticality="TIER-1",
               migration_readiness_category="READY_NOW"),
        System(id="sys-b", name="mobile-gateway", criticality="TIER-1",
               migration_readiness_category="NOT_READY"),
        System(id="sys-c", name="payment-core", criticality="TIER-1",
               migration_readiness_category="READY_WITH_PREP"),
        System(id="sys-d", name="settlement", criticality="TIER-2",
               migration_readiness_category="BLOCKED"),
        CryptoAsset(id="ca-shared", algorithm="RSA-2048",
                    file_path="src/KeyStore.java", purpose="signing",
                    key_size=2048, confidence=1.0),
        Vendor(id="vendor-thales", name="Thales", criticality="HIGH",
               vendor_type="hsm"),
        BusinessProcess(id="bp-1", name="Card Payments"),
        Certificate(fingerprint_sha256="ab" * 32, subject="CN=payment-core",
                    not_after=NOW + timedelta(days=200)),
    ])
    session.flush()
    session.add_all([
        SystemAsset(system_id="sys-a", asset_id="ca-shared"),
        SystemAsset(system_id="sys-b", asset_id="ca-shared"),
        SystemDependency(parent_id="sys-a", child_id="sys-c", relation="CALLS"),
        SystemDependency(parent_id="sys-b", child_id="sys-c", relation="CALLS"),
        SystemDependency(parent_id="sys-c", child_id="sys-d", relation="CALLS"),
        SystemVendor(id="sv-1", system_id="sys-c", vendor_id="vendor-thales",
                     dependency_type="runtime"),
        SystemBusinessProcess(system_id="sys-c", process_id="bp-1"),
        CertificateUsage(fingerprint_sha256="ab" * 32, usage_type="TLS_SERVER",
                         location="system:sys-c"),
        VendorCryptoInventory(vendor_id="vendor-thales", algorithm="RSA-2048",
                              key_size=2048, pqc_ready=False,
                              crypto_use_case="HSM signing"),
    ])
    # a completed scan carrying the scanner's observed cascade
    scan = Scan(id="scan-1", scanner_version="1.0.0",
                scan_start=NOW, scan_end=NOW,
                target_location="https://example/bank", target_commit="deadbeef",
                status="COMPLETED")
    scan.statistics = {
        "cascade": {
            "providers": [{
                "file": "src/KeyStore.java", "wave": 2,
                "direct_dependents": 3, "transitive_dependents": 5,
                "algorithms": ["RSA-2048"], "depends_on_providers": [],
            }],
            "systems": [{
                "system": "payment-core", "criticality": "TIER-1",
                "paths": ["src/**"], "depends_on_systems": [],
            }],
        },
    }
    session.add(scan)
    session.add(EvidenceRecord(
        id="ev-1", scan_id="scan-1", content_hash="a" * 64, chain_hash="",
        chain_position=0, algorithm="RSA-2048", file_path="src/KeyStore.java",
        line_number=1, finding_data={}))
    session.commit()
    try:
        yield application
    finally:
        session.close()
        engine.dispose()


# ------------------------------------------------------------ edge CRUD

def test_register_edge_by_name_and_id(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/graph/edges", json={
            "parent_name": "web-frontend", "child_id": "sys-d",
            "relation": "CONTAINS"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["registered"] is True
    assert body["edge"] == {"parent_id": "sys-a", "child_id": "sys-d",
                            "parent_name": "web-frontend",
                            "child_name": "settlement", "relation": "CONTAINS"}


def test_register_edge_rejects_unknown_system(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/graph/edges", json={
            "parent_id": "nope", "child_id": "sys-d"})
    assert resp.status_code == 404


def test_register_edge_rejects_self_loop(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/graph/edges", json={
            "parent_id": "sys-a", "child_id": "sys-a"})
    assert resp.status_code == 400


def test_register_edge_rejects_duplicate(app_db):
    with TestClient(app_db) as client:
        first = client.post("/api/v1/graph/edges", json={
            "parent_id": "sys-a", "child_id": "sys-b"})
        assert first.status_code == 200
        dup = client.post("/api/v1/graph/edges", json={
            "parent_id": "sys-a", "child_id": "sys-b"})
    assert dup.status_code == 409


def test_list_edges_and_filters(app_db):
    with TestClient(app_db) as client:
        listed = client.get("/api/v1/graph/edges").json()
        assert listed["count"] == 3
        by_system = client.get(
            "/api/v1/graph/edges", params={"system_id": "sys-c"}).json()
        # edges touching sys-c either way: two incoming, one outgoing
        pairs = {(e["parent_id"], e["child_id"]) for e in by_system["edges"]}
        assert pairs == {("sys-a", "sys-c"), ("sys-b", "sys-c"),
                         ("sys-c", "sys-d")}
        by_relation = client.get(
            "/api/v1/graph/edges", params={"relation": "CALLS"}).json()
        assert by_relation["count"] == 3


def test_delete_edge_and_404_on_missing(app_db):
    with TestClient(app_db) as client:
        resp = client.delete("/api/v1/graph/edges/sys-a/sys-c")
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True
        again = client.delete("/api/v1/graph/edges/sys-a/sys-c")
        listed = client.get("/api/v1/graph/edges").json()
    assert again.status_code == 404
    assert listed["count"] == 2


def test_registered_edge_is_visible_in_blast_radius(app_db):
    """The write surface and the read surface must agree: register an edge,
    then see it in the walk."""
    with TestClient(app_db) as client:
        client.post("/api/v1/graph/edges", json={
            "parent_id": "sys-a", "child_id": "sys-b"})
        radius = client.get("/api/v1/graph/blast-radius",
                            params={"system_id": "sys-a", "hops": 3}).json()
    names = {s["name"] for s in radius["systems"]}
    assert "mobile-gateway" in names  # the edge just registered
    assert "payment-core" in names
    assert "settlement" in names


# ------------------------------------------------------------ asset radius

def test_blast_radius_from_shared_asset_unions_owners(app_db):
    with TestClient(app_db) as client:
        resp = client.get("/api/v1/graph/blast-radius",
                          params={"asset_id": "ca-shared", "hops": 3})
    assert resp.status_code == 200
    body = resp.json()
    assert body["start_kind"] == "asset"
    assert body["owning_systems"] == ["sys-a", "sys-b"]
    by_name = {s["name"]: s["hops"] for s in body["systems"]}
    # payment-core is one hop from either owner; settlement two
    assert by_name == {"payment-core": 1, "settlement": 2}


def test_blast_radius_from_unlinked_asset_is_404(app_db):
    with TestClient(app_db) as client:
        resp = client.get("/api/v1/graph/blast-radius",
                          params={"asset_id": "ca-unlinked"})
    assert resp.status_code == 404


def test_blast_radius_requires_a_start(app_db):
    with TestClient(app_db) as client:
        resp = client.get("/api/v1/graph/blast-radius")
    assert resp.status_code == 400


# ------------------------------------------------------------ scan CBOM

def test_scan_cbom_carries_observed_cascade(app_db):
    with TestClient(app_db) as client:
        resp = client.get("/api/v1/cbom/scan/scan-1")
    assert resp.status_code == 200
    bom = resp.json()
    deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    # the root depends on the business system, which depends on the provider file
    assert "root:scan-1" in deps
    assert "system:payment-core" in deps
    assert "file:src/KeyStore.java" in deps
    refs = {c["bom-ref"] for c in bom["components"]}
    refs.add(bom["metadata"]["component"].get("bom-ref"))
    # every dependency ref resolves: components list or the metadata root
    for ref in deps:
        assert ref in refs, ref
    props = {p["name"]: p["value"] for p in bom["metadata"].get("properties", [])}
    assert props.get("cryptoscan:dependencies") == "scan-cascade"
    file_comp = next(c for c in bom["components"]
                     if c.get("bom-ref") == "file:src/KeyStore.java")
    wave = {p["name"]: p["value"] for p in file_comp.get("properties", [])}
    assert wave["cryptoscan:cascade:wave"] == "2"
    assert wave["cryptoscan:cascade:transitive_dependents"] == "5"


# ------------------------------------------------- twin feeds the cascade

def test_twin_snapshot_carries_new_real_feeds(app_db):
    from api.routers.digital_twin import _snapshot

    snapshot = _snapshot(app_db.state.test_session)
    assert snapshot["certificate_usages"] == {"ab" * 32: ["sys-c"]}
    assert snapshot["business_processes"]["sys-c"][0]["name"] == "Card Payments"
    assert snapshot["vendor_crypto"]["vendor-thales"][0]["pqc_ready"] is False
    # the fingerprint catalog is consulted for the estate's own libraries;
    # none are named here, so the catalog section is present but empty
    assert isinstance(snapshot["library_catalog"], dict)


def test_certificate_cascade_names_system_from_usage(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "ab" * 32})
    assert resp.status_code == 200
    body = resp.json()
    assert body["target"]["kind"] == "certificate"
    assert body["layers"]["system"]["systems"] == ["sys-c"]
    assert body["layers"]["process"]["processes"] == [
        {"id": "bp-1", "name": "Card Payments"}]
    assert body["impact"]["affected_processes"] == [
        {"id": "bp-1", "name": "Card Payments"}]


def test_system_cascade_names_vendor_crypto(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "payment-core"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["layers"]["vendor"]["vendors"] == ["Thales"]
    assert body["layers"]["process"]["processes"][0]["name"] == "Card Payments"


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
    tenancy_session.add(TenantMembership(tenant_id="acme",
                                         username="acme_viewer",
                                         tenant_role="member"))
    tenancy_session.add_all([
        System(tenant_id="acme", id="sys-acme", name="Acme Core"),
        System(tenant_id="acme", id="sys-acme-2", name="Acme Ledger"),
        System(tenant_id="globex", id="sys-globex", name="Globex Core"),
        System(tenant_id="globex", id="sys-globex-2", name="Globex Ledger"),
    ])
    tenancy_session.commit()

    app = create_app()
    app.add_middleware(TenantScopeMiddleware)
    yield _login(tenancy_session, app, "acme_viewer")
    app.dependency_overrides.clear()


def test_edges_are_tenant_scoped(tenants, tenancy_session):
    acme = tenants
    # acme registers its own edge; globex has one seeded directly
    tenancy_session.add(SystemDependency(tenant_id="globex",
                                         parent_id="sys-globex",
                                         child_id="sys-globex-2"))
    tenancy_session.commit()

    resp = acme.post("/api/v1/graph/edges", json={
        "parent_id": "sys-acme", "child_id": "sys-acme-2"})
    assert resp.status_code == 200

    listed = acme.get("/api/v1/graph/edges").json()
    assert listed["count"] == 1
    assert listed["edges"][0]["parent_id"] == "sys-acme"
    # globex's edge is invisible — in the list and by direct delete
    assert all("globex" not in str(e).lower() for e in listed["edges"])
    resp = acme.delete("/api/v1/graph/edges/sys-globex/sys-globex-2")
    assert resp.status_code == 404

    # and the new edge is stamped to the acme tenant, not the platform
    row = tenancy_session.query(SystemDependency).filter_by(
        parent_id="sys-acme").one()
    assert row.tenant_id == "acme"


def test_tenant_cannot_register_cross_tenant_edge(tenants):
    acme = tenants
    # parent is acme's, child is globex's — the child must not resolve
    resp = acme.post("/api/v1/graph/edges", json={
        "parent_id": "sys-acme", "child_id": "sys-globex-2"})
    assert resp.status_code == 404


# ------------------------------------------------- round-3: process, waves, diff

def test_process_cascade_end_to_end(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "Card Payments"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["target"]["kind"] == "process"
    assert body["layers"]["system"]["systems"] == ["sys-c"]
    # both callers of payment-core stop with it
    assert body["layers"]["system"]["dependents_by_depth"] == {
        "1": ["sys-a", "sys-b"]}
    assert set(body["impact"]["affected_systems"]) == {"sys-a", "sys-b", "sys-c"}
    assert body["layers"]["vendor"]["vendors"] == ["Thales"]


def test_twin_systems_carry_migration_wave(app_db):
    from api.routers.digital_twin import _snapshot

    snapshot = _snapshot(app_db.state.test_session)
    waves = {s["id"]: s["migration_wave"] for s in snapshot["systems"]}
    assert waves == {"sys-a": 1, "sys-b": 2, "sys-c": 2, "sys-d": 3}


def test_cascade_impact_groups_migration_waves(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "payment-core"})
    body = resp.json()
    assert body["impact"]["migration_waves"] == {
        "1": ["sys-a"], "2": ["sys-b", "sys-c"], "3": ["sys-d"]}


def test_cascade_run_diff_shows_blast_radius_change(app_db):
    with TestClient(app_db) as client:
        first = client.post("/api/v1/technology-bom/cascade",
                            json={"target": "payment-core"}).json()
        # the blast radius shrinks: web-frontend stops calling payment-core
        client.delete("/api/v1/graph/edges/sys-a/sys-c")
        second = client.post("/api/v1/technology-bom/cascade",
                             json={"target": "payment-core"}).json()
        diff = client.get(
            f"/api/v1/technology-bom/cascade/runs/{second['run_id']}/diff"
        ).json()
    assert diff["target"] == "payment-core"
    assert diff["against"]["id"] == first["run_id"]
    assert diff["affected_systems"]["removed"] == ["sys-a"]
    assert diff["affected_systems"]["added"] == []
    assert diff["affected_systems"]["before"] == 4
    assert diff["affected_systems"]["after"] == 3
    assert diff["verdict_changed"] is False


def test_cascade_run_diff_explicit_against(app_db):
    with TestClient(app_db) as client:
        first = client.post("/api/v1/technology-bom/cascade",
                            json={"target": "payment-core"}).json()
        second = client.post("/api/v1/technology-bom/cascade",
                             json={"target": "payment-core"}).json()
        diff = client.get(
            f"/api/v1/technology-bom/cascade/runs/{second['run_id']}/diff",
            params={"against": first["run_id"]}).json()
    assert diff["affected_systems"]["removed"] == []
    assert diff["affected_systems"]["added"] == []
    assert diff["affected_systems"]["unchanged_count"] == 4


def test_cascade_run_diff_rejects_different_targets(app_db):
    with TestClient(app_db) as client:
        run_a = client.post("/api/v1/technology-bom/cascade",
                            json={"target": "payment-core"}).json()
        run_b = client.post("/api/v1/technology-bom/cascade",
                            json={"target": "Card Payments"}).json()
        resp = client.get(
            f"/api/v1/technology-bom/cascade/runs/{run_a['run_id']}/diff",
            params={"against": run_b["run_id"]})
    assert resp.status_code == 400


def test_cascade_run_diff_needs_an_earlier_run(app_db):
    with TestClient(app_db) as client:
        only = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "settlement"}).json()
        resp = client.get(
            f"/api/v1/technology-bom/cascade/runs/{only['run_id']}/diff")
    assert resp.status_code == 404
