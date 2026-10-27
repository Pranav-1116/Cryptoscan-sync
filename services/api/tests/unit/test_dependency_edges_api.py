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
    CryptoLiveState,
    EvidenceRecord,
    Scan,
    System,
    SystemAsset,
    SystemBusinessProcess,
    SystemDependency,
    SystemVendor,
    Vendor,
)
from db.models.graph_snapshot import GraphSnapshot
from db.models.hardware_live import HardwareAsset
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
        Vendor(id="vendor-chip", name="ChipWorks", criticality="MEDIUM",
               vendor_type="chip"),
        HardwareAsset(id="hw-1", asset_id="hsm-x", manufacturer="Thales",
                      model="Luna 7", device_type="hsm"),
        CryptoLiveState(asset_id="ca-shared", cbom_version=2,
                        algorithms={"RSA-2048": 4},
                        quantum_status={"status": "vulnerable"}),
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
                "paths": ["src/**"],
                "depends_on_systems": [],
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
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        resp = client.post("/api/v1/graph/edges", json={
            "parent_name": "web-frontend", "child_id": "sys-d",
            "relation": "CONTAINS"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["registered"] is True
    edge = body["edge"]
    assert edge["parent_id"] == "sys-a" and edge["child_id"] == "sys-d"
    assert edge["parent_name"] == "web-frontend"
    assert edge["child_name"] == "settlement"
    assert edge["relation"] == "CONTAINS"
    assert edge["source"] == "manual" and edge["created_by"] == "testuser"


def test_register_edge_rejects_unknown_system(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        resp = client.post("/api/v1/graph/edges", json={
            "parent_id": "nope", "child_id": "sys-d"})
    assert resp.status_code == 404


def test_register_edge_rejects_self_loop(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        resp = client.post("/api/v1/graph/edges", json={
            "parent_id": "sys-a", "child_id": "sys-a"})
    assert resp.status_code == 400


def test_register_edge_rejects_duplicate(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        first = client.post("/api/v1/graph/edges", json={
            "parent_id": "sys-a", "child_id": "sys-b"})
        assert first.status_code == 200
        dup = client.post("/api/v1/graph/edges", json={
            "parent_id": "sys-a", "child_id": "sys-b"})
    assert dup.status_code == 409


def test_list_edges_and_filters(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
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


def test_delete_retains_tombstone_and_rejects_stale_revision(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        resp = client.delete("/api/v1/graph/edges/sys-a/sys-c", params={"expected_revision": 0, "reason": "explicit operator retirement", "evidence_ref": "change/retire-1"})
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True
        again = client.delete("/api/v1/graph/edges/sys-a/sys-c", params={"expected_revision": 0, "reason": "explicit operator retirement", "evidence_ref": "change/retire-1"})
        listed = client.get("/api/v1/graph/edges").json()
    assert again.status_code == 409
    assert listed["count"] == 3
    assert next(e for e in listed["edges"] if e["parent_id"] == "sys-a")["effective_state"] == "DELETED"


def test_registered_edge_is_visible_in_blast_radius(app_db):
    """The write surface and the read surface must agree: register an edge,
    then see it in the walk."""
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
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
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
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
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        resp = client.get("/api/v1/graph/blast-radius",
                          params={"asset_id": "ca-unlinked"})
    assert resp.status_code == 404


def test_blast_radius_requires_a_start(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        resp = client.get("/api/v1/graph/blast-radius")
    assert resp.status_code == 400


# ------------------------------------------------------------ scan CBOM

def test_scan_cbom_carries_observed_cascade(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
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
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
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
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
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
    users.create_user("acme_viewer", hash_password("x"), ["security_analyst"])
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
    resp = acme.delete("/api/v1/graph/edges/sys-globex/sys-globex-2", params={"expected_revision": 0, "reason": "retire", "evidence_ref": "change/1"})
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
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "Card Payments"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["target"]["kind"] == "process"
    assert body["layers"]["system"]["systems"] == ["sys-c"]
    # both registered callers appear in modeled consumer exposure
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
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        resp = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "payment-core"})
    body = resp.json()
    assert body["impact"]["migration_waves"] == {
        "1": ["sys-a"], "2": ["sys-b", "sys-c"], "3": ["sys-d"]}


def test_cascade_run_diff_shows_blast_radius_change(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        first = client.post("/api/v1/technology-bom/cascade",
                            json={"target": "payment-core"}).json()
        # the blast radius shrinks: web-frontend stops calling payment-core
        client.delete("/api/v1/graph/edges/sys-a/sys-c", params={"expected_revision": 0, "reason": "explicit operator retirement", "evidence_ref": "change/retire-1"})
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
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
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
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        run_a = client.post("/api/v1/technology-bom/cascade",
                            json={"target": "payment-core"}).json()
        run_b = client.post("/api/v1/technology-bom/cascade",
                            json={"target": "Card Payments"}).json()
        resp = client.get(
            f"/api/v1/technology-bom/cascade/runs/{run_a['run_id']}/diff",
            params={"against": run_b["run_id"]})
    assert resp.status_code == 400


def test_cascade_run_diff_needs_an_earlier_run(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        only = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "settlement"}).json()
        resp = client.get(
            f"/api/v1/technology-bom/cascade/runs/{only['run_id']}/diff")
    assert resp.status_code == 404


# ------------------------------------------- round-4: internal missing parts

def test_edge_provenance_recorded(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        resp = client.post("/api/v1/graph/edges", json={
            "parent_id": "sys-a", "child_id": "sys-b",
            "relation": "CALLS", "confidence": 0.9})
        assert resp.status_code == 200
        edge = resp.json()["edge"]
        assert edge["source"] == "manual"
        assert edge["created_by"] == "testuser"
        assert edge["confidence"] == 0.9
        assert edge["last_verified"]  # manual registration self-verifies
        listed = client.get("/api/v1/graph/edges").json()
        assert listed["edges"][0]["source"] == "manual"


def test_hardware_links_and_device_cascade_end_to_end(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        # before: device cascade is inventory-only
        before = client.post("/api/v1/technology-bom/cascade",
                             json={"target": "hsm-x"}).json()
        assert before["layers"]["hardware"]["inventory_only"] is True
        assert any("declare one" in u for u in before["honest_unknowns"])

        # declare the link the cascade needs
        resp = client.post("/api/v1/graph/hardware-links", json={
            "asset_id": "ca-shared", "hardware_asset_id": "hsm-x",
            "note": "payment keys live on Luna 7"})
        assert resp.status_code == 200
        # validation: unknown asset / device, duplicate
        assert client.post("/api/v1/graph/hardware-links", json={
            "asset_id": "nope", "hardware_asset_id": "hsm-x"}).status_code == 404
        assert client.post("/api/v1/graph/hardware-links", json={
            "asset_id": "ca-shared", "hardware_asset_id": "nope"}).status_code == 404
        assert client.post("/api/v1/graph/hardware-links", json={
            "asset_id": "ca-shared", "hardware_asset_id": "hsm-x"}).status_code == 409

        # settlement calls web-frontend: when the device dies, the systems
        # using it stop, and so does everyone calling THEM
        client.post("/api/v1/graph/edges", json={
            "parent_id": "sys-d", "child_id": "sys-a"})

        # after: the device cascade names its systems and dependents
        after = client.post("/api/v1/technology-bom/cascade",
                            json={"target": "hsm-x"}).json()
        assert after["layers"]["hardware"]["inventory_only"] is False
        assert sorted(after["layers"]["code"]["systems"]) == ["sys-a", "sys-b"]
        # transitively: settlement calls web-frontend, payment-core calls settlement
        assert after["layers"]["system"]["dependents_by_depth"] == {
            "1": ["sys-d"], "2": ["sys-c"]}
        assert not any("declare one" in u for u in after["honest_unknowns"])

        links = client.get("/api/v1/graph/hardware-links").json()
        assert links["count"] == 1
        assert links["links"][0]["note"] == "payment keys live on Luna 7"


def test_vendor_edges_and_sub_tier_cascade(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        resp = client.post("/api/v1/graph/vendor-edges", json={
            "parent_vendor_name": "Thales", "child_vendor_name": "ChipWorks",
            "relation": "supplies"})
        assert resp.status_code == 200
        assert resp.json()["parent_vendor_id"] == "vendor-thales"
        # duplicate + unknown vendor
        assert client.post("/api/v1/graph/vendor-edges", json={
            "parent_vendor_id": "vendor-thales",
            "child_vendor_id": "vendor-chip"}).status_code == 409
        assert client.post("/api/v1/graph/vendor-edges", json={
            "parent_vendor_id": "vendor-thales",
            "child_vendor_id": "nope"}).status_code == 404

        cascade = client.post("/api/v1/technology-bom/cascade",
                              json={"target": "Thales"}).json()
        assert cascade["layers"]["vendor"]["sub_tier_vendors_by_depth"] == {
            "1": ["vendor-chip"]}
        assert not any("vendor-of-vendor" in u
                       for u in cascade["honest_unknowns"])
        listed = client.get("/api/v1/graph/vendor-edges").json()
        assert listed["edges"][0]["child_vendor"] == "ChipWorks"


def test_discovered_edges_and_adoption(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        session = app_db.state.test_session
        # this scan declares payment-core imports crypto from web-frontend
        # (and names a system that does not exist — reported, never guessed)
        session.add(Scan(id="scan-2", scanner_version="1.0.0",
                         scan_start=NOW, scan_end=NOW,
                         target_location="https://example/bank2",
                         status="COMPLETED",
                         statistics={"cascade": {"systems": [{
                             "system": "payment-core", "criticality": "TIER-1",
                             "paths": ["src/**"],
                             "depends_on_systems": ["web-frontend",
                                                    "ghost-system"]}]}}))
        session.commit()
        # a captured graph snapshot contributes candidates too
        session.add(GraphSnapshot(version=1, fingerprint="f" * 64,
                                  node_count=2, edge_count=1,
                                  nodes=[], edges_by_relation={},
                                  nodes_by_kind={},
                                  edges=[{"from": "sys-a", "to": "sys-d",
                                          "label": "CALLS"}]))
        session.commit()

        discovered = client.get("/api/v1/graph/edges/discovered").json()
        pairs = {(p["parent_id"], p["child_id"]) for p in discovered["proposals"]}
        # scanner cascade: payment-core depends on web-frontend (unresolved
        # ghost-system reported honestly)
        assert ("sys-c", "sys-a") in pairs
        # graph snapshot: sys-a → sys-d (not yet a registered edge)
        assert ("sys-a", "sys-d") in pairs
        assert "ghost-system" in discovered["unresolved_names"]
        # already-registered edges are not proposed
        assert ("sys-a", "sys-c") not in pairs

        # adopt one; the duplicate is skipped with a reason
        adopt = client.post("/api/v1/graph/edges/adopt", json={
            "edges": [{"parent_id": "sys-c", "child_id": "sys-a",
                       "confidence": 0.8},
                      {"parent_id": "sys-a", "child_id": "sys-c"}]})
        assert adopt.status_code == 200
        body = adopt.json()
        assert body["adopted_count"] == 1
        assert body["adopted"][0]["source"] == "discovered"
        assert body["adopted"][0]["confidence"] == 0.8
        assert body["skipped"][0]["reason"] == "already registered"

        # adopted edge is live in the graph and carries provenance
        listed = client.get("/api/v1/graph/edges",
                            params={"system_id": "sys-c"}).json()
        adopted_edge = next(e for e in listed["edges"]
                            if e["parent_id"] == "sys-c" and e["child_id"] == "sys-a")
        assert adopted_edge["source"] == "discovered"


def test_twin_snapshots_and_version_replay(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        first = client.post("/api/v1/digital-twin/snapshot").json()
        assert first["recorded"] is True and first["version"] == 1
        # unchanged estate → no duplicate version
        again = client.post("/api/v1/digital-twin/snapshot").json()
        assert again["recorded"] is False and again["version"] == 1

        listed = client.get("/api/v1/digital-twin/snapshots").json()
        assert listed["count"] == 1
        got = client.get("/api/v1/digital-twin/snapshots/1").json()
        assert got["state"]["systems"]
        assert client.get("/api/v1/digital-twin/snapshots/9").status_code == 404

        # the estate changes after capture…
        client.delete("/api/v1/graph/edges/sys-a/sys-c", params={"expected_revision": 0, "reason": "explicit operator retirement", "evidence_ref": "change/retire-1"})
        live = client.post("/api/v1/technology-bom/cascade",
                           json={"target": "payment-core"}).json()
        assert "sys-a" not in live["impact"]["affected_systems"]
        # …but the replay over v1 still answers for the estate as captured
        replay = client.post("/api/v1/technology-bom/cascade",
                             params={"version": 1},
                             json={"target": "payment-core"}).json()
        assert replay["replayed_over"]["twin_snapshot_version"] == 1
        assert replay["replayed_over"]["clock_source"] == "snapshot_capture"
        assert replay["as_of"] == replay["replayed_over"]["evaluation_clock"]
        assert "sys-a" in replay["impact"]["affected_systems"]
        assert client.post("/api/v1/technology-bom/cascade",
                           params={"version": 9},
                           json={"target": "payment-core"}).status_code == 404


def test_watches_run_due_and_blast_radius_change(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        created = client.post("/api/v1/technology-bom/cascade/watch",
                              json={"target": "payment-core"}).json()
        assert created["watched"] is True
        listed = client.get("/api/v1/technology-bom/cascade/watches").json()
        assert listed["count"] == 1

        # first run: no previous answer, no diff
        first = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()
        assert first["ran"] == 1
        assert first["watches"][0]["verdict"]
        assert "diff" not in first["watches"][0]

        # the blast radius shrinks; the next run-due must report it
        client.delete("/api/v1/graph/edges/sys-a/sys-c", params={"expected_revision": 0, "reason": "explicit operator retirement", "evidence_ref": "change/retire-1"})
        second = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()
        entry = second["watches"][0]
        assert entry["diff"] == {"added": [], "removed": ["sys-a"]}
        assert entry["blast_radius_changed"] is True

        # the watch now points at the latest run
        watches = client.get("/api/v1/technology-bom/cascade/watches").json()
        assert watches["watches"][0]["last_run_id"] == entry["run_id"]
        # cleanup
        assert client.delete(
            f"/api/v1/technology-bom/cascade/watch/{created['id']}").json()["deleted"]


def test_evidence_package_includes_cascade_runs(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        client.post("/api/v1/technology-bom/cascade",
                    json={"target": "payment-core"})
        package = client.get("/api/v1/technology-bom/evidence-package").json()
        assert package["cascade_runs"]
        run = package["cascade_runs"][0]
        assert run["target"] == "payment-core"
        assert len(run["result_sha256"]) == 64
        # the package hash covers the cascade section
        assert len(package["content_sha256"]) == 64


def test_diff_covers_all_layers(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        # the first answer exists so the diff has a baseline to compare to
        client.post("/api/v1/technology-bom/cascade",
                    json={"target": "payment-core"})
        client.delete("/api/v1/graph/edges/sys-a/sys-c", params={"expected_revision": 0, "reason": "explicit operator retirement", "evidence_ref": "change/retire-1"})
        second = client.post("/api/v1/technology-bom/cascade",
                             json={"target": "payment-core"}).json()
        diff = client.get(
            f"/api/v1/technology-bom/cascade/runs/{second['run_id']}/diff"
        ).json()
        assert diff["affected_systems"]["removed"] == ["sys-a"]
        for section in ("network_endpoints", "hardware_devices",
                        "vendors", "code_evidence"):
            assert section in diff
            assert {"added", "removed", "before", "after"} <= set(diff[section])


def test_diff_is_tenant_scoped(tenants, tenancy_session):
    """A tenant cannot diff against another tenant's run — 404, never a leak."""
    from db.models.cascade_run import CascadeRun

    acme = tenants
    tenancy_session.add(CascadeRun(
        tenant_id="globex", target="Globex Core", target_kind="system",
        max_depth=6, verdict="AFFECTED", result={"impact": {"affected_systems": ["sys-globex"]}}))
    tenancy_session.commit()
    mine = acme.post("/api/v1/technology-bom/cascade",
                     json={"target": "Acme Core"}).json()
    globex_run = tenancy_session.query(CascadeRun).filter_by(
        tenant_id="globex").first()
    resp = acme.get(
        f"/api/v1/technology-bom/cascade/runs/{mine['run_id']}/diff",
        params={"against": globex_run.id})
    assert resp.status_code == 404


def test_relationship_evidence_survives_sql_graph_and_twin_cascade(app_db):
    app, session = app_db, app_db.state.test_session
    from api.routers.digital_twin import _snapshot
    from cbom.unified_cascade import unified_cascade
    with TestClient(app, headers={"Authorization": "Bearer test-token"}) as client:
        response = client.post("/api/v1/graph/edges", json={
            "parent_id": "sys-d", "child_id": "sys-a", "source": "imported", "confidence": .7,
            "evidence_ref": "change:bank-42", "confidence_meaning": "operator-reviewed dependency assertion"})
        assert response.status_code == 200
        row = response.json()["edge"]
        assert row["evidence_ref"] == "change:bank-42"
        radius = client.get("/api/v1/graph/blast-radius", params={"system_id": "sys-d", "hops": 1}).json()
        path = radius["traversal_evidence"]["paths"][0]
        assert path["edges"][0]["provenance"] == "DECLARED"
        assert path["edges"][0]["evidence_references"] == ["change:bank-42"]
    snapshot = _snapshot(session)
    answer = unified_cascade(snapshot, target="sys-a", kind="system", now=NOW)
    edge = next(p for p in answer["traversal_evidence"]["dependent_consumers"]["paths"] if p["system_id"] == "sys-d")["edges"][0]
    assert edge["source"] == "imported" and edge["confidence"] == .7
    assert edge["confidence_meaning"] == "operator-reviewed dependency assertion"
    assert edge["freshness"]["observation"]["status"] == "MISSING"


def test_asset_detection_confidence_never_verifies_relationship():
    from api.routers.graph import _edge_evidence
    from graph_engine.core.engine import GraphEngine
    graph = GraphEngine().build(systems=[{"id": "pay"}], assets=[{"id": "key", "algorithm": "RSA", "system_id": "pay", "confidence": "HIGH"}])
    result = _edge_evidence(graph, {"from": "system:pay", "to": "asset:key", "label": "USES", "confidence": .2}, {})
    assert result["confidence"] == .2 and result["asset_detection_confidence"] == "HIGH"
    assert not result["verified"] and not result["references_verified_by_traversal"]
    assert result["first_seen"] is None and result["last_seen"] is None


def test_asset_start_union_keeps_witnesses_and_actual_join_record_ids(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        response = client.get("/api/v1/graph/blast-radius", params={"asset_id": "ca-shared"})
    assert response.status_code == 200
    result = response.json()
    assert result["traversal_evidence"]["requested_count"] == len(result["systems"])
    assert result["traversal_evidence"]["complete_for_requested_systems"]
    assert {e["from"] for e in result["start_links"]["edges"]} == {"sys-a", "sys-b"}
    assert all(e["record_id"] and e["evidence_missing"] and not e["references_verified_by_traversal"] for e in result["start_links"]["edges"])


def test_process_projection_closes_all_scopes_keeps_mapping_ids_and_history(app_db):
    from copy import deepcopy
    from db.models.cascade_run import CascadeRun
    db = app_db.state.test_session
    existing = db.query(BusinessProcess).filter_by(id="bp-1").one()
    existing.revenue_daily = 100
    existing.customer_count = 10
    db.add_all([BusinessProcess(id="bp-consumer", name="Online Banking", revenue_daily=100, customer_count=10),
        BusinessProcess(id="bp-context", name="Settlement Review", revenue_daily=9999, customer_count=999)])
    db.flush()
    db.add_all([SystemBusinessProcess(id="support-consumer", system_id="sys-a", process_id="bp-consumer", role="FRONTEND"),
        SystemBusinessProcess(id="support-shared", system_id="sys-a", process_id="bp-1", role="CHANNEL"),
        SystemBusinessProcess(id="support-context", system_id="sys-d", process_id="bp-context", role="SUPPORT")])
    db.commit()
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        response = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-core"})
        assert response.status_code == 200
        answer = response.json()
        projection = answer["impact"]["process_impact"]
        assert projection["counts"] == {"review": 3, "exposure": 2, "context_only": 1, "potential_only": 0}
        reason = next(r for p in projection["processes"] if p["id"] == "bp-1" for r in p["reasons"] if r["system_id"] == "sys-a")
        assert reason["role"] == "CHANNEL" and reason["support_link"]["record_id"] == "support-shared"
        assert reason["support_link"]["freshness"]["observation"]["status"] == "MISSING"
        graph = client.get("/api/v1/graph/impact", params={"system_id": "sys-c"}).json()
        assert graph["process_impact"]["counts"] == projection["counts"]
        assert graph["total_revenue_at_risk"] == 200 and graph["total_customers_at_risk"] == 20
        saved = deepcopy(db.query(CascadeRun).filter_by(id=answer["run_id"]).one().result)
        db.add(BusinessProcess(id="bp-later", name="Later Process"))
        db.flush()
        db.add(SystemBusinessProcess(system_id="sys-b", process_id="bp-later"))
        db.commit()
        later = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-core"}).json()
        assert later["impact"]["process_impact"]["counts"]["review"] == 4
        assert db.query(CascadeRun).filter_by(id=answer["run_id"]).one().result == saved
        diff = client.get(f"/api/v1/technology-bom/cascade/runs/{later['run_id']}/diff", params={"against": answer["run_id"]}).json()
        assert diff["process_comparison"]["comparable"]
        assert diff["affected_processes"]["added"] == ["bp-later"]


def test_legacy_process_comparison_is_explicitly_unavailable(app_db):
    from copy import deepcopy
    from db.models.cascade_run import CascadeRun
    db = app_db.state.test_session
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        answer = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-core"}).json()
        legacy = deepcopy(answer)
        del legacy["impact"]["process_impact"]
        db.add(CascadeRun(id="legacy-process-run", target="payment-core", target_kind="system", verdict="AFFECTED", result=legacy))
        db.commit()
        response = client.get(f"/api/v1/technology-bom/cascade/runs/{answer['run_id']}/diff", params={"against": "legacy-process-run"})
        assert response.status_code == 200
        assert not response.json()["process_comparison"]["comparable"]
        assert "legacy" in response.json()["process_comparison"]["reason"]
        assert "process_impact" not in db.query(CascadeRun).filter_by(id="legacy-process-run").one().result["impact"]


def test_process_source_caps_are_disclosed_and_unregistered_targets_not_invented(app_db, monkeypatch):
    import api.routers.digital_twin as twin
    db = app_db.state.test_session
    db.add(BusinessProcess(id="another-process", name="Another Process"))
    db.flush()
    db.add(SystemBusinessProcess(system_id="sys-a", process_id="another-process"))
    db.commit()
    monkeypatch.setitem(twin.SNAPSHOT_CAPS, "business_processes", 1)
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        answer = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-core"}).json()
    coverage = answer["impact"]["process_impact"]["coverage"]
    assert coverage["source_coverage"]["processes_truncated"]
    assert coverage["source_coverage"]["support_links_truncated"]
    assert {p["id"] for p in answer["impact"]["process_impact"]["processes"]} <= {"another-process"}


def test_graph_wrappers_keep_process_explanations_and_economic_qualification(app_db):
    with TestClient(app_db, headers={"Authorization": "Bearer test-token"}) as client:
        simulation = client.post("/api/v1/graph/simulate", json={"node_id": "sys-c"})
        explanation = client.get("/api/v1/graph/explain", params={"node_id": "sys-c"})
    assert simulation.status_code == explanation.status_code == 200
    assert simulation.json()["process_impact"]["schema"] == "cryptoscan.business-process-impact/1"
    assert "not predicted losses" in simulation.json()["economic_totals_meaning"]
    assert explanation.json()["process_impact"]["counts"]["exposure"] == 1
    assert any("not predicted loss" in s.get("detail", "") for s in explanation.json()["steps"])
