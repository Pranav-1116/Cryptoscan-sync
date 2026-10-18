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
        assert posted["replayed_over"]["twin_snapshot_version"] == version
        assert posted["replayed_over"]["clock_source"] == "snapshot_capture"

        # ...and so does the persisted audit trail — read the row back from
        # the database (a fresh session, not the request session's identity
        # map, which would hand back the same mutated dict)
        from sqlalchemy.orm import sessionmaker

        fresh = sessionmaker(bind=app_db.state.test_session.get_bind(),
                             expire_on_commit=False)()
        try:
            row = fresh.query(CascadeRun).filter(
                CascadeRun.id == posted["run_id"]).one()
            assert (row.result or {}).get("replayed_over") == posted["replayed_over"]
        finally:
            fresh.close()
        fetched = client.get(
            f"/api/v1/technology-bom/cascade/runs/{posted['run_id']}").json()
        assert fetched["result"]["replayed_over"] == posted["replayed_over"]
        # and the history list carries it too — replay runs are identifiable
        # without fetching each one
        listed = client.get("/api/v1/technology-bom/cascade/runs").json()
        entry = next(r for r in listed["runs"] if r["id"] == posted["run_id"])
        assert entry["replayed_over"] == posted["replayed_over"]
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
        # A missing target has not been analyzed. Do not invent removals or
        # replace the last resolved baseline with placeholder zeroes.
        assert entry["analysis_performed"] is False
        assert entry["attention_required"] is True
        assert "diff" not in entry
        assert "blast_radius_changed" not in entry
        from db.models.cascade_extensions import CascadeWatch
        saved = session.query(CascadeWatch).one()
        assert saved.last_run_id == first["watches"][0]["run_id"]

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


# Additive scope contract: old totals are review scope, not exposure counts.
def test_classified_scope_round_trips_live_history_and_stored_run(app_db):
    with TestClient(app_db) as client:
        posted = client.post("/api/v1/technology-bom/cascade",
                             json={"target": "payment-api", "kind": "system"})
        assert posted.status_code == 200
        body = posted.json()
        scope = body["impact"]["system_classification"]
        assert scope["direct_exposure"] == {"systems": ["sys-pay"], "count": 1}
        assert scope["dependent_consumers"] == {"systems": ["sys-web"], "count": 1}
        assert scope["supporting_context"] == {"systems": ["sys-db"], "count": 1}
        assert scope["exposure_system_count"] == 2
        assert scope["review_system_count"] == body["impact"]["affected_system_count"] == 3
        listed = client.get("/api/v1/technology-bom/cascade/runs").json()["runs"]
        summary = listed[0]["system_classification"]
        assert summary["direct_exposure"] == {"count": 1}
        assert summary["dependent_consumers"] == {"count": 1}
        assert summary["supporting_context"] == {"count": 1}
        assert summary["exposure_system_count"] == 2
        assert summary["review_system_count"] == 3
        assert "review_systems" not in summary
        stored = client.get(f"/api/v1/technology-bom/cascade/runs/{body['run_id']}").json()
        assert stored["result"]["impact"]["system_classification"] == scope
        client.post("/api/v1/technology-bom/cascade/watch", json={"target": "payment-api"})
        watched = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()
        assert watched["watches"][0]["system_classification"] == summary


def test_classified_diff_reports_role_change_even_when_review_union_unchanged(app_db):
    with TestClient(app_db) as client:
        old = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-api"}).json()
        session = app_db.state.test_session
        session.add(SystemDependency(parent_id="sys-db", child_id="sys-pay"))
        session.commit()
        new = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-api"}).json()
        resp = client.get(f"/api/v1/technology-bom/cascade/runs/{new['run_id']}/diff",
                          params={"against": old["run_id"]})
    assert resp.status_code == 200
    diff = resp.json()
    assert diff["affected_systems"]["added"] == diff["affected_systems"]["removed"] == []
    assert diff["system_classification"]["available"] is True
    assert diff["system_classification"]["dependent_consumers"]["added"] == ["sys-db"]
    assert diff["system_classification"]["supporting_context"]["removed"] == ["sys-db"]


def test_legacy_history_and_mixed_diff_do_not_invent_zero_classification(app_db):
    session = app_db.state.test_session
    with TestClient(app_db) as client:
        old = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-api"}).json()
        row = session.query(CascadeRun).filter_by(id=old["run_id"]).one()
        legacy = dict(row.result)
        legacy["impact"] = {k: v for k, v in legacy["impact"].items() if k != "system_classification"}
        row.result = legacy
        session.commit()
        new = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-api"}).json()
        listed = client.get("/api/v1/technology-bom/cascade/runs").json()["runs"]
        entry = next(r for r in listed if r["id"] == old["run_id"])
        assert entry["system_classification"] is None
        assert entry["affected_system_count"] == 3
        diff = client.get(f"/api/v1/technology-bom/cascade/runs/{new['run_id']}/diff",
                          params={"against": old["run_id"]}).json()
        assert diff["system_classification"]["available"] is False
        assert "direct_exposure" not in diff["system_classification"]
        assert diff["affected_systems"]["after"] == diff["affected_systems"]["before"] == 3
        fetched = client.get(f"/api/v1/technology-bom/cascade/runs/{old['run_id']}").json()
        assert "system_classification" not in fetched["result"]["impact"]


def test_missing_target_has_explicit_zero_scope_but_stays_not_found(app_db):
    with TestClient(app_db) as client:
        resp = client.post("/api/v1/technology-bom/cascade", json={"target": "not-a-system", "kind": "system"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "NOT_FOUND"
    assert body["impact"]["system_classification"]["review_system_count"] == 0
    assert body["impact"]["system_classification"]["direct_exposure"]["systems"] == []
    assert body["honest_unknowns"]


def test_system_policy_matches_graph_routes_and_persists_in_history(app_db):
    from shared_models.dependency_semantics import POLICY_VERSION

    session = app_db.state.test_session
    edge = session.query(SystemDependency).filter_by(parent_id="sys-pay", child_id="sys-db").one()
    edge.relation = "contains"
    session.commit()
    with TestClient(app_db) as client:
        posted = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-api"}).json()
        assert posted["relationship_policy"]["version"] == POLICY_VERSION
        assert posted["impact"]["system_classification"]["supporting_context"]["count"] == 0
        forward = client.get("/api/v1/graph/blast-radius", params={"system_id": "sys-pay"}).json()
        reverse = client.get("/api/v1/graph/dependents", params={"system_id": "sys-pay"}).json()
        path = client.get("/api/v1/graph/path", params={"system_id": "sys-pay", "target_id": "sys-db"}).json()
        assert forward["systems"] == []
        assert {row["id"] for row in reverse["systems"]} == {"sys-web"}
        assert path["reachable"] is False
        for body in (forward, reverse, path):
            assert body["relationship_policy"]["version"] == POLICY_VERSION
        listed = client.get("/api/v1/technology-bom/cascade/runs").json()
        assert listed["runs"][0]["relationship_policy"] == posted["relationship_policy"]
        stored = client.get(f"/api/v1/technology-bom/cascade/runs/{posted['run_id']}").json()
        assert stored["result"]["relationship_policy"] == posted["relationship_policy"]
        edges = client.get("/api/v1/graph/edges").json()
        context = next(row for row in edges["edges"] if row["child_id"] == "sys-db")
        assert context["dependency_semantics"] == {
            "normalized_relation": "CONTAINS", "propagates": False, "policy_version": POLICY_VERSION}


def test_policy_unknown_history_is_not_recomputed_or_misreported_as_remediation(app_db):
    session = app_db.state.test_session
    with TestClient(app_db) as client:
        first = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-api"}).json()
        row = session.query(CascadeRun).filter_by(id=first["run_id"]).one()
        # Simulate an old step-1 answer: it has buckets but no policy version.
        row.result = {k: v for k, v in row.result.items() if k != "relationship_policy"}
        session.commit()
        new = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-api"}).json()
        diff = client.get(f"/api/v1/technology-bom/cascade/runs/{new['run_id']}/diff",
                          params={"against": first["run_id"]}).json()
        assert diff["policy_comparison"]["comparable"] is False
        assert diff["policy_comparison"]["against_version"] is None
        assert diff["system_classification"]["available"] is False
        assert "policy" in diff["system_classification"]["reason"]
        listed = client.get("/api/v1/technology-bom/cascade/runs").json()["runs"]
        old = next(r for r in listed if r["id"] == first["run_id"])
        assert old["relationship_policy"] is None
        assert old["system_classification"]["review_system_count"] == 3
        assert diff["affected_systems"]["before"] == diff["affected_systems"]["after"] == 3


def test_prefixed_snapshot_edges_use_policy_without_mutating_capture(app_db):
    from db.models.cascade_extensions import TwinSnapshot

    session = app_db.state.test_session
    with TestClient(app_db) as client:
        version = client.post("/api/v1/digital-twin/snapshot").json()["version"]
        snapshot = session.query(TwinSnapshot).filter_by(version=version).one()
        state = dict(snapshot.state)
        state["dependencies"] = [
            {"source": "system:sys-web", "target": "system:sys-pay", "type": "imports-crypto"},
            {"source": "system:sys-pay", "target": "system:sys-db", "type": "contains"}]
        snapshot.state = state
        session.commit()
        body = client.post("/api/v1/technology-bom/cascade", params={"version": version},
                           json={"target": "payment-api"}).json()
        assert body["layers"]["system"]["dependents_by_depth"] == {"1": ["sys-web"]}
        assert body["layers"]["system"]["downstream_by_depth"] == {}
        session.refresh(snapshot)
        assert snapshot.state["dependencies"] == state["dependencies"]
        assert body["replayed_over"]["twin_snapshot_version"] == version
        assert body["replayed_over"]["clock_source"] == "snapshot_capture"


def test_same_policy_classified_diff_remains_available(app_db):
    with TestClient(app_db) as client:
        first = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-api"}).json()
        second = client.post("/api/v1/technology-bom/cascade", json={"target": "payment-api"}).json()
        diff = client.get(f"/api/v1/technology-bom/cascade/runs/{second['run_id']}/diff",
                          params={"against": first["run_id"]}).json()
        assert diff["policy_comparison"]["comparable"] is True
        assert diff["system_classification"]["available"] is True


def test_watch_comparison_flags_pre_policy_run_without_rewriting_it(app_db):
    session = app_db.state.test_session
    with TestClient(app_db) as client:
        response = client.post("/api/v1/technology-bom/cascade/watch",
                               json={"target": "payment-api"})
        assert response.status_code == 200
        watch = response.json()
        first = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()["watches"][0]
        assert first["watch_id"] == watch["id"]
        old_run = session.query(CascadeRun).filter_by(id=first["run_id"]).one()
        old_run.result = {k: v for k, v in old_run.result.items() if k != "relationship_policy"}
        session.commit()
        second = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()["watches"][0]
        assert second["policy_comparison"]["comparable"] is False
        assert second["policy_comparison"]["against_version"] is None
        assert second["relationship_policy"]["version"] == first["relationship_policy"]["version"]
        assert "blast_radius_changed" not in second
        session.refresh(old_run)
        assert "relationship_policy" not in old_run.result


# Step 7: exact identities and frozen resolution decisions.
def test_vendor_search_requires_explicit_choice_and_persists_resolution(app_db):
    with TestClient(app_db) as client:
        default = client.post("/api/v1/technology-bom/cascade", json={"target": "Thal", "kind": "vendor"}).json()
        assert default["analysis_performed"] is False
        search = client.post("/api/v1/technology-bom/cascade", json={"target": "Thal", "kind": "vendor", "allow_name_search": True}).json()
        assert search["verdict"] == "UNRESOLVED"
        assert search["target_resolution"]["status"] == "SEARCH_RESULTS"
        assert search["target_resolution"]["candidate_count"] == 1
        selected = search["target_resolution"]["candidates"][0]
        assert selected["canonical_target"] == "vendor-thales"
        body = client.post("/api/v1/technology-bom/cascade", json={"target": selected["canonical_target"], "kind": selected["kind"]}).json()
        assert body["analysis_performed"] is True
        assert body["target_resolution"]["method"] == "exact_identity"
        fetched = client.get(f"/api/v1/technology-bom/cascade/runs/{search['run_id']}").json()["result"]
        assert fetched["target_resolution"] == search["target_resolution"]
        assert fetched["analysis_performed"] is False
        summary = next(r for r in client.get("/api/v1/technology-bom/cascade/runs").json()["runs"] if r["id"] == search["run_id"])
        assert summary["analysis_performed"] is False
        assert summary["target_resolution"] == search["target_resolution"]


def test_network_leaf_fingerprint_survives_inventory_snapshot_and_exact_cascade(app_db):
    from db.models.network_scan_run import NetworkScanRun
    from api.routers.digital_twin import _snapshot
    session = app_db.state.test_session
    session.add(Certificate(fingerprint_sha256="cd" * 32, subject="CN=payment-api"))
    session.add(NetworkScanRun(result={"probes": [
        {"endpoint": "api.bank:443", "status": "OK", "certificates": [{"subject": "CN=payment-api", "fingerprint_sha256": "ab" * 32}]},
        {"endpoint": "other.bank:443", "status": "OK", "certificates": [{"subject": "CN=payment-api", "fingerprint_sha256": "cd" * 32}]},
        {"endpoint": "legacy.bank:443", "status": "OK", "certificates": [{"subject": "CN=payment-api"}]}
    ]}))
    session.add_all([NetworkScanTarget(endpoint="other.bank:443", system_id="sys-db"), NetworkScanTarget(endpoint="legacy.bank:443", system_id="sys-db")])
    session.commit()
    assert next(e for e in _snapshot(session)["network_endpoints"] if e["host"] == "api.bank")["certificate_fingerprint_sha256"] == "ab" * 32
    with TestClient(app_db) as client:
        body = client.post("/api/v1/technology-bom/cascade", json={"target": "AB" * 32, "kind": "certificate"}).json()
        assert body["layers"]["network"]["endpoints"] == ["api.bank:443"]
        assert body["impact"]["system_classification"]["direct_exposure"]["systems"] == ["sys-pay"]
        assert body["layers"]["network"]["certificate_join"]["subject_only_endpoint_count"] == 1
        ambiguous = client.post("/api/v1/technology-bom/cascade", json={"target": "CN=payment-api", "kind": "certificate"}).json()
        assert ambiguous["analysis_performed"] is False
        assert ambiguous["target_resolution"]["status"] == "AMBIGUOUS"


def test_old_snapshot_without_endpoint_fingerprint_is_not_rebound_by_subject(app_db):
    from db.models.cascade_extensions import TwinSnapshot
    from db.models.network_scan_run import NetworkScanRun
    session = app_db.state.test_session
    session.add(NetworkScanRun(result={"probes": [{"endpoint": "api.bank:443", "status": "OK", "certificates": [{"subject": "CN=payment-api", "fingerprint_sha256": "ab" * 32}]}]}))
    session.commit()
    with TestClient(app_db) as client:
        version = client.post("/api/v1/digital-twin/snapshot").json()["version"]
        captured = session.query(TwinSnapshot).filter_by(version=version).one()
        state = dict(captured.state)
        state["network_endpoints"] = [{k: v for k, v in e.items() if k != "certificate_fingerprint_sha256"} for e in state["network_endpoints"]]
        captured.state = state
        session.commit()
        before = __import__('copy').deepcopy(state)
        result = client.post("/api/v1/technology-bom/cascade", params={"version": version}, json={"target": "ab" * 32, "kind": "certificate"}).json()
        assert result["analysis_performed"] is True
        assert result["layers"]["network"]["endpoints"] == []
        assert result["layers"]["network"]["certificate_join"]["subject_only_endpoint_count"] == 1
        assert result["impact"]["system_classification"]["direct_exposure"]["count"] == 0
        session.refresh(captured)
        assert captured.state == before


def test_watch_ambiguous_subject_keeps_resolved_baseline_without_removal(app_db):
    from db.models.cascade_extensions import CascadeWatch
    session = app_db.state.test_session
    with TestClient(app_db) as client:
        client.post("/api/v1/technology-bom/cascade/watch", json={"target": "CN=payment-api", "kind": "certificate"})
        first = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()["watches"][0]
        session.add(Certificate(fingerprint_sha256="cd" * 32, subject="CN=payment-api"))
        session.commit()
        later = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()["watches"][0]
        assert later["target_resolution"]["status"] == "AMBIGUOUS"
        assert later["attention_required"] is True
        assert "diff" not in later and "blast_radius_changed" not in later
        assert session.query(CascadeWatch).one().last_run_id == first["run_id"]


def test_changed_unique_subject_identity_withholds_diff_and_watch_baseline(app_db):
    from db.models.cascade_extensions import CascadeWatch
    session = app_db.state.test_session
    with TestClient(app_db) as client:
        old = client.post("/api/v1/technology-bom/cascade", json={"target": "CN=payment-api", "kind": "certificate"}).json()
        client.post("/api/v1/technology-bom/cascade/watch", json={"target": "CN=payment-api", "kind": "certificate"})
        first = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()["watches"][0]
        session.query(Certificate).one().subject = "CN=retired"
        session.add(Certificate(fingerprint_sha256="cd" * 32, subject="CN=payment-api"))
        session.commit()
        new = client.post("/api/v1/technology-bom/cascade", json={"target": "CN=payment-api", "kind": "certificate"}).json()
        diff = client.get(f"/api/v1/technology-bom/cascade/runs/{new['run_id']}/diff", params={"against": old["run_id"]}).json()
        assert diff["target_comparison"]["comparable"] is False
        assert diff["affected_systems"]["before"] is None
        assert diff["affected_systems"]["added"] == diff["affected_systems"]["removed"] == []
        assert diff["system_classification"]["available"] is False
        entry = client.post("/api/v1/technology-bom/cascade/watches/run-due").json()["watches"][0]
        assert entry["attention_required"] is True and "diff" not in entry
        assert session.query(CascadeWatch).one().last_run_id == first["run_id"]


def test_legacy_resolution_is_not_reconstructed_for_history_diff(app_db):
    session = app_db.state.test_session
    with TestClient(app_db) as client:
        old = client.post("/api/v1/technology-bom/cascade", json={"target": "Thales", "kind": "vendor"}).json()
        row = session.query(CascadeRun).filter_by(id=old["run_id"]).one()
        legacy = {k: v for k, v in row.result.items() if k not in {"target_resolution", "analysis_performed"}}
        row.result = legacy
        session.commit()
        new = client.post("/api/v1/technology-bom/cascade", json={"target": "Thales", "kind": "vendor"}).json()
        diff = client.get(f"/api/v1/technology-bom/cascade/runs/{new['run_id']}/diff", params={"against": old["run_id"]}).json()
        assert diff["target_comparison"]["comparable"] is False
        assert diff["process_comparison"]["comparable"] is False
        assert diff["affected_systems"]["after"] is None
        assert client.get(f"/api/v1/technology-bom/cascade/runs/{old['run_id']}").json()["result"] == legacy


def test_truncated_vendor_registry_requires_canonical_selection(app_db, monkeypatch):
    from api.routers.digital_twin import SNAPSHOT_CAPS
    session = app_db.state.test_session
    session.add(Vendor(id="zz", name="Thales OTHER"))
    session.commit()
    monkeypatch.setitem(SNAPSHOT_CAPS, "vendors", 1)
    with TestClient(app_db) as client:
        body = client.post("/api/v1/technology-bom/cascade", json={"target": "Thales", "kind": "vendor"}).json()
        assert body["target_resolution"]["status"] == "INCOMPLETE"
        assert body["target_resolution"]["coverage"]["vendor_truncated"] is True
        exact = client.post("/api/v1/technology-bom/cascade", json={"target": "vendor-thales", "kind": "vendor"}).json()
        assert exact["analysis_performed"] is True


def test_certificate_and_vendor_search_candidates_are_tenant_scoped(tenants, tenancy_session):
    acme, _ = tenants
    tenancy_session.add_all([
        Certificate(tenant_id="acme", fingerprint_sha256="ab" * 32, subject="CN=Bank Acme"),
        Certificate(tenant_id="globex", fingerprint_sha256="cd" * 32, subject="CN=Bank Secret"),
        Vendor(tenant_id="acme", id="v-acme", name="Bank Crypto Acme"),
        Vendor(tenant_id="globex", id="v-secret", name="Bank Crypto Secret")])
    tenancy_session.commit()
    for kind, query in [("certificate", "CN=Bank"), ("vendor", "Bank Crypto")]:
        response = acme.post("/api/v1/technology-bom/cascade", json={"target": query, "kind": kind, "allow_name_search": True})
        assert response.status_code == 200
        result = response.json()
        assert result["target_resolution"]["status"] == "SEARCH_RESULTS"
        assert result["target_resolution"]["candidate_count"] == 1
        assert "secret" not in response.text.lower()
        assert "globex" not in response.text.lower()
        assert result["analysis_performed"] is False
    response = acme.post("/api/v1/technology-bom/cascade", json={"target": "cd" * 32, "kind": "certificate"})
    assert response.json()["analysis_performed"] is False
    assert response.json()["target_resolution"]["candidate_count"] == 0
