"""Cross-tenant isolation of the OS & Kernel intelligence surface, e2e.

The tenant e2e chain (``test_tenant_e2e_flow``) pins the header → scope →
stamp → scoped-list loop for the technology-bom router. This file pins the
SAME guarantees for the OS-intelligence surface (collections, assets,
capabilities, findings, live-capture, runtime sessions/events/usage, rule
evaluation) over the REAL production stack — ``create_app()`` +
``TenantScopeMiddleware`` + real session tokens:

* a member of two orgs never reads one org's rows through the other's
  context, whatever tenant id the query/body names;
* a single-org member who FORGES another tenant's id in the body/query
  never creates or reads a row there — the scope (not the payload) owns
  the stamp;
* every stored row carries the owning tenant, checked at the ORM.
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
from db.models.os_intelligence import OSAsset, OSRuntimeSession
from db.models.tenant import Tenant, TenantMembership
from db.repositories.user_repository import UserRepository
from db.tenancy import platform_scope

from test_os_intelligence_api import _real_inventory


@pytest.fixture()
def two_tenants(tmp_path):
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False},
        poolclass=StaticPool)
    Base.metadata.create_all(engine)
    configure_session(engine)
    session = SessionLocal()

    users = UserRepository(session)
    users.create_user("dual_member", hash_password("x"), ["security_analyst"])
    users.create_user("alpha_only", hash_password("x"), ["security_analyst"])
    users.create_user("alpha_reader", hash_password("x"), ["readonly"])
    session.add_all([
        Tenant(id="alpha", name="Alpha Bank", slug="alpha"),
        Tenant(id="beta", name="Beta Bank", slug="beta"),
        TenantMembership(tenant_id="alpha", username="dual_member",
                         tenant_role="owner"),
        TenantMembership(tenant_id="beta", username="dual_member",
                         tenant_role="member"),
        TenantMembership(tenant_id="alpha", username="alpha_only",
                         tenant_role="member"),
        TenantMembership(tenant_id="alpha", username="alpha_reader",
                         tenant_role="viewer"),
    ])
    session.commit()

    app = create_app()
    app.add_middleware(TenantScopeMiddleware)  # the real production stack

    manager = SessionManager()
    tokens = {}
    for username in ("dual_member", "alpha_only", "alpha_reader"):
        token = manager.create_session(username, roles=[])
        UserRepository(session).create_session(
            token, username,
            datetime.now(timezone.utc) + timedelta(hours=1), ip="127.0.0.1")
        tokens[username] = token
    session.commit()

    client = TestClient(app)

    class Caller:
        def __init__(self, token):
            self.token = token

        def get(self, url, tenant):
            return client.get(url, cookies={"cryptoscan_session": self.token},
                              headers={"X-Tenant-ID": tenant} if tenant else {})

        def post(self, url, json, tenant):
            return client.post(url, json=json,
                               cookies={"cryptoscan_session": self.token},
                               headers={"X-Tenant-ID": tenant} if tenant else {})

    try:
        yield {
            "dual": Caller(tokens["dual_member"]),
            "alpha_only": Caller(tokens["alpha_only"]),
            "reader": Caller(tokens["alpha_reader"]),
            "client": client,
            "session": session,
            "tmp_path": tmp_path,
        }
    finally:
        session.close()
        engine.dispose()
        app.dependency_overrides.clear()


def _seed(caller, sess, tmp_path, asset_id, tenant, tenant_header):
    """Post one real collection for ``tenant`` and return it."""
    inventory = _real_inventory(tmp_path)
    res = caller.post(
        "/api/v1/os-intelligence/collections",
        {"tenant_id": tenant, "asset_id": asset_id, "inventory": inventory},
        tenant=tenant_header)
    assert res.status_code in (200, 201), res.text
    return inventory


def test_dual_member_scoped_reads_and_writes(two_tenants):
    dual, sess, tmp_path = two_tenants["dual"], two_tenants["session"], two_tenants["tmp_path"]
    _seed(dual, sess, tmp_path, "alpha-host", "alpha", "alpha")

    # alpha context sees the asset, stamped alpha at the ORM
    listed = dual.get("/api/v1/os-intelligence/assets?tenant_id=alpha",
                      tenant="alpha")
    assert listed.status_code == 200
    assert [a["asset_id"] for a in listed.json()["assets"]] == ["alpha-host"]
    with platform_scope():
        row = sess.query(OSAsset).filter_by(asset_id="alpha-host").one()
    assert row.tenant_id == "alpha"

    # beta context: lists are empty and NEVER name alpha's rows
    beta_list = dual.get("/api/v1/os-intelligence/assets?tenant_id=beta",
                         tenant="beta")
    assert beta_list.status_code == 200
    assert beta_list.json()["assets"] == []
    assert "alpha-host" not in beta_list.text

    # beta context naming alpha's tenant in the query: no leak either way
    spoofed = dual.get("/api/v1/os-intelligence/assets?tenant_id=alpha",
                       tenant="beta")
    assert spoofed.status_code in (200, 403, 404)
    if spoofed.status_code == 200:
        assert spoofed.json()["assets"] == []
    assert "alpha-host" not in spoofed.text

    # direct reads of alpha's asset under beta: refused
    for path in (
        "/api/v1/os-intelligence/assets/alpha-host",
        "/api/v1/os-intelligence/assets/alpha-host/capabilities",
        "/api/v1/os-intelligence/assets/alpha-host/findings",
        "/api/v1/os-intelligence/assets/alpha-host/session-stats",
        "/api/v1/os-intelligence/assets/alpha-host/runtime-sessions",
        "/api/v1/os-intelligence/assets/alpha-host/runtime-events",
        "/api/v1/os-intelligence/assets/alpha-host/runtime-usage",
        "/api/v1/os-intelligence/assets/alpha-host/rule-evaluation",
    ):
        res = dual.get(path + "?tenant_id=beta", tenant="beta")
        assert res.status_code in (403, 404), (path, res.status_code, res.text)
        assert "alpha-host" not in res.text or res.status_code == 404


def test_single_org_member_cannot_forge_another_tenant(two_tenants):
    alpha_only, sess, tmp_path = (
        two_tenants["alpha_only"], two_tenants["session"], two_tenants["tmp_path"])

    # forging beta as the body tenant must NOT create a beta-owned row
    inventory = _real_inventory(tmp_path)
    forged = alpha_only.post(
        "/api/v1/os-intelligence/collections",
        {"tenant_id": "beta", "asset_id": "forged-host", "inventory": inventory},
        tenant=None)  # no header: auto-scoped to alpha (their only org)
    assert forged.status_code in (200, 201, 403, 422), forged.text
    with platform_scope():
        rows = sess.query(OSAsset).filter_by(asset_id="forged-host").all()
    owners = {r.tenant_id for r in rows}
    assert "beta" not in owners, (
        "a member of alpha created a beta-owned row from a forged body "
        "tenant_id — the scope, not the payload, must own the stamp")
    if forged.status_code in (200, 201):
        assert owners == {"alpha"}  # stamped to the resolved scope

    # alpha_only cannot read beta's territory at all
    beta_read = alpha_only.get("/api/v1/os-intelligence/assets?tenant_id=beta",
                               tenant=None)
    assert beta_read.status_code in (200, 403)
    if beta_read.status_code == 200:
        assert beta_read.json()["assets"] == []
    assert "forged-host" not in beta_read.text or beta_read.status_code == 403


def test_runtime_sessions_are_tenant_scoped(two_tenants):
    dual, sess, tmp_path = two_tenants["dual"], two_tenants["session"], two_tenants["tmp_path"]
    _seed(dual, sess, tmp_path, "alpha-host", "alpha", "alpha")

    session_body = {
        "session_id": "rt-alpha-1",
        "boot_id": "boot-1",
        "collection_profile": "tier2-approved-tracepoints",
        "evidence_source": "runtime collector",
        "events_lost": 1,
        "attached_points": ["tracepoint:crypto:crypto_alg_get"],
        "events": [{
            "timestamp": "17600000001",
            "process_id": "4242",
            "process_start_time": "9001",
            "executable_digest": "sha256:aaaa",
            "operation_category": "crypto_api_allocation",
            "algorithm_identifier": "cbc(aes)",
            "provider_identifier": "cbc-aes-aesni",
            "kernel_or_userspace": "kernel",
            "interface": "crypto-api",
            "evidence_source": "runtime collector",
        }],
    }

    # alpha records the session
    ok = dual.post(
        "/api/v1/os-intelligence/assets/alpha-host/runtime-sessions",
        {"tenant_id": "alpha", "asset_id": "alpha-host", "session": session_body},
        tenant="alpha")
    assert ok.status_code in (200, 201), ok.text

    with platform_scope():
        row = sess.query(OSRuntimeSession).filter_by(
            session_id="rt-alpha-1").one()
    assert row.tenant_id == "alpha"

    # beta cannot record a session against alpha's asset
    cross = dual.post(
        "/api/v1/os-intelligence/assets/alpha-host/runtime-sessions",
        {"tenant_id": "beta", "asset_id": "alpha-host", "session": dict(
            session_body, session_id="rt-beta-1")},
        tenant="beta")
    assert cross.status_code in (403, 404), cross.text

    # beta's runtime reads are empty and never name alpha's session/asset
    for path in ("/api/v1/os-intelligence/assets/alpha-host/runtime-sessions",
                 "/api/v1/os-intelligence/assets/alpha-host/runtime-events",
                 "/api/v1/os-intelligence/assets/alpha-host/runtime-usage"):
        res = dual.get(path + "?tenant_id=beta", tenant="beta")
        assert res.status_code in (403, 404), (path, res.status_code, res.text)

    beta_events = dual.get(
        "/api/v1/os-intelligence/assets/alpha-host/runtime-events"
        "?tenant_id=beta&session_id=rt-alpha-1", tenant="beta")
    assert beta_events.status_code in (403, 404)
    assert "rt-alpha-1" not in beta_events.text or beta_events.status_code == 404

    # alpha still sees everything
    alpha_events = dual.get(
        "/api/v1/os-intelligence/assets/alpha-host/runtime-events"
        "?tenant_id=alpha", tenant="alpha")
    assert alpha_events.status_code == 200
    assert "rt-alpha-1" in alpha_events.text


def test_cryptolog_and_performance_reject_foreign_payloads(two_tenants):
    """Exercise real session → middleware scope, not a mocked tenant id."""
    dual = two_tenants["dual"]
    event = {
        "tenant_id": "alpha", "event_type": "TLS_NEGOTIATION_OBSERVED",
        "category": "TLS", "logging_kind": "ACTIVITY", "severity": "INFO",
        "asset_id": "gateway-alpha",
        "source": {"collector_id": "fixture", "collector_version": "1.0",
                   "source_type": "NETWORK_OBSERVATION"},
        "cryptographic_context": {"protocol": "TLS", "evidence_level": "NETWORK_NEGOTIATED"},
        "observation": {"observed_at": "2026-11-07T04:00:00Z"},
        "evidence": {"evidence_ids": ["evidence-alpha"]},
    }
    metric = {
        "metric_id": "metric-alpha", "tenant_id": "alpha",
        "asset_id": "gateway-alpha", "metric_name": "network.rtt_ms",
        "metric_type": "gauge", "metric_value": 42.0, "unit": "ms",
        "source_id": "fixture", "observed_at": "2026-11-07T04:00:00Z",
        "quality_status": "valid",
    }
    accepted_event = dual.post("/api/v1/cryptolog/events", event, "alpha")
    assert accepted_event.status_code == 201
    event_id = accepted_event.json()["event"]["event_id"]
    assert dual.post("/api/v1/performance/ingest", metric, "alpha").status_code == 201
    assert dual.get(f"/api/v1/cryptolog/events/{event_id}", "beta").status_code == 404
    foreign_events = dual.get("/api/v1/cryptolog/events?tenant_id=alpha", "beta")
    assert foreign_events.status_code == 403
    foreign_samples = dual.get("/api/v1/performance/samples?tenant_id=alpha", "beta")
    assert foreign_samples.status_code == 403
    assert "metric-alpha" not in foreign_samples.text
    duplicated_selection = dual.get(
        "/api/v1/performance/samples?tenant_id=beta&tenant_id=alpha", "beta")
    assert duplicated_selection.status_code == 403
    own_samples = dual.get("/api/v1/performance/samples?tenant_id=alpha", "alpha")
    assert own_samples.status_code == 200
    assert "metric-alpha" in own_samples.text
    foreign_event = dual.post("/api/v1/cryptolog/events", event, "beta")
    assert foreign_event.status_code == 403, foreign_event.text
    foreign_metric = dual.post("/api/v1/performance/ingest", metric, "beta")
    assert foreign_metric.status_code == 403, foreign_metric.text


def test_every_new_intelligence_mutation_declares_a_write_role():
    from api.dependencies import (require_intelligence_manager,
                                  require_intelligence_writer)
    from api.routers import (binary_intelligence, cryptolog, os_intelligence,
                             performance)

    expected = [
        (binary_intelligence.router, {
            "/binary/scan", "/binary/artifacts/{artifact_id}/rescan",
            "/binary/scan/async", "/binary/scan/jobs/{job_id}/process",
            "/binary/firmware/scan"}),
        (cryptolog.router, {
            "/cryptolog/events", "/cryptolog/events/batch",
            "/cryptolog/events/{event_id}/corrections",
            "/cryptolog/alerts/evaluate",
            "/cryptolog/alerts/{alert_id}/transition",
            "/cryptolog/integrity/checkpoint"}),
        (performance.router, {
            "/performance/ingest", "/performance/ingest/batch",
            "/performance/captures/import",
            "/performance/benchmarks", "/performance/definitions"}),
        (os_intelligence.router, {
            "/os-intelligence/collections",
            "/os-intelligence/assets/{asset_id}/runtime-sessions"}),
    ]
    for router, guarded_paths in expected:
        actual = {route.path for route in router.routes
                  if any(dep.call in {require_intelligence_writer,
                                      require_intelligence_manager}
                         for dep in route.dependant.dependencies)}
        assert actual == guarded_paths, (router.prefix, actual ^ guarded_paths)


def test_readonly_member_cannot_submit_intelligence_or_host_evidence(two_tenants):
    import base64

    reader = two_tenants["reader"]
    event = {
        "tenant_id": "alpha", "event_type": "TLS_NEGOTIATION_OBSERVED",
        "category": "TLS", "logging_kind": "ACTIVITY", "severity": "INFO",
        "asset_id": "gateway-reader",
        "source": {"collector_id": "fixture", "collector_version": "1.0",
                   "source_type": "NETWORK_OBSERVATION"},
        "cryptographic_context": {"protocol": "TLS", "evidence_level": "NETWORK_NEGOTIATED"},
        "observation": {"observed_at": "2026-11-07T04:00:00Z"},
        "evidence": {"evidence_ids": ["evidence-reader"]},
    }
    metric = {
        "metric_id": "metric-reader", "tenant_id": "alpha",
        "asset_id": "gateway-reader", "metric_name": "network.rtt_ms",
        "metric_type": "gauge", "metric_value": 42.0, "unit": "ms",
        "source_id": "fixture", "observed_at": "2026-11-07T04:00:00Z",
        "quality_status": "valid",
    }
    calls = (
        ("/api/v1/cryptolog/events", event),
        ("/api/v1/performance/ingest", metric),
        ("/api/v1/binary/scan/async", {
            "tenant_id": "alpha", "artifact_base64": base64.b64encode(
                b"static fixture bytes").decode()}),
        ("/api/v1/os-intelligence/collections", {
            "tenant_id": "alpha", "asset_id": "reader-host",
            "inventory": _real_inventory(two_tenants["tmp_path"])}),
    )
    for path, body in calls:
        denied = reader.post(path, body, "alpha")
        assert denied.status_code == 403, (path, denied.status_code, denied.text)
    assert reader.get("/api/v1/os-intelligence/rules", "alpha").status_code == 200


def test_machine_key_writer_role_is_tenant_bound(two_tenants):
    from db.models.os_intelligence import OSAsset
    from db.repositories.api_key_repository import ApiKeyRepository

    db, client = two_tenants["session"], two_tenants["client"]
    repo = ApiKeyRepository(db)
    _, readonly = repo.create(name="os-readonly", created_by="test",
                              tenant_id="alpha", roles=["readonly"])
    _, scanner = repo.create(name="os-scanner", created_by="test",
                             tenant_id="alpha", roles=["scanner"])
    db.commit()
    payload = {"tenant_id": "alpha", "asset_id": "machine-key-host",
               "inventory": _real_inventory(two_tenants["tmp_path"])}
    path = "/api/v1/os-intelligence/collections"
    assert client.post(path, json=payload,
                       headers={"X-API-Key": readonly}).status_code == 403
    assert client.post(path, json=payload,
                       headers={"X-API-Key": scanner,
                                "X-Tenant-ID": "beta"}).status_code == 403
    allowed = client.post(path, json=payload,
                          headers={"X-API-Key": scanner})
    assert allowed.status_code == 201, allowed.text
    with platform_scope():
        row = db.query(OSAsset).filter_by(asset_id="machine-key-host").one()
    assert row.tenant_id == "alpha"


def test_binary_job_cannot_be_consumed_from_another_tenant(two_tenants):
    """A real session and middleware scope must gate the in-memory queue."""
    import base64
    from api.routers.binary_intelligence import WORKER_QUEUE

    dual = two_tenants["dual"]
    payload = {"tenant_id": "alpha",
               "artifact_base64": base64.b64encode(b"static fixture bytes").decode()}
    original_pending = WORKER_QUEUE.pending
    accepted = dual.post("/api/v1/binary/scan/async", payload, "alpha")
    assert accepted.status_code == 202, accepted.text
    job_id = accepted.json()["job_id"]
    assert WORKER_QUEUE.pending == original_pending + 1

    selected_foreign = dual.get("/api/v1/binary/scans/missing?tenant_id=alpha",
                                "beta")
    assert selected_foreign.status_code == 403
    rejected = dual.post(f"/api/v1/binary/scan/jobs/{job_id}/process",
                         {}, "beta")
    assert rejected.status_code == 404, rejected.text
    assert WORKER_QUEUE.pending == original_pending + 1
    forged = dual.post("/api/v1/binary/scan/async", payload, "beta")
    assert forged.status_code == 403, forged.text
    assert WORKER_QUEUE.pending == original_pending + 1

    owned = dual.post(f"/api/v1/binary/scan/jobs/{job_id}/process",
                      {}, "alpha")
    assert owned.status_code == 201, owned.text
    assert WORKER_QUEUE.pending == original_pending


def test_mismatched_body_tenant_is_refused_not_stored(two_tenants):
    """A body/query tenant_id that contradicts the request's scope is an
    explicit 403 — never a 500 scope violation and never a stored row."""
    dual, sess, tmp_path = two_tenants["dual"], two_tenants["session"], two_tenants["tmp_path"]

    inventory = _real_inventory(tmp_path)
    mismatch = dual.post(
        "/api/v1/os-intelligence/collections",
        {"tenant_id": "beta", "asset_id": "mismatch-host", "inventory": inventory},
        tenant="alpha")  # header selects alpha; body names beta
    assert mismatch.status_code == 403, mismatch.text
    assert "scope" in mismatch.text.lower()

    # nothing was stored under either tenant
    with platform_scope():
        assert sess.query(OSAsset).filter_by(
            asset_id="mismatch-host").all() == []

    # and the same refusal covers the runtime intake and the reads
    rt = dual.post(
        "/api/v1/os-intelligence/assets/alpha-host/runtime-sessions",
        {"tenant_id": "beta", "asset_id": "alpha-host",
         "session": {"session_id": "rt-x", "events": []}},
        tenant="alpha")
    assert rt.status_code == 403, rt.text

    read = dual.get("/api/v1/os-intelligence/assets?tenant_id=beta",
                    tenant="alpha")
    assert read.status_code == 403, read.text
