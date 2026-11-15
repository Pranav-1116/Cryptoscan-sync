"""Storage API tests: honest gating, honest dry-runs, honest dedup/provenance.

The HTTP surface of spec 2.1/§7. RBAC is exercised through the REAL
permission dependencies (no bypass): an unauthenticated caller is denied
every endpoint, and only an explicitly granted permission opens one. The
storage behaviors themselves run against a real session — the engine
contracts are pinned in services/database/tests/test_storage_optimization.py.
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models.content_object  # noqa: F401
import db.models.evidence_content_link  # noqa: F401
import db.models.snapshot_delta  # noqa: F401
import db.models.storage_policy  # noqa: F401

from api.dependencies import get_current_user, get_db_session, get_tenant_context
from api.dependencies import require_query_tenant_scope
from api.dependencies import TenantContext
from api.main import create_app
from api.routers.storage import (
    require_storage_ingest, require_storage_operate, require_storage_policy,
    require_storage_read,
)
from db.connection.session import Base


@pytest.fixture
def env():
    from sqlalchemy.pool import StaticPool
    # StaticPool: one shared connection across threads — TestClient runs the
    # app in a portal thread, and a per-thread :memory: pool would hand it a
    # fresh EMPTY database.
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False},
        poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()

    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    app.dependency_overrides[get_current_user] = lambda: "storage-op"
    app.dependency_overrides[get_tenant_context] = lambda: TenantContext(
        username="storage-op", tenant_id="tenant-a", tenant_role=None, is_platform_admin=False)
    app.dependency_overrides[require_query_tenant_scope] = lambda: "tenant-a"
    yield app, session
    session.close()


def test_unauthenticated_callers_are_denied_every_endpoint(env):
    app, _session = env
    # No permission overrides: the REAL require_permission dependencies run.
    client = TestClient(app, raise_server_exceptions=False)
    for method, path in (
        ("get", "/api/v1/storage/usage"),
        ("get", "/api/v1/storage/policies"),
        ("put", "/api/v1/storage/policies"),
        ("post", "/api/v1/storage/evidence"),
        ("post", "/api/v1/storage/retention/sweep"),
        ("post", "/api/v1/storage/gc"),
        ("post", "/api/v1/storage/restore-test"),
    ):
        if method == "get":
            response = client.get(path)
        else:
            response = getattr(client, method)(path, json={})
        assert response.status_code in (401, 403), (method, path, response.status_code)


def test_evidence_endpoint_dedupes_bytes_and_never_provenance(env):
    app, session = env
    app.dependency_overrides[require_storage_read] = lambda: "storage-op"
    app.dependency_overrides[require_storage_ingest] = lambda: "storage-op"
    client = TestClient(app)

    payload = base64.b64encode(b"identical evidence bytes").decode()
    first = client.post("/api/v1/storage/evidence", json={
        "content_b64": payload, "collector": "host-scan",
        "source_location": "host-a:/etc/ssl", "owner": "team-pki",
        "authorization_context": {"grant": "scan:tls"}, "observation_ref": "obs-1",
    })
    second = client.post("/api/v1/storage/evidence", json={
        "content_b64": payload, "collector": "ct-monitor",
        "source_location": "ct-log:example.com", "owner": "team-identity",
        "authorization_context": {"grant": "scan:ct"}, "observation_ref": "obs-2",
    })
    assert first.status_code == 200 and second.status_code == 200
    assert first.json()["stored"] is True
    assert second.json()["stored"] is False          # bytes deduplicated
    assert first.json()["content_sha256"] == second.json()["content_sha256"]

    from db.models.evidence_content_link import EvidenceContentLink
    links = session.query(EvidenceContentLink).all()
    assert len(links) == 2                            # provenance never merged
    assert {(l.owner, l.collector) for l in links} == {
        ("team-pki", "host-scan"), ("team-identity", "ct-monitor")}

    # Metadata separation: the object endpoint returns the row, not bytes.
    meta = client.get(f"/api/v1/storage/objects/{first.json()['content_sha256']}")
    assert meta.status_code == 200
    assert meta.json()["plain_size"] == len(b"identical evidence bytes")
    assert "content_b64" not in meta.json() and "ciphertext" not in meta.json()


def test_sweeps_are_dry_run_by_default_and_perform_only_when_said_so(env):
    app, session = env
    app.dependency_overrides[require_storage_operate] = lambda: "storage-op"
    client = TestClient(app)

    dry = client.post("/api/v1/storage/retention/sweep", json={})
    assert dry.status_code == 200
    assert dry.json()["dry_run"] is True

    dry_gc = client.post("/api/v1/storage/gc", json={})
    assert dry_gc.status_code == 200
    assert dry_gc.json()["dry_run"] is True

    wet = client.post("/api/v1/storage/retention/sweep", json={"dry_run": False})
    assert wet.status_code == 200
    assert wet.json()["dry_run"] is False
    assert all(a["performed"] for a in wet.json()["actions"]) or not wet.json()["actions"]


def test_restore_test_endpoint_records_recovery_evidence(env):
    app, session = env
    app.dependency_overrides[require_storage_ingest] = lambda: "storage-op"
    app.dependency_overrides[require_storage_operate] = lambda: "storage-op"
    client = TestClient(app)

    stored = client.post("/api/v1/storage/evidence", json={
        "content_b64": base64.b64encode(b"archived evidence").decode(),
        "collector": "host-scan", "source_location": "host-a",
        "owner": "team-pki", "observation_ref": "obs-9",
    }).json()
    result = client.post("/api/v1/storage/restore-test",
                         params={"object_sha256": stored["content_sha256"]})
    assert result.status_code == 200
    record = result.json()["results"][0]
    assert record["ok"] is True
    assert record["bytes_verified"] == len(b"archived evidence")


def test_policy_writes_require_the_storage_policy_permission(env):
    app, _session = env
    app.dependency_overrides[require_storage_read] = lambda: "storage-op"
    # storage.policy NOT granted: the real dependency must refuse.
    client = TestClient(app, raise_server_exceptions=False)
    denied = client.put("/api/v1/storage/policies", json={
        "category": "cache_data", "retention_days": 1, "hot_days": 1,
        "warm_days": 1, "compress": True, "expired_action": "delete",
    })
    assert denied.status_code in (401, 403)

    app.dependency_overrides[require_storage_policy] = lambda: "storage-op"
    allowed = client.put("/api/v1/storage/policies", json={
        "category": "cache_data", "retention_days": 1, "hot_days": 1,
        "warm_days": 1, "compress": True, "expired_action": "delete",
    })
    assert allowed.status_code == 200
    assert allowed.json()["policy"]["retention_days"] == 1
