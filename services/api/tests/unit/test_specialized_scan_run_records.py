"""Durable per-run records for the synchronous specialized scanners (§4.8/§5, round 44).

Every cloud / container / network / OT trigger now leaves a tenant-bound
ScanJob row — status, admission decision, bounded coverage — readable at
``GET /jobs/{id}``. A run that fails mid-flight is stamped FAILED with the
reason; coverage summarizes size, never finding content; and a run created
inside one tenant scope is invisible to another tenant.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings

REPO_ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/runs.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.events.bus import reset_event_bus

    reset_event_bus()
    from api.main import create_app

    with TestClient(create_app()) as c:
        yield c


def _pin_ok(monkeypatch):
    from api.security import scan_admission as admission

    monkeypatch.setattr(admission, "_control_plane_state", lambda: ([], None))
    monkeypatch.setattr(admission, "_ot_declared", lambda: False)
    monkeypatch.setattr(admission, "_active_job_count", lambda: 0)


def _auth(client):
    token = client.post("/api/v1/auth/login",
                        json={"username": "admin", "password": "cryptoscan"}
                        ).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def _stub(monkeypatch, module, class_name, report):
    class _Stub:
        def __init__(self, *args, **kwargs):
            pass

        def scan_filesystem(self, target, **kwargs):
            return dict(report)

        def scan_hosts(self, hosts, **kwargs):
            return dict(report)

        def scan(self, **kwargs):
            return dict(report)

    monkeypatch.setattr(module, class_name, _Stub)


def test_cloud_scan_leaves_durable_completed_record(client, monkeypatch):
    _pin_ok(monkeypatch)
    import api.routers.cloud_scans as cloud_module

    _stub(monkeypatch, cloud_module, "CloudScanner",
          {"resources": 3, "findings": [], "accounts_scanned": 1})
    r = client.post("/api/v1/cloud-scans", headers=_auth(client),
                    json={"path": str(REPO_ROOT), "live": False})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["job_id"], "response must identify the durable run"

    job = client.get(f"/api/v1/jobs/{body['job_id']}", headers=_auth(client)).json()
    assert job["status"] == "COMPLETED"
    assert job["job_type"] == "CLOUD_SCAN"
    assert job["target_repo"] == str(REPO_ROOT)
    assert job["progress"]["execution"] == "synchronous"
    assert job["progress"]["admission"]["mode"] == "standard"
    assert job["progress"]["coverage"]["resources"] == 3
    assert job["progress"]["coverage"]["findings_count"] == 0
    assert job["started_at"] and job["completed_at"]


def test_container_scan_failure_leaves_durable_failed_record(client, monkeypatch):
    _pin_ok(monkeypatch)
    missing = str(REPO_ROOT / "does-not-exist-anywhere")
    r = client.post("/api/v1/container-scans", headers=_auth(client),
                    json={"path": missing, "live_cve": False})
    assert r.status_code == 404
    # the refusal is durable too: an operator can later see this run failed and why
    job_id = None
    from db.connection.session import SessionLocal
    from db.models.scan_job import ScanJob

    session = SessionLocal()
    try:
        row = (session.query(ScanJob)
               .filter(ScanJob.job_type == "CONTAINER_SCAN")
               .order_by(ScanJob.created_at.desc()).first())
        job_id = row.id if row else None
    finally:
        session.close()
    assert job_id, "a failed run must still leave its record"

    job = client.get(f"/api/v1/jobs/{job_id}", headers=_auth(client)).json()
    assert job["status"] == "FAILED"
    assert "Container filesystem not found" in (job["error_message"] or "")


def test_ot_scan_leaves_durable_completed_record(client, monkeypatch):
    _pin_ok(monkeypatch)
    import api.routers.ot as ot_module

    _stub(monkeypatch, ot_module, "OtPassiveScanner",
          {"devices": [], "findings": [], "packets_sent": 0})
    r = client.post("/api/v1/ot/scan", headers=_auth(client),
                    json={"path": str(REPO_ROOT)})
    assert r.status_code == 200, r.text
    job = client.get(f"/api/v1/jobs/{r.json()['job_id']}", headers=_auth(client)).json()
    assert job["status"] == "COMPLETED"
    assert job["job_type"] == "OT_SCAN"
    assert job["progress"]["admission"]["is_ot"] is True


def test_coverage_summarizes_size_never_finding_content(client, monkeypatch):
    _pin_ok(monkeypatch)
    import api.routers.cloud_scans as cloud_module

    _stub(monkeypatch, cloud_module, "CloudScanner",
          {"resources": 2, "findings": [{"note": "secret-material", "key": "k"}],
           "account": "acct-123", "regions": ["us-east-1", "eu-west-1"]})
    r = client.post("/api/v1/cloud-scans", headers=_auth(client),
                    json={"path": str(REPO_ROOT), "live": False})
    assert r.status_code == 200
    job = client.get(f"/api/v1/jobs/{r.json()['job_id']}", headers=_auth(client)).json()
    progress_json = json.dumps(job["progress"])
    assert "secret-material" not in progress_json, "finding content must not reach the job record"
    assert job["progress"]["coverage"]["findings_count"] == 2 or \
        job["progress"]["coverage"]["findings_count"] == 1
    assert job["progress"]["coverage"]["resources"] == 2
    assert job["progress"]["coverage"]["regions_count"] == 2


def test_network_scan_response_identifies_the_run(client, monkeypatch):
    _pin_ok(monkeypatch)
    import api.routers.network_scans as net_module

    _stub(monkeypatch, net_module, "NetworkTlsScanner",
          {"certificates": [], "usages": [], "hosts_scanned": 1})
    r = client.post("/api/v1/network-scans", headers=_auth(client),
                    json={"hosts": ["scanima.local"], "live": True})
    assert r.status_code == 200, r.text
    job = client.get(f"/api/v1/jobs/{r.json()['job_id']}", headers=_auth(client)).json()
    assert job["status"] == "COMPLETED"
    assert job["job_type"] == "NETWORK_SCAN"
    assert job["progress"]["run"]["hosts"] == 1


def test_run_records_are_tenant_bound(client, monkeypatch):
    """A run created inside one tenant scope is invisible to another tenant."""
    _pin_ok(monkeypatch)
    import api.routers.cloud_scans as cloud_module

    _stub(monkeypatch, cloud_module, "CloudScanner", {"resources": 1, "findings": []})

    from api.security.session_manager import SessionManager
    from db.connection.session import SessionLocal
    from db.repositories.tenant_repository import TenantRepository

    session = SessionLocal()
    try:
        tenants = TenantRepository(session)
        tenants.ensure_user("member-a")
        tenants.ensure_user("member-b")
        tenant_a = tenants.create(name="Run Alpha", slug="run-alpha", created_by="member-a")
        tenant_b = tenants.create(name="Run Beta", slug="run-beta", created_by="member-b")
        tenants.add_member(tenant_a.id, "member-a", "member")
        tenants.add_member(tenant_b.id, "member-b", "member")
        session.commit()
        tenant_a_id, tenant_b_id = tenant_a.id, tenant_b.id
    finally:
        session.close()

    def auth(username: str, tenant: str) -> dict[str, str]:
        token = SessionManager().create_session(username, roles=["readonly"])
        return {"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant}

    created = client.post(
        "/api/v1/cloud-scans",
        headers=auth("member-a", tenant_a_id),
        json={"path": str(REPO_ROOT), "live": False},
    )
    assert created.status_code == 200, created.text
    job_id = created.json()["job_id"]

    # the owning tenant sees its run…
    own = client.get(f"/api/v1/jobs/{job_id}", headers=auth("member-a", tenant_a_id))
    assert own.status_code == 200
    assert own.json()["status"] == "COMPLETED"
    # …another tenant cannot, even with the id in hand
    other = client.get(f"/api/v1/jobs/{job_id}", headers=auth("member-b", tenant_b_id))
    assert other.status_code == 404

    # the row itself is stamped to the creating tenant
    from db.models.scan_job import ScanJob

    session = SessionLocal()
    try:
        row = session.query(ScanJob).filter(ScanJob.id == job_id).one_or_none()
        assert row is not None and row.tenant_id == tenant_a_id
    finally:
        session.close()
