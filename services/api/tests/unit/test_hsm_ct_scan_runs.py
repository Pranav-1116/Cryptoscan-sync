"""HSM and CT scan runs under the specialized durable-job contract (§4.8, round 50).

The key-residence core (keyassure.hsm_connectivity) and CT-monitoring core
(keyassure.ct_monitor) already existed as assurance checks; these tests pin
their NEW scan surfaces: central admission, a tenant-bound durable ScanJob
row readable at ``GET /jobs/{id}``, content-free coverage, honest
verification_mode labeling, and refusals that leave no invented outcome.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings

EMERGENCY_EVENTS = [{
    "event_type": "safe_scan.emergency_stop",
    "payload": {"engaged": True},
    "created_at": "2026-10-13T00:00:00+00:00",
}]


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


def _pin_emergency(monkeypatch):
    from api.security import scan_admission as admission

    monkeypatch.setattr(admission, "_control_plane_state",
                        lambda: (EMERGENCY_EVENTS, None))
    monkeypatch.setattr(admission, "_active_job_count", lambda: 0)


def _auth(client):
    token = client.post("/api/v1/auth/login",
                        json={"username": "admin", "password": "cryptoscan"}
                        ).json()["token"]
    return {"Authorization": f"Bearer {token}"}


HARDWARE_BACKED_KEY = {
    "key_ref": "arn:aws:kms:us-east-1:000000000000:key/hsm-backed",
    "provider": "aws_kms",
    "describe": {"origin": "AWS_CLOUDHSM", "protection_level": "HARDWARE",
                 "state": "Enabled"},
}
SOFTWARE_KEY = {
    "key_ref": "arn:aws:kms:us-east-1:000000000000:key/aws-managed",
    "provider": "aws_kms",
    "describe": {"origin": "AWS_KMS", "protection_level": "SOFTWARE"},
}


def test_hsm_scan_leaves_durable_completed_record(client, monkeypatch):
    _pin_ok(monkeypatch)
    r = client.post("/api/v1/hsm-scans", headers=_auth(client),
                    json={"keys": [HARDWARE_BACKED_KEY, SOFTWARE_KEY], "live": False})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["job_id"], "response must identify the durable run"
    assert body["summary"]["verification_mode"] == "SUBMITTED"
    assert body["summary"]["hardware_backed"] == 1
    assert body["summary"]["software_keys"] == 1
    modes = {res["verification_mode"] for res in body["results"]}
    assert modes == {"SUBMITTED"}, "submitted mode must be labeled on every result"

    job = client.get(f"/api/v1/jobs/{body['job_id']}", headers=_auth(client)).json()
    assert job["status"] == "COMPLETED"
    assert job["job_type"] == "HSM_KEY_CHECK"
    assert job["progress"]["admission"]["mode"] == "standard"
    assert job["progress"]["run"]["live"] is False
    # coverage is bounded counts, never key material or finding content
    assert job["progress"]["coverage"]["hardware_backed"] == 1
    assert job["progress"]["coverage"]["total"] == 2
    assert "key_ref" not in job["progress"]["coverage"]
    assert job["started_at"] and job["completed_at"]


def test_hsm_live_mode_refused_without_credentials(client, monkeypatch):
    _pin_ok(monkeypatch)
    monkeypatch.delenv("CRYPTOSCAN_HSM_LIVE", raising=False)
    r = client.post("/api/v1/hsm-scans", headers=_auth(client),
                    json={"keys": [HARDWARE_BACKED_KEY], "live": True})
    assert r.status_code == 403
    assert "CRYPTOSCAN_HSM_LIVE" in r.json()["detail"]
    # the refusal left no invented run
    jobs = client.get("/api/v1/jobs", headers=_auth(client)).json()
    hsm_jobs = [j for j in jobs.get("jobs", []) if j.get("job_type") == "HSM_KEY_CHECK"]
    assert hsm_jobs == []


def test_hsm_scan_refused_on_emergency_stop(client, monkeypatch):
    _pin_emergency(monkeypatch)
    r = client.post("/api/v1/hsm-scans", headers=_auth(client),
                    json={"keys": [HARDWARE_BACKED_KEY], "live": False})
    assert r.status_code == 409
    assert "emergency stop" in r.json()["detail"].lower()


def test_hsm_scan_records_are_tenant_bound(client, monkeypatch):
    _pin_ok(monkeypatch)
    from api.security.session_manager import SessionManager
    from db.connection.session import SessionLocal
    from db.repositories.tenant_repository import TenantRepository

    session = SessionLocal()
    try:
        tenants = TenantRepository(session)
        tenants.ensure_user("member-a")
        tenants.ensure_user("member-b")
        tenant_a = tenants.create(name="HSM Alpha", slug="hsm-alpha", created_by="member-a")
        tenant_b = tenants.create(name="HSM Beta", slug="hsm-beta", created_by="member-b")
        tenants.add_member(tenant_a.id, "member-a", "member")
        tenants.add_member(tenant_b.id, "member-b", "member")
        session.commit()
        tenant_a_id, tenant_b_id = tenant_a.id, tenant_b.id
    finally:
        session.close()

    def auth(username: str, tenant: str) -> dict[str, str]:
        token = SessionManager().create_session(username, roles=["readonly"])
        return {"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant}

    created = client.post("/api/v1/hsm-scans", headers=auth("member-a", tenant_a_id),
                          json={"keys": [HARDWARE_BACKED_KEY]})
    assert created.status_code == 200, created.text
    job_id = created.json()["job_id"]
    assert client.get(f"/api/v1/jobs/{job_id}",
                      headers=auth("member-a", tenant_a_id)).status_code == 200
    assert client.get(f"/api/v1/jobs/{job_id}",
                      headers=auth("member-b", tenant_b_id)).status_code == 404


def _fake_ct_report(domain, *, new=0, rogue=0, observed=2):
    """A CtReport-shaped object for the deterministic (injected) monitor."""
    from keyassure.ct_monitor import CtReport

    return CtReport(
        domain=domain,
        observed=[{"id": i, "domain": domain} for i in range(observed)],
        new_certs=[{"id": f"new-{i}", "domain": domain} for i in range(new)],
        rogue_certs=[{"id": f"rogue-{i}", "domain": domain} for i in range(rogue)],
        known_certs=observed - new,
    )


def test_ct_scan_leaves_durable_record_with_honest_errors(client, monkeypatch):
    _pin_ok(monkeypatch)
    import keyassure.ct_monitor as ct_module

    def fake_monitor(domain, *, known_serials=(), allowed_issuers=(), **kwargs):
        if domain == "broken.example":
            raise ct_module.CtMonitorError("CT source unavailable")
        return _fake_ct_report(domain, new=1, rogue=1, observed=3)

    monkeypatch.setattr(ct_module, "monitor_domain", fake_monitor)
    r = client.post("/api/v1/ct-scans", headers=_auth(client),
                    json={"domains": ["good.example", "broken.example"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["job_id"]
    assert body["summary"]["domains"] == 2
    assert body["summary"]["errors"] == 1
    assert body["summary"]["new_cert_alerts"] == 1
    assert body["summary"]["rogue_cert_alerts"] == 1
    # the uncheckable domain is reported as an error, never folded into green
    by_domain = {rep["domain"]: rep for rep in body["reports"]}
    assert "error" in by_domain["broken.example"]

    job = client.get(f"/api/v1/jobs/{body['job_id']}", headers=_auth(client)).json()
    assert job["status"] == "COMPLETED"
    assert job["job_type"] == "CT_MONITOR"
    assert job["progress"]["coverage"]["domains"] == 2
    assert job["progress"]["coverage"]["observed_certs"] == 3
    assert job["progress"]["coverage"]["errors"] == 1


def test_ct_scan_refused_on_emergency_stop(client, monkeypatch):
    _pin_emergency(monkeypatch)
    r = client.post("/api/v1/ct-scans", headers=_auth(client),
                    json={"domains": ["good.example"]})
    assert r.status_code == 409
    assert "emergency stop" in r.json()["detail"].lower()
