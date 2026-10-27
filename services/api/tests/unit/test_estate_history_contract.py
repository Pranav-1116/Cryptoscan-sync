"""Exact-estate history at authenticated HTTP boundaries, with/without middleware."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from db.models.scan_job import ScanJob
from db.models.network_scan_run import NetworkScanRun
from test_software_supply_chain_api import banks as banks


@pytest.fixture
def history(banks, monkeypatch):
    clients, db, _ = banks
    records = {}
    for n, (who, owner) in enumerate([("bank_a", "a"), ("bank_b", "b"), ("platform_admin", None)]):
        jobs, runs = [], []
        for i in range(2):
            stamp = datetime(2026, 10, 21, tzinfo=timezone.utc) + timedelta(seconds=n * 10 + i)
            job = ScanJob(
                tenant_id=owner,
                target_repo=f"private-{who}-{i}",
                job_type="NETWORK_SCAN",
                triggered_by=who,
                status="FAILED",
                created_at=stamp,
                progress={"execution": "synchronous", "logs": [{"message": f"secret-{who}-{i}"}]},
            )
            run = NetworkScanRun(
                tenant_id=owner,
                target_kind="hosts",
                created_at=stamp,
                result={"findings": [{"endpoint": f"{who}:443", "status": "OK", "crypto": {"tls_version": "TLSv1.3"}}]},
            )
            db.add_all([job, run])
            jobs.append(job)
            runs.append(run)
        records[who] = (jobs, runs)
    db.commit()
    state = {"retry": []}

    def enqueue(*args, **kwargs):
        from db.tenancy import current_tenant

        state["retry"].append((current_tenant(), kwargs))
        return {"job_id": "controlled-retry"}

    monkeypatch.setattr("api.routers.trigger.enqueue_scan_job", enqueue)
    return clients, db, records, state


@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
@pytest.mark.parametrize("resource", ["job", "logs", "retry", "run", "metrics"])
def test_foreign_history_is_not_found_before_content_or_retry(history, who, resource):
    clients, _, records, state = history
    for other, (jobs, runs) in records.items():
        if other == who:
            continue
        path = {
            "job": f"jobs/{jobs[0].id}",
            "logs": f"jobs/{jobs[0].id}/logs",
            "retry": f"jobs/{jobs[0].id}/retry",
            "run": f"network/runs/{runs[0].id}",
            "metrics": f"network/runs/{runs[0].id}/metrics",
        }[resource]
        response = getattr(clients[who], "post" if resource == "retry" else "get")("/api/v1/" + path)
        assert response.status_code == 404, response.text
        assert "private-" not in response.text and "secret-" not in response.text
    assert not state["retry"]


@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
def test_lists_counts_limits_drift_and_owned_content_share_one_estate(history, who):
    clients, _, records, _ = history
    client = clients[who]
    jobs, runs = records[who]
    listed = client.get("/api/v1/jobs?limit=1")
    assert listed.status_code == 200, listed.text
    assert [j["job_id"] for j in listed.json()["jobs"]] == [jobs[-1].id]
    data = client.get("/api/v1/network/runs?limit=1").json()
    assert data["total"] == 2 and [r["id"] for r in data["runs"]] == [runs[-1].id]
    assert client.get(f"/api/v1/jobs/{jobs[0].id}/logs").json()["logs"] == [{"message": f"secret-{who}-0"}]
    assert client.get(f"/api/v1/network/runs/{runs[0].id}").status_code == 200
    assert client.get(f"/api/v1/network/runs/{runs[0].id}/metrics").status_code == 200
    drift = client.get("/api/v1/network/drift/latest").json()
    assert drift["previous_run_id"] == runs[0].id and drift["current_run_id"] == runs[1].id
    assert client.post(f"/api/v1/jobs/{jobs[0].id}/retry").status_code == 409


@pytest.mark.parametrize("who", ["bank_a", "platform_admin"])
def test_history_does_not_require_optional_tenant_middleware(history, who):
    from api.main import create_app

    clients, _, records, _ = history
    with TestClient(create_app()) as client:
        client.cookies.update(clients[who].cookies)
        jobs, runs = records[who]
        assert [j["job_id"] for j in client.get("/api/v1/jobs?limit=1").json()["jobs"]] == [jobs[-1].id]
        assert client.get("/api/v1/network/runs").json()["total"] == 2
        other = "bank_b"
        assert client.get(f"/api/v1/jobs/{records[other][0][0].id}").status_code == 404
        assert client.get(f"/api/v1/network/runs/{records[other][1][0].id}").status_code == 404


def test_platform_can_explicitly_select_bank_but_not_implicitly_inherit_it(history):
    clients, _, records, _ = history
    client = clients["platform_admin"]
    jobs, runs = records["bank_a"]
    headers = {"X-Tenant-ID": "a"}
    assert client.get(f"/api/v1/jobs/{jobs[0].id}", headers=headers).status_code == 200
    assert client.get(f"/api/v1/network/runs/{runs[0].id}", headers=headers).status_code == 200
    assert client.get(f"/api/v1/jobs/{jobs[0].id}").status_code == 404
    assert clients["bank_b"].get(f"/api/v1/jobs/{jobs[0].id}", headers=headers).status_code == 404


def test_retry_uses_selected_estate_and_foreign_retry_cannot_enqueue(history):
    clients, db, records, state = history
    job = records["bank_a"][0][0]
    job.job_type = "MANUAL"
    job.progress = {"scan_options": {"format": "spdx"}}
    db.commit()
    assert clients["platform_admin"].post(f"/api/v1/jobs/{job.id}/retry").status_code == 404
    assert not state["retry"]
    response = clients["bank_a"].post(f"/api/v1/jobs/{job.id}/retry")
    assert response.status_code == 200, response.text
    assert state["retry"][0][0] == "a" and state["retry"][0][1]["scan_options"] == {"format": "spdx"}


def test_internal_repositories_remain_available_to_dispatch_and_reapers(history):
    from db.repositories.job_repository import JobRepository
    from db.repositories.scan_run_repository import ScanRunRepository

    _, db, _, _ = history
    assert len(JobRepository(db).list_recent()) == 6
    assert ScanRunRepository(db).count_runs() == 6


@pytest.mark.parametrize(
    "path",
    [
        "jobs",
        "jobs/unknown",
        "jobs/unknown/logs",
        "network/runs",
        "network/runs/unknown",
        "network/runs/unknown/metrics",
        "network/drift/latest",
    ],
)
def test_anonymous_history_is_not_available(history, path):
    from api.main import create_app

    with TestClient(create_app()) as client:
        assert client.get("/api/v1/" + path).status_code == 401


def test_scope_resolution_refusals_do_not_fall_back_to_platform_history(history):
    from db.models.tenant import TenantMembership, Tenant

    clients, db, records, state = history
    job_id = records["bank_a"][0][0].id
    db.query(TenantMembership).filter_by(username="bank_a").delete()
    db.commit()
    assert clients["bank_a"].get(f"/api/v1/jobs/{job_id}").status_code == 403
    assert clients["bank_a"].get("/api/v1/network/runs").status_code == 403
    db.get(Tenant, "b").status = "SUSPENDED"
    db.commit()
    assert clients["bank_b"].get("/api/v1/jobs").status_code == 423
    assert clients["bank_b"].post(f"/api/v1/jobs/{job_id}/retry").status_code == 423
    assert not state["retry"]


def test_empty_owned_history_does_not_fill_from_other_estates(history):
    clients, db, _, _ = history
    db.query(ScanJob).filter_by(tenant_id="a").delete()
    db.query(NetworkScanRun).filter_by(tenant_id="a").delete()
    db.commit()
    assert clients["bank_a"].get("/api/v1/jobs").json() == {"jobs": [], "total_count": 0}
    assert clients["bank_a"].get("/api/v1/network/runs").json() == {"runs": [], "total": 0}
    drift = clients["bank_a"].get("/api/v1/network/drift/latest").json()
    assert drift["change_count"] == 0 and "current_run_id" not in drift and "only 0" in drift["detail"]


def test_exact_owner_predicates_apply_to_cached_objects_and_filtered_counts(history):
    from db.repositories.job_repository import JobRepository
    from db.repositories.scan_run_repository import ScanRunRepository
    from db.tenancy import tenant_scope

    _, db, records, _ = history
    jobs, runs = JobRepository(db), ScanRunRepository(db)
    bank_job, bank_run = records["bank_a"][0][0], records["bank_a"][1][0]
    assert jobs.get_by_id(bank_job.id) is bank_job
    assert runs.get_run(bank_run.id) is bank_run
    assert jobs.get_by_id(bank_job.id, owner=None) is None
    assert runs.get_run(bank_run.id, owner=None) is None
    assert jobs.get_by_id(bank_job.id, owner="b") is None
    assert runs.get_run(bank_run.id, owner="b") is None
    with tenant_scope("a"):
        assert jobs.get_by_id(records["bank_b"][0][0].id, owner="b") is None
        assert runs.count_runs(owner="b") == 0
    for owner in ("a", "b", None):
        assert runs.count_runs(owner=owner, target_kind="hosts") == 2
        assert runs.count_runs(owner=owner, target_kind="monitor") == 0
