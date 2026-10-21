"""SSH durable receipts with real auth/SQL and controlled collectors, no packets."""

import pytest
from sqlalchemy import event
from db.models.scan_job import ScanJob
from db.models.network_scan_run import NetworkScanRun
from db.models.tenant import TenantUsageEvent
from test_software_supply_chain_api import banks as banks


@pytest.fixture()
def ssh(banks, monkeypatch):
    clients, db, _ = banks
    state = {"policy": {}, "calls": [], "fault": None, "status": "OK"}
    monkeypatch.setattr("api.security.scan_admission._control_plane_state", lambda: ([], state["policy"]))
    monkeypatch.setattr("api.security.scan_admission._ot_declared", lambda: False)
    monkeypatch.setattr("api.security.scan_admission._active_job_count", lambda: 0)

    def keyscan(host, port, **kwargs):
        db.expire_all()
        assert db.query(ScanJob).filter_by(status="RUNNING").count() == 1
        state["calls"].append((host, port))
        if state["fault"] == "collector":
            raise RuntimeError("private collector path")
        if state["fault"] == "stop":
            state["policy"] = {"emergency_stop": True}
        return {"endpoint": f"{host}:{port}", "status": state["status"], "keys": []}

    def kex(*args, **kwargs):
        state["calls"].append("kex")
        return {"status": "OK", "policy_issues": []}

    monkeypatch.setattr("network_scanner.probing.ssh_keyscan.scan_ssh_host_keys", keyscan)
    monkeypatch.setattr("network_scanner.probing.ssh_kex.probe_ssh_kex_offer", kex)
    return clients, db, state


@pytest.mark.parametrize("who,owner", [("bank_a", "a"), ("bank_b", "b"), ("platform_admin", None)])
def test_ssh_receipt_is_persisted_before_collection_and_queryable_only_by_owner(ssh, who, owner):
    clients, db, state = ssh
    response = clients[who].post("/api/v1/network/ssh-scan", json={"hosts": ["10.21.0.10"], "include_kex": True})
    assert response.status_code == 200, response.text
    data = response.json()
    db.expire_all()
    job = db.query(ScanJob).one()
    run = db.query(NetworkScanRun).one()
    assert job.status == "COMPLETED" and job.tenant_id == run.tenant_id == owner
    assert data["job_id"] == job.id and data["run_id"] == run.id
    assert run.target_kind == "ssh" and run.result["collection"]["protocol"] == "ssh"
    assert run.result["collection"]["baseline_source"] == "CALLER_SUPPLIED_UNVERIFIED"
    assert data["collection"]["durable"] is True
    assert len(run.result["collection"]["phase_admission"]) == 2
    assert job.progress["coverage"]["protocol"] == "ssh"
    assert clients[who].get("/api/v1/jobs/" + job.id).status_code == 200
    other = "bank_b" if who == "bank_a" else "bank_a"
    assert clients[other].get("/api/v1/jobs/" + job.id).status_code == 404
    assert clients[who].post("/api/v1/jobs/" + job.id + "/retry").status_code == 409
    if owner:
        assert db.query(TenantUsageEvent).one().amount == 1


def test_stop_between_host_keys_and_kex_refuses_second_phase_and_records_failure(ssh):
    clients, db, state = ssh
    state["fault"] = "stop"
    response = clients["bank_a"].post("/api/v1/network/ssh-scan", json={"hosts": ["10.21.0.10"], "include_kex": True})
    assert response.status_code == 409
    assert len(state["calls"]) == 1
    db.expire_all()
    assert db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanRun).count() == 0


@pytest.mark.parametrize("fault", ["collector", "ledger", "completion"])
def test_ssh_storage_or_collector_failure_never_claims_durable_success(ssh, monkeypatch, fault):
    clients, db, state = ssh
    state["fault"] = fault

    def fail(*args, **kwargs):
        raise RuntimeError("private store path")

    if fault == "ledger":
        event.listen(NetworkScanRun, "before_insert", fail)
    if fault == "completion":
        monkeypatch.setattr("api.security.scan_runs.DurableScanRun.succeed", fail)
    try:
        response = clients["bank_a"].post("/api/v1/network/ssh-scan", json={"hosts": ["10.21.0.10"]})
    finally:
        if fault == "ledger":
            event.remove(NetworkScanRun, "before_insert", fail)
    assert response.status_code == 503 and "private" not in response.text
    db.expire_all()
    assert db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanRun).count() == 0


def test_failed_observation_remains_failed_even_when_receipt_completes(ssh):
    clients, db, state = ssh
    state["status"] = "TIMEOUT"
    response = clients["bank_a"].post("/api/v1/network/ssh-scan", json={"hosts": ["10.21.0.10"]})
    assert response.status_code == 200
    db.expire_all()
    assert db.query(ScanJob).one().status == "COMPLETED"
    assert db.query(NetworkScanRun).one().verdict == "FAILED"
    assert response.json()["probe_telemetry"]["ok"] == 0


def test_initial_receipt_failure_prevents_any_collector(ssh, monkeypatch):
    clients, db, state = ssh

    def fail(*args, **kwargs):
        raise RuntimeError("initial receipt refused")

    monkeypatch.setattr("api.security.scan_runs.DurableScanRun.__enter__", fail)
    with pytest.raises(RuntimeError, match="initial receipt refused"):
        clients["bank_a"].post("/api/v1/network/ssh-scan", json={"hosts": ["10.21.0.10"]})
    assert not state["calls"]
    assert db.query(NetworkScanRun).count() == 0
