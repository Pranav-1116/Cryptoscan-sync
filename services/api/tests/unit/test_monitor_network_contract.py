"""Authenticated monitor scan-now entry point uses the worker admission contract."""

import pytest

from db.models.scan_job import ScanJob
from db.models.network_scan_run import NetworkScanRun
from test_software_supply_chain_api import banks as banks


@pytest.fixture
def contract(banks, monkeypatch):
    clients, db, _ = banks
    import api.security.scan_admission as admission

    state = {"policy": {}, "calls": []}
    monkeypatch.setattr(admission, "_control_plane_state", lambda: ([], state["policy"]))
    monkeypatch.setattr(admission, "_ot_declared", lambda: False)
    monkeypatch.setattr(admission, "_active_job_count", lambda: 0)

    def scan(self, hosts):
        state["calls"].append(list(hosts))
        return {"findings": [], "probe_telemetry": {"status": "OK", "probed": len(hosts), "ok": len(hosts)}}

    monkeypatch.setattr("network_scanner.core.scanner.NetworkTlsScanner.scan_hosts", scan)
    response = clients["bank_a"].post(
        "/api/v1/monitor/targets",
        json={
            "name": "bank-edge",
            "target_type": "NETWORK",
            "config": {"endpoints": ["10.0.0.1:443"], "tenant_id": "b"},
        },
    )
    assert response.status_code == 201, response.text
    yield clients, db, state, response.json()["id"]


def test_owned_monitor_has_authenticated_actor_linkage_and_private_job_history(contract):
    clients, db, state, target_id = contract
    response = clients["bank_a"].post(f"/api/v1/monitor/targets/{target_id}/scan-now")
    assert response.status_code == 200, response.text
    job = db.query(ScanJob).one()
    ledger = db.query(NetworkScanRun).one()
    assert job.triggered_by == "bank_a" and job.tenant_id == ledger.tenant_id == "a"
    assert response.json()["job_id"] == job.id and response.json()["run_id"] == ledger.id
    assert clients["bank_a"].get(f"/api/v1/jobs/{job.id}").status_code == 200
    assert clients["bank_b"].get(f"/api/v1/jobs/{job.id}").status_code == 404
    assert clients["bank_a"].post(f"/api/v1/jobs/{job.id}/retry").status_code == 409
    assert state["calls"] == [["10.0.0.1:443"]]


@pytest.mark.parametrize("who", ["bank_b", "platform_admin"])
def test_foreign_or_platform_caller_cannot_execute_bank_monitor(contract, who):
    clients, db, state, target_id = contract
    response = clients[who].post(f"/api/v1/monitor/targets/{target_id}/scan-now")
    assert response.status_code == 404
    assert not state["calls"] and db.query(ScanJob).count() == 0


@pytest.mark.parametrize(
    "policy,code", [({"emergency_stop": True}, 409), ({"mode": "passive"}, 409), ({"excluded_ports": [443]}, 409)]
)
def test_scan_now_returns_policy_refusal_not_http_success(contract, policy, code):
    clients, db, state, target_id = contract
    state["policy"] = policy
    response = clients["bank_a"].post(f"/api/v1/monitor/targets/{target_id}/scan-now")
    assert response.status_code == code, response.text
    assert not state["calls"] and db.query(ScanJob).count() == db.query(NetworkScanRun).count() == 0


def test_executor_failure_returns_error_with_owned_failed_job(contract, monkeypatch):
    clients, db, _, target_id = contract

    def broken(*args, **kwargs):
        raise TimeoutError("controlled timeout")

    monkeypatch.setattr("network_scanner.core.scanner.NetworkTlsScanner.scan_hosts", broken)
    response = clients["bank_a"].post(f"/api/v1/monitor/targets/{target_id}/scan-now")
    assert response.status_code == 500
    job = db.query(ScanJob).one()
    assert response.json()["detail"]["job_id"] == job.id
    assert job.status == "FAILED" and db.query(NetworkScanRun).count() == 0
