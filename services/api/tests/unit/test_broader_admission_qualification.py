"""Additional A01/A02 evidence, with explicit expected failures for open A04 gaps.

No network/SSH/plugin/worker collector actually runs here. Passing admission
negatives are not proof of durable SSH collection, granular regional grants,
atomic budgets, signed queue authority, or live bank qualification.
"""

import pytest
from fastapi.testclient import TestClient
from api.main import create_app
from api.middleware.tenant_scope import TenantScopeMiddleware
from db.models.scan_job import ScanJob as JobRow
from db.repositories.user_repository import UserRepository
from db.tenancy import current_tenant
from test_software_supply_chain_api import banks as banks


@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
@pytest.mark.parametrize("fault", ["stop", "outage", "port", "protocol", "target", "ot"])
def test_ssh_refusal_precedes_both_keyscan_and_kex(banks, monkeypatch, who, fault):
    from api.security import scan_admission as gate

    clients, _, _ = banks

    def never(*args, **kwargs):
        raise AssertionError("Refused SSH collector ran")

    monkeypatch.setattr("network_scanner.probing.ssh_keyscan.scan_ssh_host_keys", never)
    monkeypatch.setattr("network_scanner.probing.ssh_kex.probe_ssh_kex_offer", never)
    policy = {"mode": "standard"}
    if fault == "port":
        policy["excluded_ports"] = [22]
    if fault == "protocol":
        policy["excluded_protocols"] = ["ssh"]
    if fault == "target":
        policy["excluded_assets"] = ["10.21.0.10"]
    events = [{"event_type": "safe_scan.emergency_stop", "payload": {"engaged": True}}] if fault == "stop" else []

    def state():
        if fault == "outage":
            raise RuntimeError("private database unavailable")
        return events, policy

    monkeypatch.setattr(gate, "_control_plane_state", state)
    monkeypatch.setattr(gate, "_active_job_count", lambda: 0)
    monkeypatch.setattr(gate, "_ot_declared", lambda: fault == "ot")
    response = clients[who].post("/api/v1/network/ssh-scan", json={"hosts": ["10.21.0.10"], "include_kex": True})
    assert response.status_code == (503 if fault == "outage" else 409), response.text
    assert "private database" not in response.text


@pytest.mark.parametrize("middleware", [False, True])
@pytest.mark.parametrize("who,owner", [("bank_a", "a"), ("bank_b", "b"), ("platform_admin", None)])
def test_ssh_admission_and_receipt_have_authoritative_estate(banks, monkeypatch, middleware, who, owner):
    from api.security import scan_admission as gate

    clients, _, _ = banks
    seen = []

    def state():
        seen.append(current_tenant())
        return [], {"mode": "standard"}

    monkeypatch.setattr(gate, "_control_plane_state", state)
    monkeypatch.setattr(gate, "_active_job_count", lambda: 0)
    monkeypatch.setattr(gate, "_ot_declared", lambda: False)
    monkeypatch.setattr(
        "network_scanner.probing.ssh_keyscan.scan_ssh_host_keys",
        lambda *args, **kwargs: {"endpoint": "10.21.0.10:22", "status": "LOCAL_UNSUPPORTED", "keys": []},
    )
    app = create_app()
    if middleware:
        app.add_middleware(TenantScopeMiddleware)
    with TestClient(app) as client:
        client.cookies.update(clients[who].cookies)
        response = client.post("/api/v1/network/ssh-scan", json={"hosts": ["10.21.0.10"]})
        assert response.status_code == 200, response.text
        assert response.json()["admission"]["protocol"] == "ssh"
        assert response.json()["collection"]["durable"] is True
        assert set(seen) == {owner}


@pytest.mark.parametrize(
    "payload",
    [
        {"scope_specs": ["10.21.0.0/24"], "plugins": ["snmp"]},
        {"scope_specs": ["10.21.0.10"], "plugins": ["cisco"]},
        {"scope_specs": ["10.21.0.10"], "plugins": ["none"]},
    ],
)
def test_enterprise_discovery_cannot_bypass_bounded_phase_admission(banks, monkeypatch, payload):
    clients, _, _ = banks

    def never(*args, **kwargs):
        raise AssertionError("Unqualified engine ran")

    monkeypatch.setattr("network_scanner.enterprise.engine.run_network_discovery", never)
    response = clients["bank_a"].post("/api/v1/network/inventory/discover", json=payload)
    assert response.status_code == 409 and "not qualified" in response.text


@pytest.mark.parametrize("fault", ["forged-estate", "disabled-queued-principal"])
def test_generic_queued_execution_needs_authoritative_owner_and_fresh_identity(banks, monkeypatch, fault):
    from worker.core.job_consumer import ScanJob
    from worker.core.job_executor import JobExecutor

    _, db, _ = banks
    row = JobRow(
        id="queued-qualification",
        tenant_id="a",
        target_repo="binary:///approved/image",
        triggered_by="bank_a",
        status="QUEUED",
        job_type="BINARY",
        progress={
            "execution_authority": {"v": 1, "kind": "user", "id": UserRepository(db).get_by_username("bank_a").id}
        },
    )
    db.add(row)
    db.commit()
    if fault == "disabled-queued-principal":
        UserRepository(db).get_by_username("bank_a").is_active = False
        db.commit()
    ran = []
    monkeypatch.setattr("worker.pipeline.binary_job.run_binary_job", lambda job: ran.append(job.tenant_id) or True)
    descriptor = ScanJob(
        job_id=row.id,
        target_repo=row.target_repo,
        triggered_by="bank_a",
        tenant_id="b" if fault == "forged-estate" else "a",
        job_type="BINARY",
    )
    assert JobExecutor().execute(descriptor) is False
    assert ran == []
