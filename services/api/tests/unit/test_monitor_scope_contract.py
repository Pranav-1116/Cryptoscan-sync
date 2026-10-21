"""Authenticated scope execution uses actual tenant-private DB range grants."""

import pytest

from db.models.crypto_live import CryptoLiveState
from db.models.network_scan_run import NetworkScanRun
from db.models.network_scan_target import NetworkScanTarget
from db.models.onboarding import ScopeEntry
from db.models.scan_job import ScanJob
from db.models.tenant import TenantUsageEvent
from test_monitor_network_contract import banks as banks, contract as contract

CONFIG = {
    "scope_profile": "bounded-tcp",
    "scope": ["10.0.0.0/30"],
    "scope_ports": [443],
    "tenant_id": "b",
    "authorization_scope": "10.0.0.0/24",
}


@pytest.fixture
def scope_contract(contract, monkeypatch):
    clients, db, state, target_id = contract
    # Real authority lookup, not the forged config tenant/authorization string.
    grant = ScopeEntry(tenant_id="a", org_id="org-a", kind="network", target="10.0.0.0/24", enabled=True)
    db.add(grant)
    db.commit()
    assert clients["bank_a"].patch(f"/api/v1/monitor/targets/{target_id}", json={"config": CONFIG}).status_code == 200
    state["scope_calls"] = []

    def discover(cidr, ports, **kwargs):
        state["scope_calls"].append(cidr)
        if state.get("bad_output"):
            return {"error": "controlled failure"}
        return {
            "cidr": cidr,
            "ports": ports,
            "hosts_checked": 2,
            "candidates": 2,
            "truncated": False,
            "endpoints": ["10.0.0.1:443"],
            "open_count": 1,
            "tcp_probes": {"open": 1, "closed": 0, "filtered_timeout": 1},
        }

    monkeypatch.setattr("network_scanner.discovery.subnet_discoverer.discover_subnet", discover)
    return clients, db, state, target_id, grant


def test_authenticated_scope_job_linkage_quota_privacy_and_no_crypto(scope_contract):
    clients, db, state, target_id, _ = scope_contract
    response = clients["bank_a"].post(f"/api/v1/monitor/targets/{target_id}/scan-now")
    assert response.status_code == 200, response.text
    job, ledger = db.query(ScanJob).one(), db.query(NetworkScanRun).one()
    assert job.tenant_id == ledger.tenant_id == "a" and job.triggered_by == "bank_a"
    assert response.json()["job_id"] == job.id and response.json()["run_id"] == ledger.id
    assert ledger.verdict == "NOT_EVALUATED" and db.query(CryptoLiveState).count() == 0
    assert db.query(TenantUsageEvent).filter_by(kind="scan_run").one().amount == 2 and not state["calls"]
    assert clients["bank_b"].get(f"/api/v1/jobs/{job.id}").status_code == 404
    assert clients["bank_b"].get(f"/api/v1/network/runs/{ledger.id}").status_code == 404
    assert clients["bank_a"].post(f"/api/v1/jobs/{job.id}/retry").status_code == 409


@pytest.mark.parametrize("grant_owner,enabled", [("b", True), (None, True), ("a", False)])
@pytest.mark.parametrize("grant_kind", ["scope", "registered"])
def test_other_estate_or_disabled_grant_cannot_authorize_sweep(scope_contract, grant_owner, enabled, grant_kind):
    clients, db, state, target_id, grant = scope_contract
    db.delete(grant)
    db.commit()
    if grant_kind == "scope":
        db.add(
            ScopeEntry(tenant_id=grant_owner, org_id="other-org", kind="network", target="10.0.0.0/24", enabled=enabled)
        )
    else:
        db.add(NetworkScanTarget(tenant_id=grant_owner, endpoint="10.0.0.0/24", enabled=enabled))
    db.commit()
    response = clients["bank_a"].post(f"/api/v1/monitor/targets/{target_id}/scan-now")
    assert response.status_code == 409, response.text
    assert (
        not state["scope_calls"]
        and db.query(ScanJob).count() == db.query(TenantUsageEvent).filter_by(kind="scan_run").count() == 0
    )


@pytest.mark.parametrize("who", ["bank_b", "platform_admin"])
def test_foreign_caller_cannot_execute_scope(scope_contract, who):
    clients, db, state, target_id, _ = scope_contract
    assert clients[who].post(f"/api/v1/monitor/targets/{target_id}/scan-now").status_code == 404
    assert not state["scope_calls"] and db.query(ScanJob).count() == 0


def test_bad_scope_result_is_error_with_owned_failed_job(scope_contract):
    clients, db, state, target_id, _ = scope_contract
    state["bad_output"] = True
    response = clients["bank_a"].post(f"/api/v1/monitor/targets/{target_id}/scan-now")
    assert response.status_code == 500, response.text
    job = db.query(ScanJob).one()
    assert response.json()["detail"]["job_id"] == job.id and job.status == "FAILED"
    assert (
        db.query(NetworkScanRun).count() == 0
        and db.query(TenantUsageEvent).filter_by(kind="scan_run").one().amount == 2
    )


@pytest.mark.parametrize(
    "changes,code", [({"scope_profile": "enterprise"}, 409), ({"scope_ports": []}, 422), ({"plugins": ["snmp"]}, 409)]
)
def test_unqualified_scope_has_explicit_refusal_not_partial_tls(scope_contract, changes, code):
    clients, db, state, target_id, _ = scope_contract
    assert (
        clients["bank_a"]
        .patch(
            f"/api/v1/monitor/targets/{target_id}",
            json={"config": {**CONFIG, **changes, "endpoints": ["10.0.0.8:443"]}},
        )
        .status_code
        == 200
    )
    response = clients["bank_a"].post(f"/api/v1/monitor/targets/{target_id}/scan-now")
    assert response.status_code == code, response.text
    assert not state["scope_calls"] and not state["calls"] and db.query(ScanJob).count() == 0


def test_range_authority_is_exact_estate_even_for_unscoped_platform(scope_contract):
    from api.security.scan_admission import _authorized_network_scope, authorize_network_sweep
    from db.tenancy import tenant_scope

    _, db, _, _, _ = scope_contract
    for owner, suffix in [("a", 1), ("b", 2), (None, 3)]:
        db.add(
            ScopeEntry(tenant_id=owner, org_id="test-org", kind="network", target=f"10.{suffix}.0.0/24", enabled=True)
        )
        db.add(NetworkScanTarget(tenant_id=owner, endpoint=f"10.{suffix}.1.1:443", enabled=True))
    db.commit()
    for owner, suffix in [("a", 1), ("b", 2), (None, 3)]:
        with tenant_scope(owner):
            grants = _authorized_network_scope()
            assert f"10.{suffix}.1.1:443" in grants
            assert all(f"10.{other}.1.1:443" not in grants for other in (1, 2, 3) if other != suffix)
            for other in (1, 2, 3):
                allowed, _ = authorize_network_sweep(f"10.{other}.0.0/30")
                assert allowed is (other == suffix)
