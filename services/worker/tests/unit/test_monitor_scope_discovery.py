"""Bounded TCP-only monitor scope: real SQL, controlled policy and packets."""

from copy import deepcopy
import errno
import ipaddress

import pytest
from sqlalchemy.orm import Session

from db.models.crypto_live import CryptoLiveEventRow, CryptoLiveState
from db.models.network_scan_run import NetworkScanRun
from db.models.scan_job import ScanJob
from db.models.tenant import TenantUsageEvent
from network_scanner.discovery.subnet_discoverer import discover_subnet as real_discover_subnet
from db.tenancy import current_tenant
from services.worker.tests.unit.test_monitor_network_admission import contract as contract, run

PROFILE = {"scope_profile": "bounded-tcp", "scope": ["10.0.0.0/30"], "scope_ports": [80, 443]}


@pytest.fixture
def scope_contract(contract, monkeypatch):
    db, state = contract
    state.update(authorized=["10.0.0.0/24"], scope_calls=[])
    monkeypatch.setattr("api.security.scan_admission._authorized_network_scope", lambda: state["authorized"])

    def discover(cidr, ports, **kwargs):
        with Session(db.get_bind()) as observer:
            job = observer.query(ScanJob).filter_by(status="RUNNING").one()
            assert job.tenant_id == current_tenant() == "a"
            assert job.progress["phase_admission"][-1]["execution_range"] == cidr
        state["scope_calls"].append((cidr, list(ports), kwargs))
        network = ipaddress.ip_network(cidr)
        candidates = len(list(network.hosts())) * len(ports)
        result = {
            "cidr": cidr,
            "ports": sorted(ports),
            "hosts_checked": len(list(network.hosts())),
            "candidates": candidates,
            "truncated": False,
            "endpoints": [f"{next(network.hosts())}:{ports[0]}"],
            "open_count": 1,
            "tcp_probes": {"open": 1, "closed": candidates - 1, "filtered_timeout": 0},
            # Registry hints / arbitrary SDK fields are not verified crypto.
            "services": [{"protocol": "TLS", "algorithm": "INVENTED-ALGORITHM"}],
        }
        result.update(deepcopy(state.get("reply", {})))
        if state.get("stop_after_scope"):
            state["policy"] = {"emergency_stop": True}
        if state.get("revoke_after_scope"):
            state["authorized"] = []
        if state.get("fault"):
            raise TimeoutError("controlled discovery failure")
        return result

    monkeypatch.setattr("network_scanner.discovery.subnet_discoverer.discover_subnet", discover)
    return db, state


def test_bounded_scope_has_job_receipts_no_tls_or_crypto_fabrication(scope_contract):
    db, state = scope_contract
    row, outcome = run(scope_contract, config=PROFILE)
    assert outcome["status"] == "DEGRADED" and row.last_scan_at is None
    assert len(state["scope_calls"]) == 1 and not state["calls"] and state["constructs"] == 0
    assert state["scope_calls"][0][2] == {"timeout": 5.0, "workers": 8, "max_targets": 256}
    job, ledger = db.query(ScanJob).one(), db.query(NetworkScanRun).one()
    assert job.status == "COMPLETED" and ledger.result["collection"]["job_id"] == job.id
    assert ledger.verdict == "NOT_EVALUATED" and ledger.ok is ledger.probed is None
    assert db.query(TenantUsageEvent).one().amount == 4
    assert ledger.result["scope_discovery"][0]["tls_status"] == "NOT_EVALUATED"
    assert "INVENTED-ALGORITHM" not in str(ledger.result)
    assert db.query(CryptoLiveState).count() == db.query(CryptoLiveEventRow).count() == 0


@pytest.mark.parametrize(
    "condition",
    ["unauthorized", "stop", "outage", "ot", "excluded-port", "excluded-host", "excluded-protocol", "quota"],
)
def test_refused_scope_has_no_discovery_or_other_phase_side_effects(scope_contract, monkeypatch, condition):
    db, state = scope_contract
    if condition == "unauthorized":
        state["authorized"] = ["10.0.1.0/24"]
    if condition == "stop":
        state["policy"] = {"emergency_stop": True}
    if condition == "outage":
        state["outage"] = True
    if condition == "ot":
        state["ot"] = True
    if condition == "excluded-port":
        state["policy"] = {"excluded_ports": [80]}
    if condition == "excluded-host":
        state["policy"] = {"excluded_assets": ["10.0.0.2"]}
    if condition == "excluded-protocol":
        state["policy"] = {"excluded_protocols": ["tcp"]}
    if condition == "quota":
        monkeypatch.setattr("api.security.tenancy.quota_check", lambda *a: (False, "quota"))
    row, outcome = run(scope_contract, config={**PROFILE, "endpoints": ["10.0.0.10:443"]})
    assert outcome["status"] == "BLOCKED" and row.last_scan_at is None
    assert not state["scope_calls"] and not state["calls"] and state["constructs"] == 0
    assert db.query(ScanJob).count() == db.query(NetworkScanRun).count() == db.query(TenantUsageEvent).count() == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"scope_profile": "enterprise"},
        {"scope_ports": []},
        {"scope_ports": [True]},
        {"scope_ports": [65536]},
        {"scope_ports": "443"},
        {"scope": ["10.0.0.0/16"]},
        {"scope": ["::/126"]},
        {"scope": ["127.0.0.0/30"]},
        {"scope": ["169.254.169.254/32"]},
        {"scope": ["*.bank.example"]},
        {"scope": ["snmp:10.0.0.1"]},
        {"scope": ["10.0.0.0/30", "10.0.0.0/31"]},
        {"plugins": ["snmp"]},
    ],
)
def test_unqualified_shape_refused_before_executor(scope_contract, changes):
    db, state = scope_contract
    _, outcome = run(scope_contract, config={**PROFILE, **changes})
    assert outcome["status"] == "BLOCKED"
    assert not state["scope_calls"] and not state["calls"] and db.query(ScanJob).count() == 0


@pytest.mark.parametrize(
    "reply",
    [
        {"cidr": "10.1.0.0/30"},
        {"ports": [22]},
        {"hosts_checked": True},
        {"candidates": 999},
        {"truncated": True},
        {"truncated": None},
        {"error": "partial collection"},
        {"endpoints": ["10.0.1.1:80"]},
        {"endpoints": ["bank.example:80"]},
        {"endpoints": ["10.0.0.1:22"]},
        {"endpoints": ["10.0.0.0:80"]},
        {"endpoints": ["10.0.0.1:80", "10.0.0.1:80"]},
        {"open_count": 0},
        {"tcp_probes": {"open": 1, "closed": 0, "filtered_timeout": 0}},
    ],
)
def test_bad_or_truncated_output_cannot_be_accepted(scope_contract, reply):
    db, state = scope_contract
    state["reply"] = reply
    row, outcome = run(scope_contract, config=PROFILE)
    assert outcome["status"] == "DEGRADED" and row.last_scan_at is None
    assert db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanRun).count() == db.query(CryptoLiveState).count() == 0
    assert not state["calls"]


@pytest.mark.parametrize("condition", ["stop", "revoke"])
def test_ranges_recheck_policy_and_authorization(scope_contract, condition):
    db, state = scope_contract
    state["stop_after_scope" if condition == "stop" else "revoke_after_scope"] = True
    _, outcome = run(scope_contract, config={**PROFILE, "scope": ["10.0.0.0/30", "10.0.0.4/30"]})
    assert outcome["status"] == "BLOCKED" and len(state["scope_calls"]) == 1
    assert db.query(ScanJob).one().status == "FAILED" and db.query(NetworkScanRun).count() == 0


def test_mixed_profile_uses_fixed_tls_only_not_discovery_followup(scope_contract):
    db, state = scope_contract
    _, outcome = run(scope_contract, config={**PROFILE, "endpoints": ["10.0.0.10:443"]})
    assert outcome["status"] == "DEGRADED" and state["calls"] == ["tls"]
    assert db.query(TenantUsageEvent).one().amount == 5
    assert db.query(NetworkScanRun).one().verdict == "PARTIAL"


@pytest.mark.parametrize(
    "code,expected",
    [
        (errno.ECONNREFUSED, "closed"),
        (errno.EACCES, "filtered"),
        (errno.EINVAL, "filtered"),
        (errno.ENETUNREACH, "filtered"),
    ],
)
def test_local_socket_error_is_not_invented_remote_refusal(monkeypatch, code, expected):
    from network_scanner.discovery.subnet_discoverer import _tcp_probe

    def broken(*args, **kwargs):
        raise OSError(code, "controlled error")

    monkeypatch.setattr("socket.create_connection", broken)
    assert _tcp_probe("10.0.0.1:443", 1) == expected


@pytest.mark.parametrize("has_observation", [False, True])
def test_control_receipts_and_discovery_are_not_crypto_observations(scope_contract, has_observation):
    from types import SimpleNamespace
    from db.tenancy import tenant_scope
    from worker.monitor.realtime_projection import persist_monitor_projection

    db, _ = scope_contract
    payload = {
        "collection": {"phase_admission": [{"protocol": "TLS", "algorithm": "FORGED-CONTROL"}]},
        "monitor": {"algorithm": "FORGED-COVERAGE"},
        "scope_discovery": [{"algorithm": "FORGED-PORT-HINT"}],
    }
    if has_observation:
        payload["findings"] = [{"endpoint": "10.0.0.1:443", "crypto": {"algorithm": "AES"}}]
    with tenant_scope("a"):
        persist_monitor_projection(
            SimpleNamespace(id="edge", target_type="NETWORK", tenant_id="a"),
            {"scanner": "network", "data": payload, "observation_complete": False},
            db,
        )
        db.commit()
    states = db.query(CryptoLiveState).all()
    assert len(states) == int(has_observation)
    assert "FORGED" not in str([s.cbom for s in states])


@pytest.mark.parametrize("change", ["pause", "suspend", "config"])
def test_authority_reloaded_between_ranges(scope_contract, monkeypatch, change):
    from db.models.monitor import MonitorTarget
    from db.models.tenant import Tenant
    from db.tenancy import tenant_scope
    from network_scanner.discovery import subnet_discoverer as sdk

    db, state = scope_contract
    previous = sdk.discover_subnet

    def discover(*args, **kwargs):
        result = previous(*args, **kwargs)
        with Session(db.get_bind()) as other, tenant_scope("a"):
            if change == "suspend":
                other.get(Tenant, "a").status = "SUSPENDED"
            else:
                row = other.query(MonitorTarget).one()
                if change == "pause":
                    row.enabled = False
                else:
                    row.config = {**PROFILE, "scope_ports": [22]}
            other.commit()
        return result

    monkeypatch.setattr(sdk, "discover_subnet", discover)
    _, outcome = run(scope_contract, config={**PROFILE, "scope": ["10.0.0.0/30", "10.0.0.4/30"]})
    assert outcome["status"] == "BLOCKED" and len(state["scope_calls"]) == 1
    assert db.query(ScanJob).one().status == "FAILED" and db.query(NetworkScanRun).count() == 0


def test_permission_lookup_outage_is_fail_closed(scope_contract, monkeypatch):
    db, state = scope_contract

    def unavailable():
        raise RuntimeError("scope registry unavailable")

    monkeypatch.setattr("api.security.scan_admission._authorized_network_scope", unavailable)
    _, outcome = run(scope_contract, config=PROFILE)
    assert outcome["status"] == "BLOCKED" and outcome["refusal_status"] == 503
    assert not state["scope_calls"] and db.query(ScanJob).count() == 0


def test_socket_candidate_cap_precedes_host_enumeration(monkeypatch):
    from fastapi import HTTPException
    from worker.monitor.network_collection import prepare

    def forbidden(*args, **kwargs):
        pytest.fail("oversized CIDR was enumerated")

    monkeypatch.setattr(ipaddress.IPv4Network, "hosts", forbidden)
    for scope, ports in [(["10.0.0.0/16"], [443]), (["10.0.0.0/24"], [80, 443])]:
        with pytest.raises(HTTPException) as refused:
            prepare({**PROFILE, "scope": scope, "scope_ports": ports})
        assert refused.value.status_code == 422


def test_combined_boundary_and_canonical_deduplication():
    from fastapi import HTTPException
    from worker.monitor.network_collection import prepare

    plan = prepare(
        {
            **PROFILE,
            "scope": ["10.0.0.0/24", "10.0.0.9/24"],
            "scope_ports": [443, 443],
            "endpoints": ["10.0.1.1:443", "10.0.1.2:443"],
        }
    )
    assert len(plan.units) == 256 and plan.config["scope"] == ["10.0.0.0/24"]
    with pytest.raises(HTTPException):
        prepare({**plan.config, "endpoints": plan.config["endpoints"] + ["10.0.1.3:443"]})
    assert len(prepare({**PROFILE, "scope": ["10.0.0.1"], "scope_ports": [443]}).units) == 1
    assert len(prepare({**PROFILE, "scope": ["10.0.0.0/31"], "scope_ports": [443]}).units) == 2


def test_bounded_adapter_without_context_cannot_execute(scope_contract):
    from worker.monitor.runners import network_runner

    _, state = scope_contract
    result = network_runner(PROFILE, scope_contract[0])
    assert result.get("blocked_reason") and not state["scope_calls"] and state["constructs"] == 0


def test_actual_tcp_sdk_stays_inside_admitted_candidates(scope_contract, monkeypatch):
    from network_scanner.discovery import subnet_discoverer as sdk

    db, state = scope_contract
    packets = []

    def probe(endpoint, timeout):
        packets.append(endpoint)
        return "open" if endpoint == "10.0.0.1:443" else "filtered"

    def discover(cidr, *args, **kwargs):
        with Session(db.get_bind()) as observer:
            job = observer.query(ScanJob).filter_by(status="RUNNING").one()
            assert job.progress["phase_admission"][-1]["execution_range"] == cidr
        return real_discover_subnet(cidr, *args, **kwargs)

    monkeypatch.setattr(sdk, "discover_subnet", discover)
    monkeypatch.setattr(sdk, "_tcp_probe", probe)
    _, outcome = run(scope_contract, config=PROFILE)
    assert outcome["status"] == "DEGRADED" and len(packets) == 4
    assert set(packets) == {f"10.0.0.{i}:{p}" for i in (1, 2) for p in (80, 443)}
    ledger = db.query(NetworkScanRun).one()
    assert ledger.result["scope_discovery"][0]["tcp_probes"] == {"open": 1, "closed": 0, "filtered_timeout": 3}
    assert not state["calls"] and state["constructs"] == 0


def test_discovery_fault_retains_failed_admitted_attempt(scope_contract):
    db, state = scope_contract
    state["fault"] = True
    _, outcome = run(scope_contract, config=PROFILE)
    assert outcome["execution_failed"] is True
    assert db.query(ScanJob).one().status == "FAILED" and db.query(TenantUsageEvent).one().amount == 4
    assert db.query(NetworkScanRun).count() == 0


@pytest.mark.parametrize("fault", ["cas", "commit"])
def test_phase_receipt_fault_prevents_first_tcp_connection(scope_contract, monkeypatch, fault):
    from db.repositories.job_repository import JobRepository

    db, state = scope_contract
    if fault == "cas":
        original = JobRepository.update_status

        def update(self, job_id, status, **kwargs):
            if status == "RUNNING" and (kwargs.get("progress") or {}).get("phase_admission"):
                return None
            return original(self, job_id, status, **kwargs)

        monkeypatch.setattr(JobRepository, "update_status", update)
    else:
        original = db.commit

        def commit():
            job = db.query(ScanJob).filter_by(status="RUNNING").first()
            if job is not None and (job.progress or {}).get("phase_admission") and not state.get("commit_fault"):
                state["commit_fault"] = True
                raise RuntimeError("receipt commit failed")
            return original()

        monkeypatch.setattr(db, "commit", commit)
    _, outcome = run(scope_contract, config=PROFILE)
    assert outcome["execution_failed"] is True and not state["scope_calls"]
    assert db.query(ScanJob).one().status == "FAILED" and db.query(NetworkScanRun).count() == 0


def test_each_range_receipt_only_readmits_executing_range(scope_contract, monkeypatch):
    from worker.monitor import scope_discovery

    db, state = scope_contract
    checks = []
    original = scope_discovery.authorize_network_sweep

    def authorize(cidr):
        checks.append(cidr)
        return original(cidr)

    monkeypatch.setattr(scope_discovery, "authorize_network_sweep", authorize)
    ranges = ["10.0.0.0/30", "10.0.0.4/30"]
    _, outcome = run(scope_contract, config={**PROFILE, "scope": ranges})
    assert outcome["status"] == "DEGRADED" and checks == ranges + ranges
    receipts = db.query(ScanJob).one().progress["phase_admission"]
    assert len(receipts) == len(state["scope_calls"]) == 2
    for cidr, receipt in zip(ranges, receipts):
        assert receipt["execution_range"] == cidr
        assert {d["target"] for d in receipt["phases"][0]["admission"]["decisions"]} == {cidr}
