"""Real monitor SQL lifecycle, controlled policy/executors; no bank packets."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401
from db.connection.session import Base
from db.models.crypto_live import CryptoLiveState
from db.models.monitor import MonitorEvent
from db.models.network_scan_run import NetworkScanRun
from db.models.scan_job import ScanJob
from db.models.tenant import Tenant, TenantUsageEvent
from db.repositories.monitor_repository import MonitorRepository
from db.tenancy import current_tenant, install_tenant_guard
from worker.monitor.engine import MonitorEngine

NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
CONFIGS = {
    "tls": {"endpoints": ["10.0.0.1:443"]},
    "ipsec": {"ipsec": ["10.0.0.2"]},
    "dnssec": {"dnssec": ["bank.example"], "dns_resolver": "10.0.0.53:53", "check_zone_transfer": True},
    "mixed": {
        "endpoints": ["10.0.0.1:443"],
        "ipsec": ["10.0.0.2"],
        "dnssec": ["bank.example"],
        "dns_resolver": "10.0.0.53:53",
    },
}


@pytest.fixture
def contract(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'monitor.db'}")
    Base.metadata.create_all(engine)
    install_tenant_guard()
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    db = factory()
    db.add(Tenant(id="a", name="Bank A", slug="bank-a", status="ACTIVE", plan="ENTERPRISE"))
    db.commit()
    state = {"policy": {}, "calls": [], "outage": False, "ot": False, "queue": 0, "constructs": 0}
    import api.security.scan_admission as admission

    def policy():
        if state["outage"]:
            raise RuntimeError("policy unavailable")
        return [], deepcopy(state["policy"])

    monkeypatch.setattr(admission, "_control_plane_state", policy)
    monkeypatch.setattr(admission, "_ot_declared", lambda: state["ot"])
    monkeypatch.setattr(admission, "_active_job_count", lambda: state["queue"])
    monkeypatch.setenv("MAX_QUEUE_DEPTH", "5")

    class Scanner:
        def __init__(self, **kwargs):
            state["constructs"] += 1

        def observe(self, phase):
            with factory() as observer:
                job = observer.query(ScanJob).filter_by(status="RUNNING").one()
                assert job.tenant_id == current_tenant() == "a"
                assert job.progress["phase_admission"][-1]["phases"][0]["phase"] == phase
            state["calls"].append(phase)
            if state.get("fail") == phase:
                raise TimeoutError("controlled executor failure")
            if state.get("stop_after") == phase:
                state["policy"] = {"emergency_stop": True}
            if state.get("change_after") == phase:
                with factory() as other:
                    if state["change"] == "suspend":
                        other.get(Tenant, "a").status = "SUSPENDED"
                    else:
                        from db.models.monitor import MonitorTarget

                        target = other.query(MonitorTarget).one()
                        if state["change"] == "pause":
                            target.enabled = False
                        else:
                            target.config = {"endpoints": ["10.0.0.99:443"]}
                    other.commit()

        def scan_hosts(self, hosts):
            self.observe("tls")
            return {
                "findings": [{"endpoint": h, "status": "OK", "crypto": {"algorithm": "AES"}} for h in hosts],
                "probe_telemetry": {
                    "status": state.get("tls_status", "OK"),
                    "probed": len(hosts),
                    "ok": 0 if state.get("tls_status") == "ERROR" else len(hosts),
                },
            }

        def scan_ipsec_hosts(self, hosts, **kwargs):
            self.observe("ipsec")
            return {"findings": [], "probe_telemetry": {"probed": len(hosts), "responded": len(hosts)}}

        def scan_dnssec_zones(self, zones, **kwargs):
            self.observe("dnssec")
            return {"zones": [{"zone": z, "status": "SIGNED"} for z in zones]}

        def discover_network(self, *args, **kwargs):
            pytest.fail("unqualified scope must not execute")

    monkeypatch.setattr("network_scanner.core.scanner.NetworkTlsScanner", Scanner)
    yield db, state
    db.close()
    engine.dispose()


def run(contract, profile="tls", *, config=None):
    db, _ = contract
    row = MonitorRepository(db).create(
        name="edge",
        tenant_id="a",
        target_type="NETWORK",
        interval_seconds=600,
        next_scan_at=NOW - timedelta(seconds=1),
        config=deepcopy(config or CONFIGS[profile]),
    )
    db.commit()
    outcome = MonitorEngine(db, clock=lambda: NOW).run_target(row)
    return row, outcome


@pytest.mark.parametrize("profile", CONFIGS)
@pytest.mark.parametrize("condition", ["stop", "outage", "passive", "ot", "queue", "quota"])
def test_refusal_before_any_executor_job_or_meter(contract, monkeypatch, profile, condition):
    db, state = contract
    if condition == "stop":
        state["policy"] = {"emergency_stop": True}
    if condition == "outage":
        state["outage"] = True
    if condition == "passive":
        state["policy"] = {"mode": "passive"}
    if condition == "ot":
        state["ot"] = True
    if condition == "queue":
        state["queue"] = 6
    if condition == "quota":
        monkeypatch.setattr("api.security.tenancy.quota_check", lambda *a: (False, "quota exhausted"))
    row, outcome = run(contract, profile)
    assert outcome["status"] == "BLOCKED"
    assert state["calls"] == [] and state["constructs"] == 0
    assert db.query(ScanJob).count() == db.query(NetworkScanRun).count() == db.query(TenantUsageEvent).count() == 0
    assert row.last_scan_at is None


@pytest.mark.parametrize(
    "config",
    [
        {"endpoints": ["10.0.0.1:443", "169.254.169.254:80"]},
        {"ipsec": ["127.0.0.1"]},
        {"ipsec": ["10.0.0.1:500"]},
        {"ipsec": ["10.0.0.1"], "ike_ports": "500,not-a-port"},
        {"dnssec": ["bank.example"]},
        {"dnssec": ["bank.example"], "dns_resolver": "127.0.0.1:53"},
        {"dnssec": ["bank.example;injected"], "dns_resolver": "10.0.0.53:53"},
        {"endpoints": ["10.0.0.1:443"], "scope": ["10.0.0.0/24"]},
        {"scope": ["10.0.0.0/24"]},
        {"endpoints": ["10.0.0.1:443"], "live": False},
        {"endpoints": ["10.0.0.1:443"], "persist_run": False},
        {"endpoints": ["10.0.0.1:443"], "scan_mode": "PASSIVE"},
        {"endpoints": ["10.0.0.1:443"], "scan_versions": True},
    ],
)
def test_invalid_or_unqualified_whole_profile_has_no_packets(contract, config):
    db, state = contract
    row, outcome = run(contract, config=config)
    assert outcome["status"] == "BLOCKED"
    assert not state["calls"] and state["constructs"] == 0
    assert db.query(ScanJob).count() == 0 and row.last_scan_at is None


@pytest.mark.parametrize("profile", CONFIGS)
def test_admitted_profile_has_linked_job_ledger_owner_and_attempt_meter(contract, profile):
    db, state = contract
    row, outcome = run(contract, profile)
    job, ledger = db.query(ScanJob).one(), db.query(NetworkScanRun).one()
    assert job.status == "COMPLETED" and job.tenant_id == ledger.tenant_id == "a"
    assert ledger.target_kind == "monitor"
    assert ledger.result["collection"]["job_id"] == job.id
    assert ledger.result["monitor"]["target_id"] == row.id
    assert job.progress["coverage"]["network_run_id"] == ledger.id
    assert outcome["job_id"] == job.id and outcome["run_id"] == ledger.id
    assert db.query(TenantUsageEvent).one().amount == (3 if profile == "mixed" else 1)
    assert set(state["calls"]) == ({"tls", "ipsec", "dnssec"} if profile == "mixed" else {profile})
    assert current_tenant() is None


@pytest.mark.parametrize(
    "excluded",
    [
        {"excluded_ports": [443]},
        {"excluded_ports": [500]},
        {"excluded_ports": [53]},
        {"excluded_protocols": ["udp"]},
        {"excluded_protocols": ["DNS"]},
        {"excluded_assets": ["bank.example"]},
        {"excluded_assets": ["10.0.0.53"]},
    ],
)
def test_any_excluded_phase_refuses_entire_mixed_pass(contract, excluded):
    db, state = contract
    state["policy"] = excluded
    _, outcome = run(contract, "mixed")
    assert outcome["status"] == "BLOCKED" and state["constructs"] == 0
    assert not state["calls"] and db.query(ScanJob).count() == 0


def test_stop_between_phases_keeps_failed_job_and_no_false_acceptance(contract):
    db, state = contract
    state["stop_after"] = "tls"
    row, outcome = run(contract, "mixed")
    assert state["calls"] == ["tls"]
    assert outcome["status"] == "BLOCKED"
    assert db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanRun).count() == db.query(CryptoLiveState).count() == 0
    assert db.query(TenantUsageEvent).one().amount == 3 and row.last_scan_at is None


@pytest.mark.parametrize("fault", ["executor", "ledger", "projection", "completion"])
def test_failure_retains_failed_job_but_rolls_back_acceptance(contract, monkeypatch, fault):
    db, state = contract

    def fail(*args, **kwargs):
        raise RuntimeError("controlled write failure")

    if fault == "executor":
        state["fail"] = "tls"
    if fault == "ledger":
        monkeypatch.setattr("db.repositories.scan_run_repository.ScanRunRepository.create_run", fail)
    if fault == "projection":
        monkeypatch.setattr("worker.monitor.realtime_projection.persist_monitor_projection", fail)
    if fault == "completion":
        from db.repositories.job_repository import JobRepository

        original = JobRepository.update_status

        def refused(self, job_id, status, **kwargs):
            return None if status == "COMPLETED" else original(self, job_id, status, **kwargs)

        monkeypatch.setattr(JobRepository, "update_status", refused)
    row, outcome = run(contract)
    assert outcome["status"] == "DEGRADED"
    assert db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanRun).count() == db.query(CryptoLiveState).count() == 0
    assert db.query(TenantUsageEvent).one().amount == 1 and row.last_scan_at is None
    assert db.query(MonitorEvent).one().event_type == "SCAN_FAILED"


@pytest.mark.parametrize("change", ["suspend", "pause", "profile"])
def test_authority_is_reloaded_between_phases(contract, change):
    db, state = contract
    state.update(change_after="tls", change=change)
    row, outcome = run(contract, "mixed")
    assert outcome["status"] == "BLOCKED" and state["calls"] == ["tls"]
    assert db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanRun).count() == 0 and row.last_scan_at is None


@pytest.mark.parametrize("transfer,allowed", [(True, False), (False, True)])
def test_dns_transport_admission_matches_actual_axfr_setting(contract, transfer, allowed):
    db, state = contract
    state["policy"] = {"excluded_protocols": ["tcp"]}
    config = {**CONFIGS["dnssec"], "check_zone_transfer": transfer}
    _, outcome = run(contract, config=config)
    assert bool(state["calls"]) is allowed
    assert outcome["status"] == ("DEGRADED" if allowed else "BLOCKED")
    assert db.query(ScanJob).count() == int(allowed)


def test_whole_mixed_plan_quota_is_checked_before_any_phase(contract, monkeypatch):
    db, state = contract
    seen = []

    def quota(plan, kind, used):
        seen.append(used)
        return used < 2, "only two units remain"

    monkeypatch.setattr("api.security.tenancy.quota_check", quota)
    _, outcome = run(contract, "mixed")
    assert outcome["status"] == "BLOCKED" and outcome["refusal_status"] == 402
    assert seen == [2] and not state["calls"] and db.query(ScanJob).count() == 0


def test_initial_running_commit_failure_cannot_probe_or_leave_staged_job(contract, monkeypatch):
    db, state = contract
    original = db.commit

    def fail_initial():
        if db.query(ScanJob).filter_by(status="RUNNING").count():
            raise RuntimeError("initial durable job commit failed")
        return original()

    monkeypatch.setattr(db, "commit", fail_initial)
    row, outcome = run(contract)
    assert outcome["status"] == "DEGRADED" and row.last_scan_at is None
    assert not state["calls"] and state["constructs"] == 0
    assert db.query(ScanJob).count() == db.query(TenantUsageEvent).count() == 0


def test_receipts_do_not_publish_other_estates_exclusions(contract):
    db, state = contract
    state["policy"] = {"excluded_assets": ["other-bank.private.example"]}
    _, outcome = run(contract)
    assert outcome["status"] == "OK"
    job = db.query(ScanJob).one()
    ledger = db.query(NetworkScanRun).one()
    assert "other-bank.private.example" not in str(job.progress) + str(ledger.result)


def test_mixed_ledger_does_not_claim_tls_subphase_counts_are_whole_profile(contract):
    db, _ = contract
    row, outcome = run(contract, "mixed")
    ledger = db.query(NetworkScanRun).one()
    assert outcome["status"] == "DEGRADED" and row.last_scan_at is None
    assert ledger.verdict == "PARTIAL" and ledger.probed is ledger.ok is None
    assert ledger.result["monitor"]["phase_telemetry"]["tls"]["ok"] == 1
    assert ledger.result["monitor"]["observation_complete"] is False


def test_refused_phase_progress_cas_cannot_probe(contract, monkeypatch):
    db, state = contract
    from db.repositories.job_repository import JobRepository

    original = JobRepository.update_status
    calls = []

    def refused(self, job_id, status, **kwargs):
        if status == "RUNNING":
            calls.append(status)
            if len(calls) == 2:
                return None
        return original(self, job_id, status, **kwargs)

    monkeypatch.setattr(JobRepository, "update_status", refused)
    row, outcome = run(contract)
    assert outcome["status"] == "DEGRADED" and row.last_scan_at is None
    assert not state["calls"] and db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanRun).count() == 0
