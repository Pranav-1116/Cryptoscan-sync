"""Scheduled TLS admission: real SQL jobs/receipts, controlled policy and packets."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401
from db.connection.session import Base
from db.models.network_scan_run import NetworkScanRun
from db.models.network_scan_target import NetworkScanTarget
from db.models.scan_job import ScanJob
from db.models.tenant import Tenant, TenantUsageEvent
from db.tenancy import current_tenant, install_tenant_guard, tenant_scope
from worker.monitor.network_sweep import run_due_network_targets

NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


@pytest.fixture
def estate(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'estate.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    install_tenant_guard()
    db = factory()
    db.add_all([Tenant(id=t, name=t, slug=t, plan="ENTERPRISE", status="ACTIVE") for t in ("a", "b")])
    db.commit()
    state = {
        "policy": {},
        "calls": [],
        "constructed": 0,
        "status": "OK",
        "ok": None,
        "outage": False,
        "ot": False,
        "queue": 0,
    }
    import api.security.scan_admission as admission

    def policy():
        if state["outage"]:
            raise RuntimeError("policy database unavailable")
        return [], deepcopy(state["policy"])

    monkeypatch.setattr(admission, "_control_plane_state", policy)
    monkeypatch.setattr(admission, "_ot_declared", lambda: state["ot"])
    monkeypatch.setattr(admission, "_active_job_count", lambda: state["queue"])
    monkeypatch.setenv("MAX_QUEUE_DEPTH", "5")

    class Scanner:
        def __init__(self, **kwargs):
            state["constructed"] += 1
            state["options"] = kwargs

        def scan_hosts(self, hosts):
            # A separate SQL connection must see RUNNING before any packets.
            with factory() as observer:
                job = observer.execute(select(ScanJob).where(ScanJob.status == "RUNNING")).scalar_one()
                assert job.tenant_id == current_tenant()
            state["calls"].append((current_tenant(), list(hosts)))
            if state.get("failure") or ("failure_tenant" in state and state["failure_tenant"] == current_tenant()):
                raise TimeoutError("controlled probe failure")
            return {
                "certificates": state.get("certificates", []),
                "usages": state.get("usages", []),
                "findings": [],
                "probe_telemetry": {
                    "status": state["status"],
                    "probed": len(hosts),
                    "ok": len(hosts) if state["ok"] is None else state["ok"],
                },
            }

    state["scanner"] = Scanner
    yield db, state
    db.close()
    engine.dispose()


def target(db, tenant="a", endpoint="10.0.0.1:443"):
    row = NetworkScanTarget(
        endpoint=endpoint,
        tenant_id=tenant,
        enabled=True,
        scan_frequency="hourly",
        next_scan_time=NOW - timedelta(seconds=1),
    )
    db.add(row)
    db.commit()
    return row


def sweep(estate):
    db, state = estate
    return run_due_network_targets(db, now=NOW, scanner_factory=state["scanner"])


@pytest.mark.parametrize(
    "condition,code",
    [
        ("stop", 409),
        ("passive", 409),
        ("outage", 503),
        ("ot", 409),
        ("queue", 429),
        ("excluded", 409),
        ("ssrf", 422),
        ("suspended", 409),
        ("missing", 409),
        ("quota", 402),
    ],
)
def test_refused_phase_never_constructs_executor_or_records_success(estate, monkeypatch, condition, code):
    db, state = estate
    row = target(db, endpoint="127.0.0.1:443" if condition == "ssrf" else "10.0.0.1:443")
    if condition == "stop":
        state["policy"] = {"emergency_stop": True}
    if condition == "passive":
        state["policy"] = {"mode": "passive"}
    if condition == "outage":
        state["outage"] = True
    if condition == "ot":
        state["ot"] = True
    if condition == "queue":
        state["queue"] = 6
    if condition == "excluded":
        state["policy"] = {"excluded_ports": [443]}
    if condition in {"suspended", "missing"}:
        tenant = db.get(Tenant, "a")
        if condition == "suspended":
            tenant.status = "SUSPENDED"
        else:
            db.delete(tenant)
        db.commit()
    if condition == "quota":
        monkeypatch.setattr("api.security.tenancy.quota_check", lambda *a: (False, "controlled quota"))
    with pytest.raises(HTTPException) as error:
        sweep(estate)
    assert error.value.status_code == code
    assert state["constructed"] == 0 and state["calls"] == []
    assert db.query(ScanJob).count() == db.query(NetworkScanRun).count() == db.query(TenantUsageEvent).count() == 0
    assert row.last_scan_time is None and row.next_scan_time.replace(tzinfo=timezone.utc) <= NOW


@pytest.mark.parametrize(
    "status,ok,fresh",
    [("OK", None, True), ("PARTIAL", None, True), ("ERROR", 0, False), ("PARTIAL", 0, False), ("UNKNOWN", None, False)],
)
def test_receipt_job_meter_and_freshness(estate, status, ok, fresh):
    db, state = estate
    row = target(db)
    state.update(status=status, ok=ok)
    summary = sweep(estate)
    job = db.query(ScanJob).one()
    ledger = db.query(NetworkScanRun).one()
    assert job.status == "COMPLETED" and job.tenant_id == ledger.tenant_id == "a"
    assert ledger.result["collection"]["job_id"] == job.id
    assert job.progress["coverage"]["network_run_id"] == ledger.id
    assert job.progress["admission"]["protocol"] == "tls"
    assert job.progress["run"]["profile"]["workers"] == 8
    assert db.query(TenantUsageEvent).one().amount == 1
    assert bool(row.last_scan_time) is fresh
    assert summary["groups"][0]["job_id"] == job.id
    assert summary["groups"][0]["observed"] == int(fresh)
    if fresh:
        assert row.next_scan_time == NOW + timedelta(hours=1)
    else:
        assert row.next_scan_time.replace(tzinfo=timezone.utc) <= NOW
        assert summary["status"] != "OK"


def test_tenant_request_never_sweeps_platform_or_foreign_estates(estate):
    db, state = estate
    own = target(db)
    foreign = target(db, "b", "10.0.0.2:443")
    platform = target(db, None, "10.0.0.3:443")
    with tenant_scope("a"):
        result = sweep(estate)
        assert current_tenant() == "a"
    assert result["due"] == 1
    assert state["calls"] == [("a", [own.endpoint])]
    assert foreign.last_scan_time is platform.last_scan_time is None


def test_unscoped_leader_groups_by_trusted_owner_and_restores_context(estate):
    db, state = estate
    target(db)
    target(db, "b", "10.0.0.2:443")
    target(db, None, "10.0.0.3:443")
    result = sweep(estate)
    assert current_tenant() is None
    assert result["scanned"] == 3 and len(result["run_ids"]) == 3
    assert {r.tenant_id for r in db.query(NetworkScanRun)} == {"a", "b", None}
    assert {r.tenant_id for r in db.query(TenantUsageEvent)} == {"a", "b"}


@pytest.mark.parametrize("fault", ["executor", "ledger", "certificate", "usage", "completion", "commit"])
def test_fault_retains_failed_job_without_ledger_or_freshness(estate, monkeypatch, fault):
    db, state = estate
    row = target(db)
    if fault == "executor":
        state["failure"] = True
    if fault == "ledger":

        def broken(*args, **kwargs):
            raise RuntimeError("controlled storage failure")

        monkeypatch.setattr("db.repositories.scan_run_repository.ScanRunRepository.create_run", broken)
    if fault in {"certificate", "usage"}:
        state["certificates"] = [{"fingerprint_sha256": "f" * 64}]
        state["usages"] = [{"fingerprint_sha256": "f" * 64, "location": "10.0.0.1:443"}]

        def broken_projection(*args, **kwargs):
            raise RuntimeError("controlled projection failure")

        path = (
            "db.repositories.certificate_repository.CertificateRepository.upsert"
            if fault == "certificate"
            else "db.repositories.maturity_repository.MaturityRepository.upsert_usage"
        )
        monkeypatch.setattr(path, broken_projection)
    if fault == "completion":
        from db.repositories.job_repository import JobRepository

        original = JobRepository.update_status

        def refused(self, job_id, status, **kwargs):
            return None if status == "COMPLETED" else original(self, job_id, status, **kwargs)

        monkeypatch.setattr(JobRepository, "update_status", refused)
    if fault == "commit":
        original = db.commit
        calls = 0

        def fail_commit():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("controlled completion commit failure")
            return original()

        monkeypatch.setattr(db, "commit", fail_commit)
    with pytest.raises((TimeoutError, RuntimeError)):
        sweep(estate)
    assert db.query(ScanJob).one().status == "FAILED"
    assert db.query(NetworkScanRun).count() == 0
    assert db.query(TenantUsageEvent).one().amount == 1  # admitted attempt, not successful observation
    db.refresh(row)
    assert row.last_scan_time is None
    assert row.next_scan_time.replace(tzinfo=timezone.utc) <= NOW
    assert current_tenant() is None


def test_large_estate_is_bounded_and_readmitted_per_batch(estate):
    db, state = estate
    db.add_all(
        [
            NetworkScanTarget(
                endpoint=f"10.1.{i // 250}.{i % 250 + 1}:443",
                tenant_id="a",
                enabled=True,
                next_scan_time=NOW - timedelta(seconds=1),
            )
            for i in range(257)
        ]
    )
    db.commit()
    result = sweep(estate)
    assert [len(hosts) for _, hosts in state["calls"]] == [256, 1]
    assert result["scanned"] == 257 and len(result["run_ids"]) == 2


def test_production_executor_has_explicit_bounds(estate, monkeypatch):
    db, state = estate
    target(db)
    monkeypatch.setattr("network_scanner.core.scanner.NetworkTlsScanner", state["scanner"])
    run_due_network_targets(db, now=NOW)
    assert state["options"] == {"live": True, "timeout": 5.0, "workers": 8}


def test_initial_commit_failure_has_no_packets_or_late_running_job(estate, monkeypatch):
    db, state = estate
    target(db)
    original = db.commit

    def broken_commit():
        raise RuntimeError("initial job commit refused")

    monkeypatch.setattr(db, "commit", broken_commit)
    with pytest.raises(RuntimeError, match="initial job commit"):
        sweep(estate)
    monkeypatch.setattr(db, "commit", original)
    db.commit()  # daemon cleanup must not accidentally accept staged work
    assert state["constructed"] == 0 and not state["calls"]
    assert db.query(ScanJob).count() == db.query(TenantUsageEvent).count() == 0


def test_stop_is_rechecked_between_batches_and_accepted_work_stays_durable(estate, monkeypatch):
    db, state = estate
    db.add_all(
        [
            NetworkScanTarget(
                endpoint=f"10.2.{i // 250}.{i % 250 + 1}:443",
                tenant_id="a",
                enabled=True,
                next_scan_time=NOW - timedelta(seconds=1),
            )
            for i in range(257)
        ]
    )
    db.commit()
    from api.security.scan_runs import DurableScanRun

    original = DurableScanRun.succeed

    def stop_after_accept(self, **kwargs):
        original(self, **kwargs)
        state["policy"] = {"emergency_stop": True}

    monkeypatch.setattr(DurableScanRun, "succeed", stop_after_accept)
    with pytest.raises(HTTPException) as error:
        sweep(estate)
    assert error.value.status_code == 409
    assert len(state["calls"]) == 1
    assert db.query(ScanJob).one().status == "COMPLETED"
    assert db.query(NetworkScanRun).count() == 1
    assert db.query(NetworkScanTarget).filter(NetworkScanTarget.last_scan_time.is_not(None)).count() == 256


@pytest.mark.parametrize("change", ["suspend", "disable", "reschedule"])
def test_next_batch_reloads_registry_and_schedule_before_admission(estate, monkeypatch, change):
    db, state = estate
    target(db)
    second = target(db, "b", "10.0.0.2:443")
    from api.security.scan_runs import DurableScanRun

    original = DurableScanRun.succeed

    def change_after_accept(self, **kwargs):
        original(self, **kwargs)
        with tenant_scope(None), sessionmaker(bind=db.get_bind())() as other:
            if change == "suspend":
                other.get(Tenant, "b").status = "SUSPENDED"
            if change == "disable":
                other.get(NetworkScanTarget, second.id).enabled = False
            if change == "reschedule":
                other.get(NetworkScanTarget, second.id).next_scan_time = NOW + timedelta(hours=1)
            other.commit()

    monkeypatch.setattr(DurableScanRun, "succeed", change_after_accept)
    with pytest.raises(HTTPException) as error:
        sweep(estate)
    assert error.value.status_code == 409
    assert len(state["calls"]) == 1
    assert db.query(ScanJob).one().status == "COMPLETED"
    assert db.query(NetworkScanRun).one().tenant_id == "a"


def test_network_fault_does_not_rollback_prior_monitor_work(estate, monkeypatch):
    db, state = estate
    target(db)
    state["failure"] = True
    monkeypatch.setattr("network_scanner.core.scanner.NetworkTlsScanner", state["scanner"])
    from db.repositories.monitor_repository import MonitorRepository
    from worker.monitor.engine import MonitorEngine

    monitor = MonitorRepository(db).create(
        name="prior-work", target_type="VENDOR", config={}, next_scan_at=NOW - timedelta(seconds=1)
    )
    db.commit()
    engine = MonitorEngine(
        db,
        runners={"VENDOR": lambda c, s: {"summary": {}, "issues": []}},
        clock=lambda: NOW,
        watch_enabled=False,
        run_reports=False,
        run_backups=False,
    )
    outcome = engine.tick()
    assert outcome["network"]["status"] == "ERROR"
    db.rollback()
    db.refresh(monitor)
    assert monitor.status == "OK"
    assert db.query(ScanJob).one().status == "FAILED"
    assert MonitorRepository(db).list_events(target_id=monitor.id)[0].event_type == "SCAN_OK"


def test_later_owner_failure_preserves_prior_owner_acceptance(estate):
    db, state = estate
    first = target(db)
    second = target(db, "b", "10.0.0.2:443")
    state["failure_tenant"] = "b"
    with pytest.raises(TimeoutError):
        sweep(estate)
    jobs = {job.tenant_id: job.status for job in db.query(ScanJob)}
    assert jobs == {"a": "COMPLETED", "b": "FAILED"}
    assert db.query(NetworkScanRun).one().tenant_id == "a"
    assert first.last_scan_time is not None and second.last_scan_time is None
    assert current_tenant() is None


def test_quota_preflights_whole_batch_not_one_host(estate, monkeypatch):
    db, state = estate
    target(db)
    target(db, "a", "10.0.0.2:443")
    seen = []

    def check(plan, kind, used):
        seen.append((current_tenant(), kind, used))
        return (used < 1, "one remaining unit")

    monkeypatch.setattr("api.security.tenancy.quota_check", check)
    with pytest.raises(HTTPException) as error:
        sweep(estate)
    assert error.value.status_code == 402
    assert seen == [("a", "scan_run", 1)]
    assert state["constructed"] == 0
    assert db.query(ScanJob).count() == db.query(TenantUsageEvent).count() == 0
