"""NETWORK monitor transaction/owner boundary; controlled executors, real SQL."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401
from db.connection.session import Base
from db.models.crypto_live import CryptoLiveEventRow, CryptoLiveState
from db.models.monitor import MonitorEvent, MonitorTarget
from db.models.tenant import Tenant, TenantUsageEvent
from db.repositories.monitor_repository import MonitorRepository
from db.tenancy import current_tenant, install_tenant_guard, tenant_scope
from worker.monitor.engine import MonitorEngine

NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)


@pytest.fixture
def estate(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'monitor.db'}", connect_args={"check_same_thread": False, "timeout": 15}
    )
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")
    Base.metadata.create_all(engine)
    install_tenant_guard()
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    db = factory()
    db.add_all([Tenant(id=t, name=t, slug=t, status="ACTIVE", plan="ENTERPRISE") for t in ("a", "b")])
    db.commit()
    yield db, factory
    db.close()
    engine.dispose()


def target(db, owner="a", name="edge", **kwargs):
    row = MonitorRepository(db).create(
        name=name,
        tenant_id=owner,
        target_type="NETWORK",
        config={"endpoints": ["10.0.0.1:443"], "tenant_id": "forged"},
        interval_seconds=600,
        next_scan_at=NOW - timedelta(seconds=1),
        **kwargs,
    )
    db.commit()
    return row


def observed(*, complete=True):
    return {
        "scanner": "network",
        "summary": {"endpoints": 1},
        "issues": [],
        "observation_complete": complete,
        "data": {"findings": [{"endpoint": "10.0.0.1:443", "status": "OK", "crypto": {"algorithm": "AES-256-GCM"}}]},
    }


def monitor(db, runner, **kwargs):
    return MonitorEngine(
        db,
        runners={"NETWORK": runner},
        clock=lambda: NOW,
        watch_enabled=False,
        run_network=False,
        run_reports=False,
        run_backups=False,
        run_reintroduction=False,
        run_sla=False,
        run_evidence_chain=False,
        **kwargs,
    )


@pytest.mark.parametrize("parallel", [False, True])
def test_fleet_scopes_each_network_pass_including_orm_reads_and_projections(estate, parallel):
    db, factory = estate
    rows = [target(db, owner, name=f"edge-{owner}") for owner in ("a", "b", None)]
    seen = []

    def runner(config, session):
        owner = current_tenant()
        visible = {t.tenant_id for t in session.query(MonitorTarget)}
        if owner is not None:
            assert visible <= {owner, None}
        seen.append(owner)
        return observed()

    engine = monitor(db, runner, concurrency=3 if parallel else 1, session_factory=factory)
    outcomes = engine._execute_many(rows)
    db.expire_all()
    assert all(r["status"] == "OK" for r in outcomes)
    assert set(seen) == {"a", "b", None} and current_tenant() is None
    assert {s.tenant_id for s in db.query(CryptoLiveState)} == {"a", "b", None}
    assert {e.tenant_id for e in db.query(CryptoLiveEventRow)} == {"a", "b", None}
    assert {u.tenant_id for u in db.query(TenantUsageEvent)} == {"a", "b"}


@pytest.mark.parametrize("owner", [None, "b"])
@pytest.mark.parametrize("parallel", [False, True])
def test_tenant_context_cannot_execute_foreign_or_shared_platform_target(estate, owner, parallel):
    db, factory = estate
    row = target(db, owner)
    calls = []
    engine = monitor(
        db, lambda c, s: calls.append(c) or observed(), concurrency=2 if parallel else 1, session_factory=factory
    )
    with tenant_scope("a"):
        outcome = engine._execute_many([row])
        assert current_tenant() == "a"
    assert not calls and outcome[0]["status"] == "GONE"
    assert db.query(MonitorEvent).count() == db.query(CryptoLiveState).count() == 0


@pytest.mark.parametrize("state", ["suspended", "missing", "paused"])
def test_network_execution_revalidates_owner_and_enabled_state(estate, state):
    db, _ = estate
    row = target(db)
    if state == "suspended":
        db.get(Tenant, "a").status = "SUSPENDED"
    if state == "missing":
        db.delete(db.get(Tenant, "a"))
    if state == "paused":
        row.enabled = False
    db.commit()
    calls = []
    outcome = monitor(db, lambda c, s: calls.append(c) or observed()).run_target(row)
    assert not calls and outcome["status"] == "BLOCKED"
    assert row.last_scan_at is None
    assert db.query(TenantUsageEvent).count() == 0


def test_blocked_pass_does_not_project_meter_or_refresh(estate):
    db, _ = estate
    row = target(db)
    result = {**observed(), "blocked_reason": "credentials unavailable"}
    monitor(db, lambda c, s: result).run_target(row)
    assert row.status == "BLOCKED" and row.last_scan_at is None
    assert db.query(CryptoLiveState).count() == db.query(TenantUsageEvent).count() == 0
    assert db.query(MonitorEvent).one().event_type == "BLOCKED"


@pytest.mark.parametrize("fault", ["executor", "projection", "meter", "completion"])
def test_failed_pass_rolls_back_staged_data_and_can_record_failure(estate, monkeypatch, fault):
    db, _ = estate
    row = target(db)

    def fail(*args, **kwargs):
        raise RuntimeError("controlled lifecycle fault")

    if fault == "projection":
        import worker.monitor.realtime_projection as projection

        original = projection.persist_monitor_projection

        def broken(*args):
            original(*args)
            fail()

        monkeypatch.setattr(projection, "persist_monitor_projection", broken)
    if fault == "meter":
        monkeypatch.setattr("db.repositories.tenant_repository.TenantRepository.record_usage", fail)
    if fault == "completion":
        original = db.commit
        calls = 0

        def fail_acceptance():
            nonlocal calls
            calls += 1
            if calls == 2:
                fail()
            return original()

        monkeypatch.setattr(db, "commit", fail_acceptance)

    def runner(config, session):
        if fault == "executor":
            session.add(CryptoLiveState(asset_id="should-rollback", tenant_id="a"))
            session.flush()
            fail()
        return observed()

    outcome = monitor(db, runner).run_target(row)
    db.commit()
    assert outcome["status"] == "DEGRADED"
    assert row.last_scan_at is None and row.consecutive_failures == 1
    assert (
        db.query(CryptoLiveState).count()
        == db.query(CryptoLiveEventRow).count()
        == db.query(TenantUsageEvent).count()
        == 0
    )
    assert db.query(MonitorEvent).one().event_type == "SCAN_FAILED"
    assert current_tenant() is None


def test_real_flush_error_is_rolled_back_before_recording_failure(estate):
    db, _ = estate
    row = target(db)

    def bad(config, session):
        session.add(CryptoLiveState(asset_id=None))
        session.flush()

    outcome = monitor(db, bad).run_target(row)
    assert outcome["status"] == "DEGRADED"
    db.commit()
    assert db.query(MonitorEvent).one().event_type == "SCAN_FAILED"


def test_two_targets_never_delete_each_others_current_state(estate):
    db, _ = estate
    first = target(db, name="first")
    second = target(db, name="second")
    engine = monitor(db, lambda c, s: observed())
    engine.run_target(first)
    engine.run_target(second)
    states = db.query(CryptoLiveState).all()
    assert {state.usage["target_id"] for state in states} == {first.id, second.id}
    assert len({state.asset_id for state in states}) == len(states)
    engine.runners["NETWORK"] = lambda c, s: {**observed(), "data": {}}
    engine.run_target(first)
    assert {state.usage["target_id"] for state in db.query(CryptoLiveState)} == {second.id}


def test_incomplete_pass_retains_evidence_and_prior_freshness(estate):
    db, _ = estate
    row = target(db)
    engine = monitor(db, lambda c, s: observed())
    engine.run_target(row)
    before = {state.id: deepcopy(state.cbom) for state in db.query(CryptoLiveState)}
    engine._now = lambda: NOW + timedelta(hours=1)
    engine.runners["NETWORK"] = lambda c, s: {**observed(complete=False), "data": {}}
    outcome = engine.run_target(row)
    assert outcome["status"] == "DEGRADED"
    assert row.last_scan_at.replace(tzinfo=timezone.utc) == NOW
    assert {state.id: state.cbom for state in db.query(CryptoLiveState)} == before
    assert row.last_summary["observation_complete"] is False


def test_callback_observes_committed_owner_state_not_unaccepted_alert(estate):
    db, factory = estate
    row = target(db)
    calls = []

    def alert(name, issue, payload):
        assert current_tenant() == "a"
        with factory() as observer:
            assert observer.get(MonitorTarget, row.id).status == "DEGRADED"
        calls.append(issue)

    result = {**observed(), "issues": ["WEAK_TLS_VERSION:10.0.0.1:443"]}
    monitor(db, lambda c, s: result, on_alert=alert).run_target(row)
    assert calls == result["issues"]


def test_prior_target_survives_later_target_failure(estate):
    db, _ = estate
    first = target(db, name="first")
    second = target(db, "b", name="second")

    def runner(c, session):
        if current_tenant() == "b":
            raise RuntimeError("second failed")
        return observed()

    monitor(db, runner)._execute_many([first, second])
    db.rollback()
    assert db.query(CryptoLiveState).one().tenant_id == "a"
    assert {row.name: row.status for row in db.query(MonitorTarget)} == {"first": "OK", "second": "DEGRADED"}


@pytest.fixture
def scanner(monkeypatch):
    state = {"calls": [], "tls": {"probe_telemetry": {"status": "OK", "probed": 1, "ok": 1}, "findings": []}}

    class Scanner:
        def __init__(self, **kwargs):
            state["options"] = kwargs

        def execute(self, phase, result):
            state["calls"].append(phase)
            if state.get("fault") == phase:
                raise RuntimeError("controlled phase failure")
            return result

        def scan_hosts(self, hosts):
            return self.execute("tls", state["tls"])

        def discover_network(self, *args, **kwargs):
            return self.execute("scope", {})

        def scan_ipsec_hosts(self, *args, **kwargs):
            return self.execute("ipsec", {"probe_telemetry": {"probed": 1, "responded": 1}, "findings": []})

        def scan_dnssec_zones(self, *args, **kwargs):
            return self.execute("dnssec", {"zones": [{"status": "SIGNED"}]})

    monkeypatch.setattr("network_scanner.core.scanner.NetworkTlsScanner", Scanner)
    return state


@pytest.mark.parametrize("phase", ["scope", "ipsec", "dnssec"])
def test_extra_phase_failure_is_not_clean_or_fresh(estate, scanner, phase):
    from worker.monitor.runners import network_runner

    db, _ = estate
    scanner["fault"] = phase
    result = network_runner({phase: ["10.0.0.1" if phase != "dnssec" else "bank.example"]}, db)
    assert result["degraded"] and result["observation_complete"] is False
    assert any("ERROR" in issue for issue in result["issues"])


@pytest.mark.parametrize(
    "telemetry,complete",
    [
        ({"status": "OK", "probed": 1, "ok": 1}, True),
        ({"status": "PARTIAL", "probed": 1, "ok": 1}, True),
        ({"status": "ERROR", "probed": 1, "ok": 0}, False),
        ({"status": "PARTIAL", "probed": 1, "ok": 0}, False),
        ({}, False),
    ],
)
def test_real_runner_reports_tls_observation_completeness(estate, scanner, telemetry, complete):
    from worker.monitor.runners import network_runner

    db, _ = estate
    scanner["tls"]["probe_telemetry"] = telemetry
    result = network_runner({"endpoints": ["10.0.0.1:443"]}, db)
    assert result["observation_complete"] is complete
    assert result["degraded"] is (not complete)
    assert scanner["options"] == {"live": True, "timeout": 5.0, "workers": 8}


@pytest.mark.parametrize("phase", ["scope", "dnssec"])
def test_legacy_extra_profile_cannot_assert_unestablished_full_coverage(estate, scanner, phase):
    from worker.monitor.runners import network_runner

    db, _ = estate
    result = network_runner({phase: ["10.0.0.0/30" if phase == "scope" else "bank.example"]}, db)
    assert result["observation_complete"] is False and result["degraded"]


def test_certificate_storage_failure_is_not_swallowed(estate, scanner, monkeypatch):
    from worker.monitor.runners import network_runner

    db, _ = estate
    scanner["tls"]["certificates"] = [{"fingerprint_sha256": "f" * 64}]

    def broken(*args, **kwargs):
        raise RuntimeError("certificate write failed")

    monkeypatch.setattr("db.repositories.certificate_repository.CertificateRepository.upsert", broken)
    with pytest.raises(RuntimeError, match="certificate write failed"):
        network_runner({"endpoints": ["10.0.0.1:443"]}, db)


@pytest.mark.parametrize(
    "config", [{"timeout": float("inf")}, {"timeout": float("nan")}, {"timeout": 31}, {"workers": 0}, {"workers": 33}]
)
def test_runner_rejects_unbounded_profile_before_executor(estate, scanner, config):
    from worker.monitor.runners import network_runner

    db, _ = estate
    with pytest.raises(ValueError):
        network_runner({"endpoints": ["10.0.0.1:443"], **config}, db)
    assert "options" not in scanner and not scanner["calls"]


@pytest.mark.parametrize("flag", [None, "true", 1])
def test_missing_or_nonboolean_completeness_cannot_refresh(estate, flag):
    db, _ = estate
    row = target(db)
    result = observed()
    if flag is None:
        result.pop("observation_complete")
    else:
        result["observation_complete"] = flag
    outcome = monitor(db, lambda c, s: result).run_target(row)
    assert outcome["status"] == "DEGRADED"
    assert row.last_scan_at is None and row.last_summary["observation_complete"] is False


def test_foreign_write_from_runner_fails_without_cross_tenant_effects(estate):
    db, _ = estate
    row = target(db)

    def forged(config, session):
        session.add(CryptoLiveState(tenant_id="b", asset_id="forged"))
        session.flush()
        return observed()

    assert monitor(db, forged).run_target(row)["status"] == "DEGRADED"
    assert db.query(CryptoLiveState).count() == 0
    assert db.query(MonitorEvent).one().tenant_id == "a"


def test_parallel_unhandled_failure_rolls_back_instead_of_committing_in_finally(estate, monkeypatch):
    db, factory = estate
    row = target(db)

    def unexpected(self, target):
        self.session.add(CryptoLiveState(asset_id="unaccepted", tenant_id="a"))
        self.session.flush()
        raise RuntimeError("unexpected worker failure")

    monkeypatch.setattr(MonitorEngine, "run_target", unexpected)
    with pytest.raises(RuntimeError, match="unexpected worker failure"):
        monitor(db, lambda c, s: observed(), concurrency=2, session_factory=factory)._execute_many([row])
    assert db.query(CryptoLiveState).count() == 0


def test_forever_loop_does_not_commit_an_aborted_tick(estate):
    db, factory = estate
    from worker.monitor.loop import MonitorLoop

    class BrokenEngine:
        def __init__(self, session):
            self.session = session

        def tick(self):
            self.session.add(CryptoLiveState(asset_id="unaccepted"))
            self.session.flush()
            loop.request_stop()
            raise RuntimeError("tick interrupted")

    loop = MonitorLoop(BrokenEngine, session_factory=factory, sleep=lambda _: None)
    assert loop.run_forever() == 0
    assert db.query(CryptoLiveState).count() == 0


@pytest.mark.parametrize("parallel", [False, True])
def test_owned_execution_inherits_callers_scope_in_thread_workers(estate, parallel):
    db, factory = estate
    row = target(db)
    seen = []

    def runner(c, s):
        seen.append(current_tenant())
        return observed()

    with tenant_scope("a"):
        outcomes = monitor(db, runner, concurrency=2 if parallel else 1, session_factory=factory)._execute_many([row])
        assert current_tenant() == "a"
    assert seen == ["a"] and outcomes[0]["status"] == "OK"
    assert db.query(CryptoLiveState).one().tenant_id == "a"


def test_replacement_failure_restores_preexisting_current_state_and_history(estate, monkeypatch):
    db, _ = estate
    row = target(db)
    engine = monitor(db, lambda c, s: observed())
    engine.run_target(row)
    state = db.query(CryptoLiveState).one()
    before = (state.id, deepcopy(state.cbom), db.query(CryptoLiveEventRow).count())
    import worker.monitor.realtime_projection as projection

    original = projection.persist_monitor_projection

    def broken(*args):
        original(*args)
        raise RuntimeError("after destructive replacement")

    monkeypatch.setattr(projection, "persist_monitor_projection", broken)
    engine._now = lambda: NOW + timedelta(hours=1)
    engine.runners["NETWORK"] = lambda c, s: {**observed(), "data": {}}
    assert engine.run_target(row)["status"] == "DEGRADED"
    state = db.query(CryptoLiveState).one()
    assert (state.id, state.cbom, db.query(CryptoLiveEventRow).count()) == before
    assert row.last_scan_at.replace(tzinfo=timezone.utc) == NOW


def test_completion_failure_does_not_dispatch_unaccepted_alerts(estate, monkeypatch):
    db, _ = estate
    row = target(db)
    original, commits, alerts = db.commit, [], []

    def commit():
        commits.append(True)
        if len(commits) == 2:
            raise RuntimeError("acceptance failed")
        original()

    monkeypatch.setattr(db, "commit", commit)
    engine = monitor(
        db, lambda c, s: {**observed(), "issues": ["WEAK_TLS_VERSION"]}, on_alert=lambda *args: alerts.append(args)
    )
    engine.run_target(row)
    assert not alerts
    assert db.query(MonitorEvent).one().event_type == "SCAN_FAILED"


def test_legacy_current_state_and_immutable_events_are_not_rewritten(estate):
    db, _ = estate
    row = target(db)
    legacy = CryptoLiveState(tenant_id="a", asset_id="a:monitor:network:algorithm:legacy:", usage={"target_id": row.id})
    db.add(legacy)
    db.commit()
    monitor(db, lambda c, s: observed()).run_target(row)
    assert db.get(CryptoLiveState, legacy.id).asset_id == legacy.asset_id
    assert len(db.query(CryptoLiveState).all()) == 2


@pytest.mark.parametrize("status,ok,fresh", [("OK", 1, True), ("ERROR", 0, False)])
def test_official_runner_engine_integration_uses_telemetry_for_freshness(estate, scanner, status, ok, fresh):
    from worker.monitor.runners import network_runner

    db, _ = estate
    row = target(db)
    scanner["tls"]["probe_telemetry"] = {"status": status, "ok": ok, "probed": 1}
    outcome = monitor(db, network_runner).run_target(row)
    assert bool(row.last_scan_at) is fresh
    assert row.last_summary["observation_complete"] is fresh
    assert outcome["status"] == ("OK" if fresh else "DEGRADED")
    assert db.query(TenantUsageEvent).one().tenant_id == "a"
