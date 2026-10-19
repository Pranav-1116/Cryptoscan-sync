"""24/7 monitor engine: due selection, state transitions, backoff, alert-once."""

from __future__ import annotations

import pytest

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from db.connection.session import Base
from db.repositories.monitor_repository import MonitorRepository
from worker.monitor.engine import MonitorEngine

T0 = datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def monitor_admission_policy(monkeypatch):
    # Real admission engine with controlled authoritative policy lookups.
    import api.security.scan_admission as admission
    monkeypatch.setattr(admission, "_control_plane_state", lambda: ([], {}))
    monkeypatch.setattr(admission, "_ot_declared", lambda: False)
    monkeypatch.setattr(admission, "_active_job_count", lambda: 0)


def _session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _clock_engine(session, runners):
    state = {"minutes": 0}

    def now():
        return T0 + timedelta(minutes=state["minutes"])

    engine = MonitorEngine(session, runners=runners, clock=now)
    return engine, state


def _target(session, **kwargs):
    body = {
        "name": "edge", "target_type": "NETWORK", "config": {"endpoints": ["h:443"]},
        "interval_seconds": 600, "next_scan_at": T0 - timedelta(seconds=1),  # due at T0
    }
    body.update(kwargs)
    return MonitorRepository(session).create(**body)


def test_due_selection_and_ok_cycle():
    session = _session()
    due = _target(session, name="due")
    future = _target(
        session, name="future",
        next_scan_at=T0 + timedelta(hours=1),  # not due yet
    )
    disabled = _target(session, name="off", enabled=False)
    calls = []

    def ok_runner(config, sess):
        calls.append(config)
        return {"observation_complete": True, "summary": {"endpoints": 1, "probed_ok": 1, "unreachable": 0}, "issues": []}

    engine, clock = _clock_engine(session, {"NETWORK": ok_runner})
    outcome = engine.tick()
    assert outcome["ran"] == 1  # only the due, enabled target
    assert calls == [{"endpoints": ["h:443"], "timeout": 5.0, "workers": 8, "expiry_alert_days": 30}]
    assert due.status == "OK" and due.last_scan_at == T0
    assert due.next_scan_at == T0 + timedelta(seconds=600)
    assert future.status == "PENDING" and disabled.status == "PENDING"
    events = MonitorRepository(session).list_events()
    assert [e.event_type for e in events] == ["SCAN_OK"]


def test_alert_fires_only_on_new_issues():
    session = _session()
    target = _target(session, name="weak")
    issue = {"observation_complete": True, "summary": {"endpoints": 1}, "issues": ["WEAK_TLS_VERSION:h:443"], "degraded": True}
    clean = {"observation_complete": True, "summary": {"endpoints": 1}, "issues": []}

    state = {"minutes": 0, "flip": True}

    def runner(config, sess):
        return dict(issue) if state["flip"] else dict(clean)

    engine = MonitorEngine(session, runners={"NETWORK": runner},
                           clock=lambda: T0 + timedelta(minutes=state["minutes"]))
    engine.tick()  # first sight of the weak endpoint -> DEGRADED + ALERT
    assert target.status == "DEGRADED"
    state["minutes"] = 10
    engine.tick()  # same issue again -> DEGRADED, but NO duplicate alert
    events = MonitorRepository(session).list_events()
    alerts = [e for e in events if e.event_type == "ALERT"]
    assert len(alerts) == 1 and "WEAK_TLS_VERSION:h:443" in alerts[0].detail
    # the issue disappears -> OK; if it ever comes back it alerts again
    state["flip"] = False
    state["minutes"] = 20
    engine.tick()
    assert target.status == "OK"
    state["flip"] = True
    state["minutes"] = 30
    engine.tick()
    assert len([e for e in MonitorRepository(session).list_events() if e.event_type == "ALERT"]) == 2


def test_failure_backoff_and_failing_status():
    session = _session()
    target = _target(session, name="dead")

    def boom(config, sess):
        raise TimeoutError("probe timed out")

    state = {"minutes": 0}
    engine = MonitorEngine(session, runners={"NETWORK": boom},
                           clock=lambda: T0 + timedelta(minutes=state["minutes"]))
    first = engine.run_target(target)
    assert first["status"] == "DEGRADED"  # one failure is degraded, not failing
    assert target.consecutive_failures == 1
    assert target.next_scan_at == T0 + timedelta(seconds=600 * 2)  # interval * 2^1

    state["minutes"] = 30  # past the backed-off time
    second = engine.run_target(target)
    assert second["status"] == "FAILING"  # two consecutive failures
    assert target.next_scan_at == T0 + timedelta(minutes=30, seconds=600 * 4)  # 2^2
    assert target.last_error.startswith("TimeoutError")
    events = MonitorRepository(session).list_events()
    assert [e.event_type for e in events] == ["SCAN_FAILED", "SCAN_FAILED"]

    # a success clears the failure state completely
    state["minutes"] = 120
    engine_ok = MonitorEngine(session, runners={"NETWORK": lambda c, s: {"observation_complete": True, "summary": {}, "issues": []}},
                              clock=lambda: T0 + timedelta(minutes=state["minutes"]))
    engine_ok.run_target(target)
    assert target.status == "OK" and target.consecutive_failures == 0 and target.last_error is None


def test_blocked_is_honest_not_silent():
    session = _session()
    target = _target(session, name="cloudless", target_type="CLOUD", config={})
    engine, _ = _clock_engine(session, {"CLOUD": lambda c, s: {"blocked_reason": "no credentials"}})
    outcome = engine.run_target(target)
    assert outcome["status"] == "BLOCKED"
    assert target.status == "BLOCKED" and "no credentials" in target.last_error
    events = MonitorRepository(session).list_events()
    assert events[0].event_type == "BLOCKED" and "no credentials" in events[0].detail
    # unknown type is blocked too, never silently skipped
    weird = _target(session, name="weird", target_type="QUANTUM", config={})
    assert engine.run_target(weird)["status"] == "BLOCKED"


def test_daemon_loop_survives_exceptions_and_stops():
    from worker.monitor.loop import MonitorLoop

    session = _session()
    _target(session, name="t1")
    ticks = {"n": 0}

    class ExplodingFactory:
        def __init__(self, session):
            if ticks["n"] == 0:
                ticks["n"] += 1
                raise RuntimeError("db exploded")
            ticks["n"] += 1

    sleeps: list[float] = []
    _loop = MonitorLoop(
        lambda s: (_ for _ in ()).throw(RuntimeError("engine died")),
        session_factory=lambda: session,
        tick_seconds=5,
        sleep=sleeps.append,
    )
    # first tick raises (engine construction), loop must keep going
    loop_factory = lambda s: ExplodingFactory(s)

    loop2 = MonitorLoop(loop_factory, session_factory=lambda: session, tick_seconds=5, sleep=sleeps.append)
    # stop after two sleeps
    _original_sleep = loop2._sleep

    def sleep_then_stop(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= 2:
            loop2.request_stop()

    loop2._sleep = sleep_then_stop
    code = loop2.run_forever()
    assert code == 0 and len(sleeps) == 2  # survived the exploding tick, ran on


def test_run_once_cron_mode():
    from worker.monitor.loop import MonitorLoop
    from worker.monitor.engine import MonitorEngine

    session = _session()
    _target(session, name="cron-me")
    loop = MonitorLoop(
        MonitorEngine,
        session_factory=lambda: session,
        tick_seconds=1,
    )
    outcome = loop.run_once()
    assert outcome["ran"] == 1  # default runners ran the live network probe path
    target = MonitorRepository(session).get_by_name("cron-me")
    assert target.status in {"OK", "DEGRADED", "FAILING", "BLOCKED"}  # real outcome, honestly kept
