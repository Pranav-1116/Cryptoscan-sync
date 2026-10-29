"""The 24/7 estate loop: daemon, run events, liveness (spec 93 §18).

What this file protects:

* a product that runs continuously must *keep running* — a bad cycle is recorded
  and the loop continues, and a dead realtime feed never fails a scan;
* a daemon that is merely "up" is not coverage — ``NEVER_STARTED``/``STALE``/
  ``STOPPED`` are distinct, and ``IDLE_NO_SCHEDULES`` says nothing is being
  re-scanned;
* downtime does not queue N runs: the next occurrence is computed forward;
* events carry the verdict, so "run finished" can never be rendered as "fine".

No sleeps against the wall clock: the loop's ``sleep``/``clock``/``now`` are
injected.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api import cli, estate_daemon, estate_events, estate_schedule
from api.estate_daemon import EstateDaemon, stale_state
from db.connection.session import Base
from db.models.estate_daemon import EstateDaemon as EstateDaemonRow

NOW = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)


def _schedule(session, **kwargs):
    kwargs.setdefault("planes", ["STATIC"])
    return estate_schedule.create_schedule(session, **kwargs)


@pytest.fixture()
def env():
    """A real session factory (the daemon opens and closes its own sessions)."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    session = factory()
    yield factory, session
    session.close()


@pytest.fixture()
def session(env):
    return env[1]


@pytest.fixture()
def factory(env):
    return env[0]


class FakeClock:
    """Monotonic clock plus a mutable wall clock, so a cycle can be replayed."""

    def __init__(self, wall: datetime = NOW) -> None:
        self.wall = wall
        self.mono = 0.0

    def now(self) -> datetime:
        return self.wall

    def clock(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.wall = self.wall + timedelta(seconds=seconds)
        self.mono += seconds

    def sleep(self, seconds: float) -> None:
        self.advance(seconds)


# --------------------------------------------------------------------------- #
# events
# --------------------------------------------------------------------------- #
def test_a_dead_feed_never_fails_the_run():
    calls: list[str] = []

    def broken(event_type, _payload):
        calls.append(event_type)
        raise RuntimeError("redis is down")

    sink = estate_events.EventSink(broken, estate="bank-a")
    sink("estate.run.started", {"planes": ["STATIC"]})   # must not raise
    assert sink.published == 0
    assert sink.publish_failures == 1
    assert "redis is down" in sink.summary()["last_error"]
    assert calls == ["estate.run.started"]


def test_an_unknown_event_type_is_a_programming_error_not_a_silent_publish():
    sink = estate_events.EventSink(lambda *_args: None)
    with pytest.raises(ValueError):
        sink("estate.something.else", {})


def test_a_run_emits_its_progress_and_its_verdict():
    from api import estate_discovery

    seen: list[tuple[str, dict]] = []

    def collector(_db, **_kwargs):
        return {"expected": 2, "collected": 1, "assets": [], "evidence": [], "relationships": [],
                "note": "read 1 of 2"}

    report = estate_discovery.run(
        None,
        estate="bank-a",
        collectors={"STATIC": collector},
        persist=False,
        on_event=lambda kind, payload: seen.append((kind, payload)),
    )
    kinds = [kind for kind, _ in seen]
    assert kinds[0] == "estate.run.started"
    assert "estate.plane.finished" in kinds
    assert kinds[-1] == "estate.run.finished"

    finished = dict(seen)["estate.run.finished"]
    # the feed carries the honest verdict, not a success flag
    assert finished["verdict"] in {"COMPLETE", "PARTIAL_COVERAGE"}
    assert finished["coverage_state"] in {"MEASURED", "NOT_OBSERVED"}
    assert finished["trigger"] == "manual"

    plane = next(payload for kind, payload in seen
                 if kind == "estate.plane.finished" and payload["plane"] == "STATIC")
    assert plane["plane"] == "STATIC"
    assert plane["status"] == "PARTIAL"
    assert plane["impact"]

    assert report["events"]["emitted"] == len(seen)


def test_a_run_with_no_subscriber_is_byte_for_byte_the_same():
    from api import estate_discovery

    def collector(_db, **_kwargs):
        return {"expected": 1, "collected": 1, "assets": [], "evidence": [], "relationships": []}

    quiet = estate_discovery.run(None, collectors={"STATIC": collector}, persist=False)
    watched = estate_discovery.run(None, collectors={"STATIC": collector}, persist=False,
                                   on_event=lambda *_args: None)
    assert quiet["verdict"] == watched["verdict"]
    assert quiet["coverage"]["summary"] == watched["coverage"]["summary"]
    assert "events" not in quiet  # nothing was subscribed, so nothing is claimed


def test_the_bus_publisher_is_the_platform_bus():
    from api.events.bus import get_event_bus

    bus = get_event_bus()
    before = bus.published_total()
    estate_events.bus_publisher(tenant_id="tenant-a")("estate.run.started", {"estate": "bank-a"})
    assert bus.published_total() >= before + 1


# --------------------------------------------------------------------------- #
# the daemon
# --------------------------------------------------------------------------- #
def _due_schedule(session, *, every: str = "6h", name: str = "nightly"):
    return _schedule(
        session, name=name, every=every, scope="production", estate="bank-a",
        planes=["STATIC"], now=NOW - timedelta(hours=7),
    )


def test_a_due_schedule_is_run_and_its_outcome_is_recorded(session, factory):
    clock = FakeClock()
    _due_schedule(session)
    seen: list[str] = []

    daemon = EstateDaemon(
        factory, worker="daemon-test", poll_seconds=5,
        runner=lambda _row, **_kwargs: {"verdict": "COMPLETE", "run_id": "run-1",
                                        "coverage": {"summary": {"coverage_state": "COMPLETE"}}},
        publisher=lambda kind, _payload: seen.append(kind),
        sleep=clock.sleep, clock=clock.clock, now=clock.now, jitter=lambda: 0.0,
    )
    cycle = daemon.run_cycle()
    assert cycle["claimed"] == 1
    assert cycle["ran"][0]["verdict"] == "COMPLETE"
    assert daemon.runs == 1
    assert "estate.run.finished" not in seen  # an injected runner emits no discovery events
    assert cycle["next_wake_at"]
    # the lease is released and the clock advanced past the due time
    row = estate_schedule.list_schedules(session)[0]
    assert row.claimed_by is None
    assert row.last_verdict == "COMPLETE"
    assert estate_schedule._utc(row.next_run_at) > NOW


def test_an_idle_cycle_says_why_it_did_nothing(session, factory):
    clock = FakeClock()
    # created five minutes ago with a six-hour cadence: nothing is due yet
    _schedule(session, name="nightly", every="6h",
                                    now=NOW - timedelta(minutes=5))
    daemon = EstateDaemon(factory, poll_seconds=5, sleep=clock.sleep, clock=clock.clock,
                          now=clock.now, jitter=lambda: 0.0)
    cycle = daemon.run_cycle()
    assert cycle["claimed"] == 0
    assert daemon.idle_reason
    assert cycle["sleep_seconds"] >= 1.0


def test_no_schedule_at_all_is_reported_not_hidden(session, factory):
    clock = FakeClock()
    daemon = EstateDaemon(factory, poll_seconds=5, sleep=clock.sleep, clock=clock.clock,
                          now=clock.now, jitter=lambda: 0.0)
    cycle = daemon.run_cycle()
    assert cycle["claimed"] == 0
    assert "nothing is being covered" in (daemon.idle_reason or "")


def test_the_loop_survives_a_failing_cycle(session, factory):
    clock = FakeClock()
    _due_schedule(session)
    calls = {"n": 0}

    def flaky(_db, **_kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("collector exploded")
        return {"verdict": "COMPLETE", "run_id": "run-2", "coverage": {"summary": {}}}

    daemon = EstateDaemon(factory, worker="w", runner=flaky, poll_seconds=5,
                          sleep=clock.sleep, clock=clock.clock, now=clock.now, jitter=lambda: 0.0)
    first = daemon.run_cycle()
    # the tick records the failed run and the lease is still released
    assert first["ran"][0]["status"] == "ERROR"
    assert "collector exploded" in (first["ran"][0]["error"] or "")
    assert daemon.failures == 1
    assert "collector exploded" in (daemon.last_error or "")
    assert daemon.stopping is False, "a failure must not stop the daemon"

    # the schedule advanced despite the failure, so the next cycle is clean
    clock.advance(6 * 3600)
    cycle = daemon.run_cycle()
    assert cycle["claimed"] == 1
    assert cycle["ran"][0]["status"] == "OK"
    session.expire_all()


def test_repeated_failures_back_off_instead_of_hammering(session, factory):
    clock = FakeClock()

    def always_broken(_db, **_kwargs):
        raise RuntimeError("still broken")

    daemon = EstateDaemon(factory, worker="w", runner=always_broken, poll_seconds=1,
                          sleep=clock.sleep, clock=clock.clock, now=clock.now, jitter=lambda: 0.0)
    delays = []
    for _ in range(4):
        # keep a schedule due every cycle so the failure path is exercised
        _schedule(session, name=f"s{len(delays)}", every="1m",
                                        now=NOW - timedelta(minutes=5))
        result = daemon.run_cycle()
        delays.append(result["sleep_seconds"])
    assert daemon.failures == 4
    assert delays[-1] >= estate_daemon.BACKOFF_SECONDS


def test_downtime_produces_one_catch_up_run_not_a_queue(session, factory):
    clock = FakeClock()
    row = _schedule(session, name="hourly", every="1h",
                                          now=NOW - timedelta(days=2))
    # simulate a long outage: next_run_at is two days in the past
    row.next_run_at = NOW - timedelta(days=2)
    session.commit()

    daemon = EstateDaemon(factory, worker="w", poll_seconds=5,
                          runner=lambda _r, **_k: {"verdict": "COMPLETE", "run_id": "r",
                                                   "coverage": {"summary": {}}},
                          sleep=clock.sleep, clock=clock.clock, now=clock.now, jitter=lambda: 0.0)
    daemon.run_cycle()
    daemon.run_cycle()  # immediately again: the next occurrence is in the future
    assert daemon.runs == 1
    session.expire_all()
    assert estate_schedule._utc(row.next_run_at) > NOW


def test_the_heartbeat_is_durable_and_upserted_per_worker(session, factory):
    clock = FakeClock()
    _due_schedule(session)
    daemon = EstateDaemon(factory, worker="beat", poll_seconds=5,
                          runner=lambda _r, **_k: {"verdict": "PARTIAL_COVERAGE", "run_id": "r",
                                                   "coverage": {"summary": {"coverage_state": "PARTIAL"}}},
                          sleep=clock.sleep, clock=clock.clock, now=clock.now, jitter=lambda: 0.0)
    daemon.run_cycle()
    clock.advance(30)
    daemon.run_cycle()

    session.expire_all()
    rows = session.query(EstateDaemonRow).all()
    assert len(rows) == 1, "one row per daemon, updated in place"
    beat = rows[0]
    assert beat.worker == "beat"
    assert beat.cycles == 2
    assert beat.state == "RUNNING"
    assert beat.last_cycle_at is not None
    assert beat.next_wake_at is not None


def test_run_forever_stops_on_signal_and_says_so(session, factory):
    clock = FakeClock()
    _due_schedule(session)
    daemon = EstateDaemon(factory, worker="loop", poll_seconds=5,
                          runner=lambda _r, **_k: {"verdict": "COMPLETE", "run_id": "r",
                                                   "coverage": {"summary": {}}},
                          sleep=lambda seconds: (clock.sleep(seconds), daemon.stop()),
                          clock=clock.clock, now=clock.now, jitter=lambda: 0.0)
    result = daemon.run_forever()
    assert result["state"] == "STOPPED"
    assert result["cycles"] >= 1
    session.expire_all()
    beat = session.query(EstateDaemonRow).all()[0]
    assert beat.state == "STOPPED"


def test_max_cycles_bounds_the_loop_for_drills(session, factory):
    clock = FakeClock()
    daemon = EstateDaemon(factory, worker="drill", poll_seconds=5,
                          sleep=clock.sleep, clock=clock.clock, now=clock.now, jitter=lambda: 0.0)
    result = daemon.run_forever(max_cycles=3)
    assert result["cycles"] == 3


# --------------------------------------------------------------------------- #
# liveness classification
# --------------------------------------------------------------------------- #
def test_liveness_states_are_distinct():
    assert stale_state(None)["state"] == "NEVER_STARTED"
    assert stale_state(None)["next_action"]

    live = stale_state({"state": "RUNNING", "last_cycle_at": NOW.isoformat()}, now=NOW + timedelta(seconds=10))
    assert live["state"] == "LIVE"
    assert live["next_action"] is None

    stale = stale_state({"state": "RUNNING", "last_cycle_at": NOW.isoformat()},
                        now=NOW + timedelta(seconds=600))
    assert stale["state"] == "STALE"
    assert "not being run" in stale["meaning"]

    stopped = stale_state({"state": "STOPPED", "last_cycle_at": NOW.isoformat()}, now=NOW + timedelta(seconds=5))
    assert stopped["state"] == "STOPPED"
    assert "start it again" in stopped["next_action"]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_cli_serve_once_runs_a_cycle_and_reports_idle(session, factory, capsys):
    code = cli.main(["serve", "--once"], session_factory=factory)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "cycle      claimed 0 schedule(s)" in out
    assert "idle" in out
    # even a one-shot cycle leaves a heartbeat the realtime probe can read
    from api import estate_daemon_store

    session.expire_all()
    assert estate_daemon_store.latest(session)["worker"] == "cryptoscan-daemon"


def test_cli_serve_once_json_is_one_document(session, factory, capsys):
    import json

    code = cli.main(["serve", "--once", "--json"], session_factory=factory)
    body = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_OK
    assert body["mode"] == "once"
    assert body["heartbeat"]["state"] == "STOPPED"
    assert body["next_wake_at"]


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@pytest.fixture()
def api(session):
    from fastapi.testclient import TestClient

    from api.dependencies import get_current_user, get_db_session
    from api.main import create_app

    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "tester"
    app.dependency_overrides[get_db_session] = lambda: session
    return TestClient(app)


def test_realtime_endpoint_says_nothing_is_running_before_a_daemon_starts(api):
    body = api.get("/api/v1/estate/evidence/realtime").json()
    assert body["verdict"] == "NOT_RUNNING"
    assert body["daemon"]["liveness"]["state"] == "NEVER_STARTED"
    assert "cryptoscan serve" in body["daemon"]["liveness"]["next_action"]
    assert body["schedules"]["enabled"] == 0


def test_realtime_endpoint_reports_a_live_daemon_and_an_idle_estate(api, session):
    from api.estate_daemon_store import record_heartbeat

    record_heartbeat(session, {"worker": "d1", "state": "RUNNING",
                               "last_cycle_at": datetime.now(timezone.utc).isoformat(),
                               "cycles": 4, "runs": 2, "next_wake_at": None})
    session.commit()

    body = api.get("/api/v1/estate/evidence/realtime").json()
    assert body["daemon"]["liveness"]["state"] == "LIVE"
    assert body["verdict"] == "IDLE_NO_SCHEDULES", "alive but nothing is being re-scanned"
    assert "no schedule is enabled" in body["reason"]

    _schedule(session, name="nightly", every="6h")
    body = api.get("/api/v1/estate/evidence/realtime").json()
    assert body["verdict"] in {"WAITING", "RUNNING"}
    assert body["schedules"]["enabled"] == 1
    assert body["schedules"]["seconds_until_due"] is not None


def test_realtime_verdict_tracks_failed_projections_and_due_cadence_not_wall_clock_age(api, session):
    from api.estate_daemon_store import record_heartbeat

    now = datetime.now(timezone.utc)
    record_heartbeat(session, {"worker": "d1", "state": "RUNNING",
                               "last_cycle_at": now.isoformat(), "cycles": 4, "runs": 1})
    row = _schedule(session, name="nightly", every="6h", now=now - timedelta(hours=2))
    row.last_run_at = now - timedelta(hours=2)
    row.last_verdict = "COMPLETE"
    row.last_coverage_state = "MEASURED"
    session.commit()
    body = api.get("/api/v1/estate/evidence/realtime").json()
    assert body["verdict"] == "WAITING", "a six-hour cadence is not stale after two hours"

    row.last_verdict = "PARTIAL_COVERAGE"
    row.last_coverage_state = "NOT_OBSERVED"
    session.commit()
    body = api.get("/api/v1/estate/evidence/realtime").json()
    assert body["verdict"] == "DEGRADED" and "incomplete coverage" in body["reason"]

    row.last_verdict = "COMPLETE"
    row.last_coverage_state = "MEASURED"
    row.next_run_at = now - timedelta(minutes=10)
    session.commit()
    body = api.get("/api/v1/estate/evidence/realtime").json()
    assert body["verdict"] == "DEGRADED" and "overdue" in body["reason"]


def test_realtime_endpoint_never_confuses_api_liveness_with_coverage(api):
    body = api.get("/api/v1/estate/evidence/realtime").json()
    assert "not proof of coverage" in body["meaning"]


# --------------------------------------------------------------------------- #
# continuous change detection — every run compares itself with the one before
# --------------------------------------------------------------------------- #
def _report(*, planes: dict, estate: str = "bank-a", projection: str = "p1", boms: bool = True) -> dict:
    from api import estate_discovery

    def make(outcomes):
        def collector(name):
            def _collect(_db, **_kwargs):
                spec = outcomes[name]
                if isinstance(spec, Exception):
                    raise spec
                return {"expected": spec.get("expected", 0), "collected": spec.get("collected", 0),
                        "assets": spec.get("assets", []), "evidence": [], "relationships": [],
                        "note": spec.get("note")}
            return _collect
        return {name: collector(name) for name in outcomes}

    return estate_discovery.run(None, estate=estate, collectors=make(planes), persist=False,
                                include_boms=boms)


def test_the_first_run_has_no_baseline_and_says_so():
    from api import estate_watch

    report = _report(planes={"STATIC": {"expected": 1, "collected": 1}})
    change = estate_watch.compare_reports(None, report)
    assert change["severity"] == "NO_BASELINE"
    assert change["changed"] is None, "an unknown is not 'no change'"
    assert "not 'no change'" in change["meaning"]


def test_a_lost_plane_is_critical_because_it_is_unknown_not_absent():
    from api import estate_watch

    before = _report(planes={"STATIC": {"expected": 4, "collected": 4},
                             "NETWORK": {"expected": 3, "collected": 3}})
    after = _report(planes={"STATIC": {"expected": 4, "collected": 4},
                            "NETWORK": RuntimeError("connector refused")}, projection="p2")
    change = estate_watch.compare_reports(before, after)
    assert change["severity"] == "CRITICAL"
    lost = [item for item in change["findings"] if item["kind"] == "COVERAGE_LOST"]
    assert lost and lost[0]["plane"] == "NETWORK"
    assert "UNKNOWN" in change["next_action"]


def test_a_smaller_read_is_coverage_debt_not_a_smaller_estate():
    from api import estate_watch

    before = _report(planes={"STATIC": {"expected": 10, "collected": 10}})
    after = _report(planes={"STATIC": {"expected": 10, "collected": 4}}, projection="p2")
    change = estate_watch.compare_reports(before, after)
    assert change["severity"] == "CRITICAL"
    assert any(item["kind"] == "COVERAGE_REDUCED" for item in change["findings"])


def test_a_new_estate_component_is_a_warning_with_a_next_action():
    from api import estate_watch

    before = _report(planes={"STATIC": {"expected": 1, "collected": 1}})
    after = _report(planes={"STATIC": {"expected": 2, "collected": 2}}, projection="p2")
    change = estate_watch.compare_reports(before, after)
    assert change["severity"] in {"WARNING", "INFO"}
    assert change["changed"] is True
    assert change["next_action"]


def test_no_change_is_reported_as_none_not_as_safety():
    from api import estate_watch

    before = _report(planes={"STATIC": {"expected": 2, "collected": 2}})
    after = _report(planes={"STATIC": {"expected": 2, "collected": 2}}, projection="p2")
    change = estate_watch.compare_reports(before, after)
    assert change["severity"] in {"NONE", "INFO"}
    assert "not a safety statement" in change["meaning"].replace("NONE is not", "not")


def test_a_change_publishes_an_event_and_a_quiet_run_does_not():
    from api import estate_discovery

    before = _report(planes={"STATIC": {"expected": 4, "collected": 4}})
    seen: list[str] = []

    after = estate_discovery.run(
        None, estate="bank-a", collectors={"STATIC": lambda _db, **_k: {"expected": 4, "collected": 1}},
        persist=False, previous=before, on_event=lambda kind, _payload: seen.append(kind),
    )
    assert after["change"]["severity"] == "CRITICAL"
    assert "estate.change.detected" in seen

    seen.clear()
    same = estate_discovery.run(
        None, estate="bank-a", collectors={"STATIC": lambda _db, **_k: {"expected": 4, "collected": 4}},
        persist=False, previous=_report(planes={"STATIC": {"expected": 4, "collected": 4}}),
        on_event=lambda kind, _payload: seen.append(kind),
    )
    assert "estate.change.detected" not in seen
    assert same["change"]["severity"] in {"NONE", "INFO"}


def test_the_scheduled_path_compares_against_the_previous_stored_run(session, factory):
    """A schedule must detect change by itself — not because someone called /drift."""
    from api import estate_discovery

    seen: list[tuple[str, dict]] = []
    _schedule(session, name="nightly", every="1h", estate="bank-a",
                                    planes=["STATIC"], now=NOW - timedelta(hours=2))
    # a stored previous report is what the real runner would find
    import db.repositories.scan_run_repository as repo_module
    previous = _report(planes={"STATIC": {"expected": 5, "collected": 5}})
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(estate_discovery, "previous_report", lambda *_a, **_k: previous)
        monkeypatch.setattr(estate_discovery, "run", lambda _db, **kwargs: (
            seen.append((kwargs.get("trigger"), kwargs.get("previous"))) or {
                "verdict": "COMPLETE", "run_id": "r2", "coverage": {"summary": {}}}))
        result = estate_schedule.tick(session, worker="w", now=NOW, on_event=lambda k, p: seen.append((k, p)))
    finally:
        monkeypatch.undo()
    assert result["claimed"] == 1
    assert ("schedule", previous) in seen, "the runner is handed the previous stored report"
    assert repo_module  # imported for parity with the real runner path


def test_a_stored_run_payload_can_be_compared_with_the_next_one(session, factory):
    """Regression: the stored payload's shape is not the API response's shape.

    Stored runs keep ``coverage`` as a row list and a compact ``boms`` index; the
    response keeps ``coverage`` as a matrix object. Comparing a stored run with
    the response used to raise `'list' object has no attribute 'get'`, which took
    the whole scheduled run down and silently disabled change detection.
    """
    from api import estate_discovery

    stored = {
        "estate": "bank-a",
        "coverage": [
            {"target": "STATIC", "expected": 5, "collected": 5, "status": "COMPLETE"},
            {"target": "NETWORK", "expected": 4, "collected": 4, "status": "COMPLETE"},
        ],
        "boms": {"CBOM": {"components": [{"bom_ref": "a"}, {"bom_ref": "b"}]}},
        "summary": {"assets": 2, "evidence": 2, "relationships": 0},
        "projection_id": "p1",
        "collectors": [{"plane": "STATIC", "status": "COMPLETE"},
                       {"plane": "NETWORK", "status": "COMPLETE"}],
    }
    live = estate_discovery.run(
        None, estate="bank-a", persist=False,
        collectors={
            "STATIC": lambda _db, **_k: {"expected": 5, "collected": 5},
            "NETWORK": lambda _db, **_k: (_ for _ in ()).throw(RuntimeError("connector dropped")),
        },
        previous=stored,
    )
    assert live["change"]["severity"] == "CRITICAL"
    assert any(item["kind"] == "COVERAGE_LOST" and item["plane"] == "NETWORK"
               for item in live["change"]["findings"])


def test_a_failed_run_makes_a_one_shot_cycle_exit_incomplete(session, factory, capsys):
    _schedule(session, name="nightly", every="1m", now=NOW - timedelta(minutes=5))

    import api.estate_daemon as daemon_module

    original = daemon_module.EstateDaemon.run_cycle

    def cycle_that_records_a_failure(self):  # noqa: ANN001
        result = {"worker": self.worker, "at": NOW.isoformat(), "claimed": 1,
                  "ran": [{"schedule": "nightly", "status": "ERROR", "error": "boom"}],
                  "failed_runs": 1, "next_wake_at": NOW.isoformat()}
        self.cycles += 1
        return result

    daemon_module.EstateDaemon.run_cycle = cycle_that_records_a_failure
    try:
        code = cli.main(["serve", "--once"], session_factory=factory)
    finally:
        daemon_module.EstateDaemon.run_cycle = original
    assert code == cli.EXIT_INCOMPLETE
    assert "ERROR" in capsys.readouterr().out
