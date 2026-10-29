"""Scheduled estate runs (spec 93 §18).

What has to be true for a schedule to be trustworthy:

* the cadence is parsed and computed, not guessed — cron in UTC, intervals in
  minutes, and an ambiguous schedule is refused;
* two workers cannot run the same schedule twice (the claim is a conditional
  UPDATE, so the loser sees zero rows);
* a run that raises still advances, so a broken connector cannot spin;
* the verdict of every run is recorded, because "it ran nightly" and "the estate
  was fully covered nightly" are different claims.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api import cli, estate_schedule
from api.estate_schedule import _utc
from db.connection.session import Base
from db.models.estate_schedule import EstateSchedule, EstateScheduleRun

from test_assurance_workflows import assured as assured, admin as selected_admin  # noqa: F401 — fixture import
from test_software_supply_chain_api import banks as banks  # noqa: F401 — assured depends on this fixture

NOW = datetime(2026, 3, 1, 22, 30, tzinfo=timezone.utc)


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    opened = sessionmaker(bind=engine)()
    try:
        yield opened
    finally:
        opened.close()


def _schedule(session, **kwargs):
    kwargs.setdefault("planes", ["STATIC"])
    return estate_schedule.create_schedule(session, **kwargs)


def _report(verdict: str = "COMPLETE", coverage_state: str = "MEASURED") -> dict:
    return {
        "run_id": "run-1",
        "verdict": verdict,
        "verdict_detail": "0 requested planes are incomplete",
        "coverage": {"summary": {"coverage_state": coverage_state, "expected": 3}},
    }


# --------------------------------------------------------------------------- #
# cadence
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("value", "minutes"),
    [("15m", 15), ("6h", 360), ("1d", 1440), ("90", 90), ("1w", 10080), ("2H", 120)],
)
def test_interval_forms(value, minutes):
    assert estate_schedule.parse_interval(value) == minutes


@pytest.mark.parametrize("value", ["", "zero", "0m", "6x hours", "-5m"])
def test_a_bad_or_zero_interval_is_refused(value):
    with pytest.raises(estate_schedule.ScheduleError):
        estate_schedule.parse_interval(value)


def test_cron_next_run_is_in_utc_and_strictly_after():
    upcoming = estate_schedule.next_cron_time("0 2 * * *", NOW)
    assert upcoming == datetime(2026, 3, 2, 2, 0, tzinfo=timezone.utc)

    already_at_two = datetime(2026, 3, 2, 2, 0, tzinfo=timezone.utc)
    assert estate_schedule.next_cron_time("0 2 * * *", already_at_two) == datetime(
        2026, 3, 3, 2, 0, tzinfo=timezone.utc
    ), "the matching minute itself is not 'after'"


def test_cron_supports_lists_ranges_steps_and_day_names():
    assert estate_schedule.parse_cron("0 2 * * mon")["day of week"] == {1}
    assert estate_schedule.parse_cron("*/15 * * * *")["minute"] == {0, 15, 30, 45}
    assert estate_schedule.parse_cron("0 9-17 * * 1-5")["hour"] == set(range(9, 18))
    assert estate_schedule.parse_cron("0 0 1,15 * *")["day of month"] == {1, 15}
    # a weekly 07:00 Monday run from a Sunday evening
    assert estate_schedule.next_cron_time("0 7 * * mon", NOW) == datetime(
        2026, 3, 2, 7, 0, tzinfo=timezone.utc
    )


@pytest.mark.parametrize("expression", ["", "0 2 * *", "0 25 * * *", "*/0 * * * *", "0 2 * * nonsense"])
def test_a_malformed_cron_is_refused(expression):
    with pytest.raises(estate_schedule.ScheduleError):
        estate_schedule.parse_cron(expression)


def test_both_or_neither_cadence_is_refused():
    with pytest.raises(estate_schedule.ScheduleError):
        estate_schedule.next_run_at(interval_minutes=60, cron="0 2 * * *", after=NOW)
    with pytest.raises(estate_schedule.ScheduleError):
        estate_schedule.next_run_at(interval_minutes=None, cron=None, after=NOW)


# --------------------------------------------------------------------------- #
# CRUD
# --------------------------------------------------------------------------- #
def test_create_and_list_a_schedule(session):
    row = _schedule(
        session, name="nightly", every="6h", scope="production", estate="bank-a",
        planes=["network", "static"], user="tester", now=NOW,
    )
    assert _utc(row.next_run_at) == NOW + timedelta(hours=6)
    payload = estate_schedule.as_dict(row)
    assert payload["cadence"] == {"every": "360m", "interval_minutes": 360}
    assert payload["planes"] == ["NETWORK", "STATIC"], "plane names are normalised, not stored as typed"
    assert payload["enabled"] is True and payload["last_run"]["verdict"] is None

    names = [item.name for item in estate_schedule.list_schedules(session)]
    assert names == ["nightly"]


def test_a_duplicate_name_is_refused(session):
    _schedule(session, name="nightly", every="1d", now=NOW)
    with pytest.raises(estate_schedule.ScheduleError) as caught:
        _schedule(session, name="nightly", every="1h", now=NOW)
    assert caught.value.code == "schedule_exists"


def test_platform_schedule_name_is_database_unique_under_concurrent_writes(session):
    _schedule(session, name="nightly", every="1h", now=NOW)
    session.add(EstateSchedule(name="nightly", tenant_id=None, next_run_at=NOW + timedelta(hours=1),
                               planes='["STATIC"]'))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
    assert len(estate_schedule.list_schedules(session, exact_tenant=True)) == 1


def test_lookup_by_name_and_id(session):
    row = _schedule(session, name="weekly", cron="0 2 * * mon", now=NOW)
    assert estate_schedule.get_schedule(session, "weekly").id == row.id
    assert estate_schedule.get_schedule(session, row.id).name == "weekly"


def test_disabling_pauses_and_enabling_resumes_on_cadence(session):
    row = _schedule(session, name="nightly", every="6h", now=NOW)
    estate_schedule.set_enabled(session, "nightly", False)
    assert estate_schedule.list_schedules(session, include_disabled=False) == []
    assert estate_schedule.claim_due(session, worker="w", now=NOW + timedelta(days=1)) == []

    later = NOW + timedelta(days=1)
    resumed = estate_schedule.set_enabled(session, row.id, True, now=later)
    assert _utc(resumed.next_run_at) == later + timedelta(hours=6), "re-enabling must not fire immediately"


def test_old_external_schedule_cannot_be_reenabled_without_new_authorization(session):
    row = _schedule(session, name="legacy", every="6h", enabled=False, now=NOW)
    row.planes = '["CLOUD"]'
    session.commit()
    with pytest.raises(estate_schedule.ScheduleError, match="not qualified"):
        estate_schedule.set_enabled(session, row.id, True)
    assert row.enabled is False


def test_schedule_delete_refuses_to_erase_its_run_history(session):
    row = _schedule(session, name="nightly", every="6h", now=NOW)
    session.add(EstateScheduleRun(schedule_id=row.id, started_at=NOW, status="ERROR",
                                   tenant_id=None, detail="collector failed"))
    session.commit()
    with pytest.raises(estate_schedule.ScheduleError) as caught:
        estate_schedule.delete_schedule(session, "nightly")
    assert caught.value.code == "schedule_retention_required"
    assert estate_schedule.get_schedule(session, row.id) is not None
    assert session.query(EstateScheduleRun).filter_by(schedule_id=row.id).count() == 1
    assert estate_schedule.set_enabled(session, row.id, False).enabled is False


# --------------------------------------------------------------------------- #
# leasing and the tick
# --------------------------------------------------------------------------- #
def test_a_lease_lets_only_one_worker_claim_a_due_schedule(session):
    _schedule(session, name="nightly", every="6h", now=NOW - timedelta(hours=7))
    first = estate_schedule.claim_due(session, worker="worker-a", now=NOW)
    second = estate_schedule.claim_due(session, worker="worker-b", now=NOW)
    assert [row.name for row in first] == ["nightly"]
    assert second == [], "the second worker must see no rows, not the same row"


def test_an_expired_lease_can_be_reclaimed(session):
    _schedule(session, name="nightly", every="6h", now=NOW - timedelta(hours=7))
    estate_schedule.claim_due(session, worker="dead-worker", now=NOW, lease_seconds=60)
    later = NOW + timedelta(minutes=5)
    assert [row.name for row in estate_schedule.claim_due(session, worker="worker-b", now=later)] == [
        "nightly"
    ]


def test_tick_scopes_each_runner_and_event_to_its_own_estate(session):
    from db.tenancy import current_tenant

    _schedule(session, name="nightly", tenant_id="a", every="6h", now=NOW - timedelta(hours=7))
    _schedule(session, name="nightly", tenant_id="b", every="6h", now=NOW - timedelta(hours=7))
    seen = []

    def runner(row):
        seen.append((row.tenant_id, current_tenant()))
        return _report()

    result = estate_schedule.tick(session, worker="w", now=NOW, runner=runner)
    assert result["claimed"] == 2
    assert len(seen) == 2 and set(seen) == {("a", "a"), ("b", "b")}
    assert current_tenant() is None
    assert {r.tenant_id for r in session.query(EstateScheduleRun).all()} == {"a", "b"}


def test_scheduled_events_use_the_claimed_estate_not_the_daemons_platform_scope(session, monkeypatch):
    from api import estate_discovery
    from api.estate_events import bus_publisher
    from api.events.bus import reset_event_bus
    from api.security.socket_history import visible_event
    from db.tenancy import current_tenant

    bus = reset_event_bus()
    _schedule(session, name="nightly", tenant_id="a", every="1m", now=NOW - timedelta(minutes=5))

    def run(_db, **kwargs):
        kwargs["on_event"]("estate.run.started", {"estate": kwargs["estate"]})
        return _report()

    monkeypatch.setattr(estate_discovery, "run", run)

    def publish(event_type, payload):
        bus_publisher(tenant_id=current_tenant())(event_type, payload)

    estate_schedule.tick(session, worker="daemon", now=NOW, on_event=publish)
    events = [row for row in bus.recent(0, 20) if row["type"] == "estate.run.started"]
    assert len(events) == 1 and events[0]["tenant_id"] == "a"
    assert visible_event(events[0], "a") and not visible_event(events[0], "b")


def test_tick_runs_due_schedules_and_records_the_verdict(session):
    _schedule(session, name="nightly", every="6h", now=NOW - timedelta(hours=7))
    _schedule(session, name="future", every="6h", now=NOW)

    result = estate_schedule.tick(session, worker="w", now=NOW, runner=lambda _row: _report())
    assert result["claimed"] == 1
    assert result["ran"][0]["schedule"] == "nightly"
    assert result["ran"][0]["verdict"] == "COMPLETE"

    row = estate_schedule.get_schedule(session, "nightly")
    assert row.last_verdict == "COMPLETE"
    assert row.last_coverage_state == "MEASURED"
    assert row.consecutive_failures == 0
    assert _utc(row.next_run_at) == NOW + timedelta(hours=6), "the cadence advances from the tick clock"
    assert row.claimed_until is None, "the lease is released when the run finishes"

    stored = session.execute(
        select(EstateScheduleRun).order_by(EstateScheduleRun.started_at)
    ).scalars().all()
    assert [item.status for item in stored] == ["OK"]
    assert stored[0].estate_run_id == "run-1"


def test_tick_records_a_partial_verdict_instead_of_hiding_it(session):
    _schedule(session, name="nightly", every="6h", now=NOW - timedelta(hours=7))
    estate_schedule.tick(session, worker="w", now=NOW,
                         runner=lambda _row: _report("PARTIAL_COVERAGE", "NOT_OBSERVED"))
    row = estate_schedule.get_schedule(session, "nightly")
    assert row.last_verdict == "PARTIAL_COVERAGE"
    assert row.last_coverage_state == "NOT_OBSERVED"


def test_legacy_all_planes_schedule_is_refused_before_any_collector_runs(session):
    row = _schedule(session, name="legacy", every="1m", now=NOW - timedelta(minutes=5))
    row.planes = None
    session.commit()

    def forbidden(_row):
        raise AssertionError("no collector may run for an unscoped legacy schedule")

    result = estate_schedule.tick(session, worker="w", now=NOW, runner=forbidden)
    assert result["ran"][0]["status"] == "ERROR"
    assert "Select at least one persisted-evidence plane" in result["ran"][0]["error"]
    assert _utc(row.next_run_at) > NOW


def test_a_failed_run_is_recorded_and_does_not_spin(session):
    _schedule(session, name="nightly", every="6h", now=NOW - timedelta(hours=7))

    def boom(_row):
        raise RuntimeError("collector exploded")

    result = estate_schedule.tick(session, worker="w", now=NOW, runner=boom)
    assert result["ran"][0]["status"] == "ERROR"
    assert "collector exploded" in result["ran"][0]["error"]

    row = estate_schedule.get_schedule(session, "nightly")
    assert row.consecutive_failures == 1
    assert row.last_verdict == "ERROR"
    assert _utc(row.next_run_at) == NOW + timedelta(hours=6), "a failed run still advances"
    assert row.claimed_until is None

    # and the next tick on the same clock finds nothing to do
    assert estate_schedule.tick(session, worker="w", now=NOW, runner=boom)["claimed"] == 0


def test_tick_uses_the_real_estate_job_by_default(session, monkeypatch):
    from api import estate_discovery

    seen: list[dict] = []

    def fake_run(_db, **kwargs):
        seen.append(kwargs)
        return _report("COMPLETE")

    monkeypatch.setattr(estate_discovery, "run", fake_run)
    _schedule(session, name="nightly", every="6h", scope="production",
                                    estate="bank-a", planes=["STATIC"], now=NOW - timedelta(hours=7))
    estate_schedule.tick(session, worker="w", now=NOW)
    assert len(seen) == 1
    assert seen[0]["estate"] == "bank-a"
    assert seen[0]["scope"] == "production"
    assert seen[0]["planes"] == ["STATIC"]
    # a scheduled run is labelled as such, and carries no event sink unless given one
    assert seen[0]["trigger"] == "schedule"
    assert seen[0]["on_event"] is None


# --------------------------------------------------------------------------- #
# CLI and API
# --------------------------------------------------------------------------- #
def test_cli_saves_lists_and_runs_a_schedule(session, capsys):
    code = cli.main(["schedule", "add", "nightly", "--every", "6h", "--plane", "STATIC"], session_factory=lambda: session)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "saved      nightly — every 360m, enabled" in out

    code = cli.main(["schedule", "list"], session_factory=lambda: session)
    assert "nightly" in capsys.readouterr().out

    # nothing is due yet, and the tick says so instead of inventing a run
    code = cli.main(["tick"], session_factory=lambda: session)
    assert code == cli.EXIT_OK
    assert "nothing was due" in capsys.readouterr().out


def test_cli_refuses_an_ambiguous_cadence_with_an_exit_code(session, capsys):
    code = cli.main(["schedule", "add", "bad", "--every", "6h", "--cron", "0 2 * * *", "--plane", "STATIC"],
                    session_factory=lambda: session)
    out = capsys.readouterr().out
    assert code == cli.EXIT_REFUSED
    assert "cadence_ambiguous" in out


def test_cli_tick_runs_a_due_schedule_and_reports_the_verdict(session, capsys, monkeypatch):
    from api import estate_discovery

    monkeypatch.setattr(estate_discovery, "run", lambda _db, **kwargs: _report("PARTIAL_COVERAGE"))
    _schedule(session, name="nightly", every="1m",
                                    now=datetime.now(timezone.utc) - timedelta(minutes=5))
    code = cli.main(["tick"], session_factory=lambda: session)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "PARTIAL_COVERAGE" in out


def test_cli_json_tick_is_parseable(session, capsys):
    code = cli.main(["tick", "--json"], session_factory=lambda: session)
    payload = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_OK
    assert payload["model"] == "cryptoscan.estate-schedule-tick/1"
    assert payload["claimed"] == 0


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
def test_api_saves_lists_and_pauses_without_erasing_a_schedule(assured, monkeypatch):
    clients, _session, _ = assured
    http = selected_admin(clients, "a")
    from api import estate_discovery

    monkeypatch.setattr(estate_discovery, "run", lambda _db, **kwargs: _report("COMPLETE"))

    created = http.post("/api/v1/estate/evidence/schedules",
                        json={"name": "nightly", "every": "6h", "estate": "bank-a", "planes": ["STATIC"]})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["cadence"]["interval_minutes"] == 360
    assert body["next_run_at"].endswith("+00:00")

    listing = http.get("/api/v1/estate/evidence/schedules").json()
    assert [item["name"] for item in listing["schedules"]] == ["nightly"]
    assert "crontab" in listing["note"]

    paused = http.request("PATCH", "/api/v1/estate/evidence/schedules/nightly", json={"enabled": False})
    assert paused.status_code == 200 and paused.json()["enabled"] is False

    # a paused schedule is never due, even when its next_run_at is in the past
    assert http.post("/api/v1/estate/evidence/tick", json={"worker": "test"}).json()["claimed"] == 0

    refused = http.request("DELETE", "/api/v1/estate/evidence/schedules/nightly")
    assert refused.status_code == 409
    assert refused.json()["detail"]["error"] == "schedule_retention_required"
    assert [row["name"] for row in http.get("/api/v1/estate/evidence/schedules").json()["schedules"]] == ["nightly"]


def test_api_refuses_an_ambiguous_or_duplicate_schedule(assured):
    clients, _session, _ = assured
    http = selected_admin(clients, "a")
    both = http.post("/api/v1/estate/evidence/schedules",
                     json={"name": "bad", "every": "6h", "cron": "0 2 * * *"})
    assert both.status_code == 422
    assert both.json()["detail"]["error"] == "cadence_ambiguous"

    assert http.post("/api/v1/estate/evidence/schedules",
                     json={"name": "ok", "every": "6h", "planes": ["STATIC"]}).status_code == 201
    duplicate = http.post("/api/v1/estate/evidence/schedules",
                          json={"name": "ok", "every": "1h", "planes": ["STATIC"]})
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["error"] == "schedule_exists"


def test_schedule_mutations_require_current_monitor_manager(assured):
    clients, _session, _ = assured
    path = "/api/v1/estate/evidence/schedules"
    body = {"name": "nightly", "every": "6h", "planes": ["STATIC"]}
    for client in (clients["reader_a"], clients["bank_a"]):
        assert client.post(path, json=body).status_code == 403
        assert client.patch(path + "/nightly", json={"enabled": True}).status_code == 403
        assert client.delete(path + "/nightly").status_code == 403
        assert client.post("/api/v1/estate/evidence/tick", json={}).status_code == 403
    assert clients["bank_a"].get(path).status_code == 200
    assert clients["bank_a"].get(path).json()["schedules"] == []


def test_schedule_never_implies_permission_for_live_collection(assured):
    clients, _session, _ = assured
    admin = selected_admin(clients, "a")
    path = "/api/v1/estate/evidence/schedules"
    for planes in (None, [], ["CLOUD"], ["STATIC", "HSM"], ["BOGUS"]):
        body = {"name": "unsafe", "every": "1m"}
        if planes is not None:
            body["planes"] = planes
        response = admin.post(path, json=body)
        assert response.status_code == 422, response.text
    assert admin.get(path).json()["schedules"] == []


def test_schedule_ids_are_exact_estate_for_reads_and_writes(assured):
    clients, _session, _ = assured
    a, b = selected_admin(clients, "a"), selected_admin(clients, "b")
    path = "/api/v1/estate/evidence/schedules"
    row = a.post(path, json={"name": "nightly", "every": "6h", "planes": ["STATIC"]}).json()
    assert b.get(path).json()["schedules"] == []
    assert b.request("PATCH", path + "/" + row["id"], json={"enabled": False}).status_code == 404
    assert b.request("DELETE", path + "/" + row["id"]).status_code == 404
    assert b.post("/api/v1/estate/evidence/tick", json={}).json()["claimed"] == 0
    assert clients["platform_admin"].post("/api/v1/estate/evidence/tick", json={}).json()["claimed"] == 0
    assert clients["platform_admin"].get(path).json()["schedules"] == []
    assert [s["id"] for s in a.get(path).json()["schedules"]] == [row["id"]]


def test_api_tick_records_the_verdict_of_a_due_schedule(assured, monkeypatch):
    clients, _session, _ = assured
    http = selected_admin(clients, "a")
    from api import estate_discovery, estate_schedule as module

    monkeypatch.setattr(estate_discovery, "run", lambda _db, **kwargs: _report("PARTIAL_COVERAGE",
                                                                              "NOT_OBSERVED"))
    created = http.post("/api/v1/estate/evidence/schedules",
                        json={"name": "nightly", "every": "1m", "planes": ["STATIC"]}).json()
    # make it due without waiting a minute (the fixture hands back the session itself)
    row = module.get_schedule(_session, created["id"], tenant_id="a")
    row.next_run_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    _session.commit()

    ticked = http.post("/api/v1/estate/evidence/tick", json={"worker": "api-tick"})
    assert ticked.status_code == 200, ticked.text
    body = ticked.json()
    assert body["claimed"] == 1
    assert body["ran"][0]["verdict"] == "PARTIAL_COVERAGE"

    listed = http.get("/api/v1/estate/evidence/schedules").json()["schedules"][0]
    assert listed["last_run"]["verdict"] == "PARTIAL_COVERAGE"
    assert listed["last_run"]["coverage_state"] == "NOT_OBSERVED"
