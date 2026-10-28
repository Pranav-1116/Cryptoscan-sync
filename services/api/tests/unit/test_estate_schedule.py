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
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api import cli, estate_schedule
from api.estate_schedule import _utc
from db.connection.session import Base
from db.models.estate_schedule import EstateScheduleRun

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

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
    row = estate_schedule.create_schedule(
        session, name="nightly", every="6h", scope="production", estate="bank-a",
        planes=["network", "cloud"], user="tester", now=NOW,
    )
    assert _utc(row.next_run_at) == NOW + timedelta(hours=6)
    payload = estate_schedule.as_dict(row)
    assert payload["cadence"] == {"every": "360m", "interval_minutes": 360}
    assert payload["planes"] == ["CLOUD", "NETWORK"], "plane names are normalised, not stored as typed"
    assert payload["enabled"] is True and payload["last_run"]["verdict"] is None

    names = [item.name for item in estate_schedule.list_schedules(session)]
    assert names == ["nightly"]


def test_a_duplicate_name_is_refused(session):
    estate_schedule.create_schedule(session, name="nightly", every="1d", now=NOW)
    with pytest.raises(estate_schedule.ScheduleError) as caught:
        estate_schedule.create_schedule(session, name="nightly", every="1h", now=NOW)
    assert caught.value.code == "schedule_exists"


def test_lookup_by_name_and_id(session):
    row = estate_schedule.create_schedule(session, name="weekly", cron="0 2 * * mon", now=NOW)
    assert estate_schedule.get_schedule(session, "weekly").id == row.id
    assert estate_schedule.get_schedule(session, row.id).name == "weekly"


def test_disabling_pauses_and_enabling_resumes_on_cadence(session):
    row = estate_schedule.create_schedule(session, name="nightly", every="6h", now=NOW)
    estate_schedule.set_enabled(session, "nightly", False)
    assert estate_schedule.list_schedules(session, include_disabled=False) == []
    assert estate_schedule.claim_due(session, worker="w", now=NOW + timedelta(days=1)) == []

    later = NOW + timedelta(days=1)
    resumed = estate_schedule.set_enabled(session, row.id, True, now=later)
    assert _utc(resumed.next_run_at) == later + timedelta(hours=6), "re-enabling must not fire immediately"


def test_removing_a_schedule(session):
    estate_schedule.create_schedule(session, name="nightly", every="6h", now=NOW)
    removed = estate_schedule.delete_schedule(session, "nightly")
    assert removed
    with pytest.raises(estate_schedule.ScheduleError):
        estate_schedule.delete_schedule(session, "nightly")


# --------------------------------------------------------------------------- #
# leasing and the tick
# --------------------------------------------------------------------------- #
def test_a_lease_lets_only_one_worker_claim_a_due_schedule(session):
    estate_schedule.create_schedule(session, name="nightly", every="6h", now=NOW - timedelta(hours=7))
    first = estate_schedule.claim_due(session, worker="worker-a", now=NOW)
    second = estate_schedule.claim_due(session, worker="worker-b", now=NOW)
    assert [row.name for row in first] == ["nightly"]
    assert second == [], "the second worker must see no rows, not the same row"


def test_an_expired_lease_can_be_reclaimed(session):
    estate_schedule.create_schedule(session, name="nightly", every="6h", now=NOW - timedelta(hours=7))
    estate_schedule.claim_due(session, worker="dead-worker", now=NOW, lease_seconds=60)
    later = NOW + timedelta(minutes=5)
    assert [row.name for row in estate_schedule.claim_due(session, worker="worker-b", now=later)] == [
        "nightly"
    ]


def test_tick_runs_due_schedules_and_records_the_verdict(session):
    estate_schedule.create_schedule(session, name="nightly", every="6h", now=NOW - timedelta(hours=7))
    estate_schedule.create_schedule(session, name="future", every="6h", now=NOW)

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
    estate_schedule.create_schedule(session, name="nightly", every="6h", now=NOW - timedelta(hours=7))
    estate_schedule.tick(session, worker="w", now=NOW,
                         runner=lambda _row: _report("PARTIAL_COVERAGE", "NOT_OBSERVED"))
    row = estate_schedule.get_schedule(session, "nightly")
    assert row.last_verdict == "PARTIAL_COVERAGE"
    assert row.last_coverage_state == "NOT_OBSERVED"


def test_a_failed_run_is_recorded_and_does_not_spin(session):
    estate_schedule.create_schedule(session, name="nightly", every="6h", now=NOW - timedelta(hours=7))

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
    estate_schedule.create_schedule(session, name="nightly", every="6h", scope="production",
                                    estate="bank-a", planes=["STATIC"], now=NOW - timedelta(hours=7))
    estate_schedule.tick(session, worker="w", now=NOW)
    assert seen == [{"estate": "bank-a", "scope": "production", "planes": ["STATIC"]}]


# --------------------------------------------------------------------------- #
# CLI and API
# --------------------------------------------------------------------------- #
def test_cli_saves_lists_and_runs_a_schedule(session, capsys):
    code = cli.main(["schedule", "add", "nightly", "--every", "6h"], session_factory=lambda: session)
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
    code = cli.main(["schedule", "add", "bad", "--every", "6h", "--cron", "0 2 * * *"],
                    session_factory=lambda: session)
    out = capsys.readouterr().out
    assert code == cli.EXIT_REFUSED
    assert "cadence_ambiguous" in out


def test_cli_tick_runs_a_due_schedule_and_reports_the_verdict(session, capsys, monkeypatch):
    from api import estate_discovery

    monkeypatch.setattr(estate_discovery, "run", lambda _db, **kwargs: _report("PARTIAL_COVERAGE"))
    estate_schedule.create_schedule(session, name="nightly", every="1m",
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
def test_api_saves_lists_toggles_and_deletes_a_schedule(api, monkeypatch):
    http, _session = api
    from api import estate_discovery

    monkeypatch.setattr(estate_discovery, "run", lambda _db, **kwargs: _report("COMPLETE"))

    created = http.post("/api/v1/estate/evidence/schedules",
                        json={"name": "nightly", "every": "6h", "estate": "bank-a"})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["cadence"]["interval_minutes"] == 360
    assert body["next_run_at"].endswith("+00:00")

    listing = http.get("/api/v1/estate/evidence/schedules").json()
    assert [item["name"] for item in listing["schedules"]] == ["nightly"]
    assert "crontab" in listing["note"]

    paused = http.patch("/api/v1/estate/evidence/schedules/nightly", json={"enabled": False})
    assert paused.status_code == 200 and paused.json()["enabled"] is False

    # a paused schedule is never due, even when its next_run_at is in the past
    assert http.post("/api/v1/estate/evidence/tick", json={"worker": "test"}).json()["claimed"] == 0

    removed = http.delete("/api/v1/estate/evidence/schedules/nightly")
    assert removed.status_code == 200 and removed.json()["deleted"]
    assert http.delete("/api/v1/estate/evidence/schedules/nightly").status_code == 404


def test_api_refuses_an_ambiguous_or_duplicate_schedule(api):
    http, _session = api
    both = http.post("/api/v1/estate/evidence/schedules",
                     json={"name": "bad", "every": "6h", "cron": "0 2 * * *"})
    assert both.status_code == 422
    assert both.json()["detail"]["error"] == "cadence_ambiguous"

    assert http.post("/api/v1/estate/evidence/schedules",
                     json={"name": "ok", "every": "6h"}).status_code == 201
    duplicate = http.post("/api/v1/estate/evidence/schedules",
                          json={"name": "ok", "every": "1h"})
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["error"] == "schedule_exists"


def test_api_tick_records_the_verdict_of_a_due_schedule(api, monkeypatch):
    http, _session = api
    from api import estate_discovery, estate_schedule as module

    monkeypatch.setattr(estate_discovery, "run", lambda _db, **kwargs: _report("PARTIAL_COVERAGE",
                                                                              "NOT_OBSERVED"))
    created = http.post("/api/v1/estate/evidence/schedules",
                        json={"name": "nightly", "every": "1m"}).json()
    # make it due without waiting a minute (the fixture hands back the session itself)
    row = module.get_schedule(_session, created["id"])
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
