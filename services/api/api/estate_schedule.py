"""Scheduled estate runs: saved cadence, a leased tick, and a recorded outcome.

The estate job was on demand only. This module makes it schedulable without
pretending a cron entry is a scheduler:

* the **schedule lives in the database**, so it survives deploys and is visible to
  the console and the CLI;
* the tick **claims each due row with a lease** (a conditional UPDATE), so two
  workers, two pods or a manual ``cryptoscan tick`` racing the sidecar cannot run
  the same schedule twice;
* the outcome — verdict, coverage state, estate run id, failure count — is written
  next to the schedule and as its own run row, so "it ran last night" is a claim
  with evidence rather than a hope;
* a run that raises still advances ``next_run_at``: a broken connector must never
  pin a schedule in the past and spin.

Cadence is one of ``interval_minutes`` ("every 6h from the last run") or a
five-field **UTC** cron expression. UTC is stated, not inherited from the host
clock, so a DST change never moves an audit run by an hour.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Mapping

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db.models.estate_schedule import EstateSchedule, EstateScheduleRun

DEFAULT_LEASE_SECONDS = 900
MAX_INTERVAL_MINUTES = 366 * 24 * 60
# These adapters only read evidence already retained in this estate. Live cloud,
# cluster, CMDB, KMS and HSM adapters need separate approved collection controls.
PERSISTED_SCHEDULE_PLANES = frozenset({"NETWORK", "RUNTIME", "STATIC", "PKI", "HARDWARE", "VENDOR"})

_CRON_FIELDS = (
    ("minute", 0, 59),
    ("hour", 0, 23),
    ("day of month", 1, 31),
    ("month", 1, 12),
    ("day of week", 0, 6),  # 0 = Sunday, like cron(5)
)

#: cron day-of-week names, because "0 2 * * mon" is what people type
_DOW_NAMES = {
    name: index for index, name in enumerate(
        ("sun", "mon", "tue", "wed", "thu", "fri", "sat")
    )
}


class ScheduleError(ValueError):
    """The schedule as written cannot be honoured."""

    def __init__(self, code: str, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(reason)


def _utc(moment: datetime | None = None) -> datetime:
    """Aware UTC, and naive values are assumed UTC rather than local time."""
    if moment is None:
        return datetime.now(timezone.utc)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# cadence
# --------------------------------------------------------------------------- #
def parse_interval(value: Any) -> int:
    """``"15m"`` / ``"6h"`` / ``"7d"`` / ``"90"`` (minutes) → minutes."""
    text = str(value if value is not None else "").strip().lower()
    if not text:
        raise ScheduleError("interval_invalid", "an interval is required, e.g. 15m, 6h or 1d")
    unit = text[-1]
    number = text[:-1].strip() if unit.isalpha() else text
    multiplier = {"m": 1, "h": 60, "d": 1440, "w": 10080}.get(unit, 1)
    try:
        amount = int(number)
    except ValueError as exc:
        raise ScheduleError(
            "interval_invalid", f"{value!r} is not an interval; use 15m, 6h, 1d or a number of minutes"
        ) from exc
    minutes = amount * multiplier
    if minutes < 1:
        raise ScheduleError("interval_invalid", "an interval of zero would spin: use at least 1m")
    if minutes > MAX_INTERVAL_MINUTES:
        raise ScheduleError("interval_invalid", f"{minutes} minutes is longer than a year")
    return minutes


def _parse_field(text: str, name: str, low: int, high: int) -> set[int]:
    values: set[int] = set()
    for part in text.split(","):
        piece = part.strip().lower()
        if not piece:
            raise ScheduleError("cron_invalid", f"empty {name} field")
        step = 1
        if "/" in piece:
            piece, _, step_text = piece.partition("/")
            if not step_text.isdigit() or int(step_text) < 1:
                raise ScheduleError("cron_invalid", f"{name} step {step_text!r} is not a positive number")
            step = int(step_text)
        if piece in {"*", "?"}:
            start, end = low, high
        elif "-" in piece:
            first, _, last = piece.partition("-")
            start, end = _cron_value(first, name, low, high), _cron_value(last, name, low, high)
            if start > end:
                raise ScheduleError("cron_invalid", f"{name} range {piece!r} runs backwards")
        else:
            start = end = _cron_value(piece, name, low, high)
        values.update(range(start, end + 1, step))
    if not values:
        raise ScheduleError("cron_invalid", f"{name} field selects nothing")
    return values


def _cron_value(text: str, name: str, low: int, high: int) -> int:
    token = text.strip().lower()
    if name == "day of week" and token in _DOW_NAMES:
        return _DOW_NAMES[token]
    if not token.lstrip("-").isdigit():
        raise ScheduleError("cron_invalid", f"{name} value {text!r} is not a number")
    value = int(token)
    # 7 is Sunday in some cron dialects; normalise instead of rejecting
    if name == "day of week" and value == 7:
        return 0
    if not low <= value <= high:
        raise ScheduleError("cron_invalid", f"{name} value {value} is outside {low}-{high}")
    return value


def parse_cron(expression: str) -> dict[str, set[int]]:
    """Five UTC fields → sets. Raises :class:`ScheduleError` for anything ambiguous."""
    fields = str(expression or "").split()
    if len(fields) != 5:
        raise ScheduleError(
            "cron_invalid",
            f"a cron expression needs 5 fields (minute hour day-of-month month day-of-week), got {len(fields)}",
        )
    parsed = {}
    for text, (name, low, high) in zip(fields, _CRON_FIELDS):
        parsed[name] = _parse_field(text, name, low, high)
    return parsed


def next_cron_time(expression: str, after: datetime) -> datetime:
    """The first minute strictly after ``after`` matching the expression (UTC)."""
    fields = parse_cron(expression)
    moment = _utc(after).replace(second=0, microsecond=0) + timedelta(minutes=1)
    # a five-field expression with no year repeats within 8 years at worst;
    # one year of minutes is 525,600 — cap well above the worst-case gaps
    for _ in range(4 * 366 * 24 * 60):
        weekday = (moment.weekday() + 1) % 7  # python Monday=0 → cron Sunday=0
        if (
            moment.minute in fields["minute"]
            and moment.hour in fields["hour"]
            and moment.day in fields["day of month"]
            and moment.month in fields["month"]
            and weekday in fields["day of week"]
        ):
            return moment
        moment += timedelta(minutes=1)
    raise ScheduleError("cron_invalid", f"{expression!r} never matches a real date")


def next_run_at(
    *,
    interval_minutes: int | None,
    cron: str | None,
    after: datetime,
) -> datetime:
    """When the next run is due, from the cadence and a reference moment."""
    if bool(interval_minutes) == bool(cron):
        raise ScheduleError(
            "cadence_ambiguous",
            "give exactly one cadence: --every 6h or --cron '0 2 * * *'",
        )
    if interval_minutes:
        return _utc(after) + timedelta(minutes=int(interval_minutes))
    return next_cron_time(str(cron), after)


# --------------------------------------------------------------------------- #
# schedule CRUD
# --------------------------------------------------------------------------- #
def admitted_planes(planes: Iterable[str] | None) -> list[str]:
    """A schedule reprojects retained evidence; it cannot authorize acquisition."""
    requested = sorted({str(item).strip().upper() for item in planes or [] if str(item).strip()})
    if not requested:
        raise ScheduleError("planes_required", "Select at least one persisted-evidence plane; an omitted or empty list would run every live collector")
    unsupported = sorted(set(requested) - PERSISTED_SCHEDULE_PLANES)
    if unsupported:
        raise ScheduleError("plane_not_authorized", f"Scheduled collection is not qualified for {', '.join(unsupported)}; use separately approved acquisition and reproject its stored evidence")
    return requested


def _planes(planes: Iterable[str] | None) -> str:
    return json.dumps(admitted_planes(planes))


def create_schedule(
    db: Session,
    *,
    name: str,
    tenant_id: str | None = None,
    scope: str = "production",
    estate: str = "default",
    every: str | None = None,
    cron: str | None = None,
    planes: Iterable[str] | None = None,
    enabled: bool = True,
    user: str | None = None,
    now: datetime | None = None,
) -> EstateSchedule:
    """Save a cadence. Refuses a nameless, ambiguous or already-taken schedule."""
    label = str(name or "").strip()
    if not label:
        raise ScheduleError("name_required", "a schedule needs a name — it is how it is referred to later")
    interval = parse_interval(every) if every else None
    expression = str(cron).strip() if cron else None
    moment = _utc(now)
    upcoming = next_run_at(interval_minutes=interval, cron=expression, after=moment)

    existing = db.execute(
        select(EstateSchedule).where(EstateSchedule.name == label,
                                    EstateSchedule.tenant_id == tenant_id)
    ).scalars().first()
    if existing is not None:
        raise ScheduleError(
            "schedule_exists",
            f"a schedule named {label!r} already exists — remove it or choose another name",
        )

    row = EstateSchedule(
        name=label,
        tenant_id=tenant_id,
        scope=str(scope or "production"),
        estate=str(estate or "default"),
        planes=_planes(planes),
        interval_minutes=interval,
        cron=expression,
        enabled=bool(enabled),
        next_run_at=upcoming,
        consecutive_failures=0,
        created_by=user,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", "") or ""
        if constraint not in {"uq_estate_schedule_platform_name", "uq_estate_schedule_tenant_name"} and not (
            "UNIQUE constraint failed: estate_schedules.name" in str(exc.orig)
            or "UNIQUE constraint failed: estate_schedules.tenant_id, estate_schedules.name" in str(exc.orig)
        ):
            raise
        raise ScheduleError("schedule_exists", f"a schedule named {label!r} already exists in this estate") from exc
    db.refresh(row)
    return row


def list_schedules(db: Session, *, tenant_id: str | None = None, include_disabled: bool = True,
                   exact_tenant: bool = False) -> list[EstateSchedule]:
    statement = select(EstateSchedule)
    if exact_tenant or tenant_id is not None:
        statement = statement.where(EstateSchedule.tenant_id == tenant_id)
    if not include_disabled:
        statement = statement.where(EstateSchedule.enabled.is_(True))
    return list(db.execute(statement.order_by(EstateSchedule.next_run_at)).scalars().all())


def get_schedule(db: Session, identifier: str, *, tenant_id: str | None = None) -> EstateSchedule | None:
    """Look a schedule up by id **or** name (the name is what operators use)."""
    statement = select(EstateSchedule).where(EstateSchedule.id == identifier,
                                             EstateSchedule.tenant_id == tenant_id)
    row = db.execute(statement).scalars().first()
    if row is None:
        row = db.execute(
            select(EstateSchedule).where(EstateSchedule.name == identifier,
                                         EstateSchedule.tenant_id == tenant_id)
        ).scalars().first()
    return row


def set_enabled(db: Session, identifier: str, enabled: bool, *, tenant_id: str | None = None,
                now: datetime | None = None) -> EstateSchedule:
    row = get_schedule(db, identifier, tenant_id=tenant_id)
    if row is None:
        raise ScheduleError("schedule_not_found", f"no schedule {identifier!r}")
    if enabled:
        admitted_planes(json.loads(row.planes) if row.planes else None)
    row.enabled = bool(enabled)
    if enabled:
        # re-enabling must not fire immediately: the schedule resumes on cadence
        row.next_run_at = next_run_at(
            interval_minutes=row.interval_minutes, cron=row.cron, after=_utc(now)
        )
    db.commit()
    db.refresh(row)
    return row


def delete_schedule(db: Session, identifier: str, *, tenant_id: str | None = None) -> str:
    row = get_schedule(db, identifier, tenant_id=tenant_id)
    if row is None:
        raise ScheduleError("schedule_not_found", f"no schedule {identifier!r}")
    # The FK on estate_schedule_runs cascades DELETE. Until a separately
    # reviewed tombstone migration exists, erasing the schedule would erase
    # every recorded run and make a failed cadence disappear from history.
    raise ScheduleError("schedule_retention_required",
                        "Schedules and their run receipts cannot be erased; pause the cadence instead")


def _iso(value: datetime | None) -> str | None:
    """Always zoned: a naive timestamp from the database is UTC, and says so."""
    return _utc(value).isoformat() if value is not None else None


def as_dict(row: EstateSchedule) -> dict[str, Any]:
    """Public shape: cadence, state, and what the last run actually did."""
    # SQLite returns naive datetimes; stamping UTC here means the API, the CLI and
    # the console never print a timestamp whose zone the reader has to guess
    return {
        "id": row.id,
        "name": row.name,
        "tenant_id": row.tenant_id,
        "scope": row.scope,
        "estate": row.estate,
        "planes": json.loads(row.planes) if row.planes else None,
        "cadence": (
            {"every": f"{row.interval_minutes}m", "interval_minutes": row.interval_minutes}
            if row.interval_minutes
            else {"cron": row.cron, "timezone": "UTC"}
        ),
        "enabled": row.enabled,
        "next_run_at": _iso(row.next_run_at),
        "last_run": {
            "at": _iso(row.last_run_at),
            "run_id": row.last_run_id,
            "verdict": row.last_verdict,
            "coverage_state": row.last_coverage_state,
        },
        "consecutive_failures": row.consecutive_failures,
        "leased_until": _iso(row.claimed_until),
        "created_by": row.created_by,
    }


# --------------------------------------------------------------------------- #
# the tick
# --------------------------------------------------------------------------- #
def claim_due(
    db: Session,
    *,
    worker: str,
    now: datetime | None = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    limit: int = 20,
    tenant_id: str | None = None,
    exact_tenant: bool = False,
) -> list[EstateSchedule]:
    """Claim due schedules for ``worker``; a second caller gets none of the same rows.

    The claim is a conditional UPDATE whose WHERE clause re-checks the lease, so
    two workers cannot both win a row: the losing UPDATE matches 0 rows.
    """
    moment = _utc(now)
    lease_until = moment + timedelta(seconds=max(30, int(lease_seconds)))
    statement = (
        select(EstateSchedule.id)
        .where(EstateSchedule.enabled.is_(True), EstateSchedule.next_run_at <= moment)
        .where((EstateSchedule.claimed_until.is_(None)) | (EstateSchedule.claimed_until < moment))
    )
    if exact_tenant:
        statement = statement.where(EstateSchedule.tenant_id == tenant_id)
    due = db.execute(statement.order_by(EstateSchedule.next_run_at).limit(limit)).scalars().all()

    claimed: list[EstateSchedule] = []
    for schedule_id in due:
        claim = update(EstateSchedule).where(EstateSchedule.id == schedule_id)
        if exact_tenant:
            claim = claim.where(EstateSchedule.tenant_id == tenant_id)
        result = db.execute(
            claim.where((EstateSchedule.claimed_until.is_(None)) | (EstateSchedule.claimed_until < moment))
            .values(claimed_by=worker, claimed_until=lease_until)
        )
        if result.rowcount == 1:
            claimed.append(schedule_id)
    db.commit()
    if not claimed:
        return []
    rows = db.execute(
        select(EstateSchedule).where(EstateSchedule.id.in_(claimed)).order_by(EstateSchedule.next_run_at)
    ).scalars().all()
    return list(rows)


def _advance(row: EstateSchedule, *, now: datetime) -> datetime:
    """The next occurrence after *now* — never a moment already in the past."""
    try:
        return next_run_at(interval_minutes=row.interval_minutes, cron=row.cron, after=now)
    except ScheduleError:
        # a schedule whose cadence became invalid must not spin: park it far
        # enough ahead that a human notices the next_run_at, and count the failure
        return now + timedelta(days=1)


def tick(
    db: Session,
    *,
    worker: str = "cryptoscan-tick",
    now: datetime | None = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    limit: int = 20,
    runner: Callable[..., Mapping[str, Any]] | None = None,
    on_event: Callable[[str, Mapping[str, Any]], Any] | None = None,
    tenant_id: str | None = None,
    exact_tenant: bool = False,
) -> dict[str, Any]:
    """Run every due schedule once, releasing each lease as it finishes.

    ``on_event`` is forwarded to the estate job, so a scheduled run is observable
    while it runs (``estate.run.started`` … ``estate.run.finished``) exactly like a
    manual one. The daemon passes an :class:`api.estate_events.EventSink`; a
    caller without one gets identical behaviour and no events.
    """
    moment = _utc(now)
    claimed = claim_due(db, worker=worker, now=moment, lease_seconds=lease_seconds, limit=limit,
                        tenant_id=tenant_id, exact_tenant=exact_tenant)
    if runner is None:
        from api import estate_discovery

        def runner(row: EstateSchedule) -> Mapping[str, Any]:  # type: ignore[misc]
            # compare against the previous stored run, so every scheduled run
            # detects change instead of waiting for someone to call /drift
            previous = estate_discovery.previous_report(db, tenant_id=row.tenant_id)
            return estate_discovery.run(
                db,
                estate=row.estate,
                scope=row.scope,
                planes=json.loads(row.planes) if row.planes else None,
                on_event=on_event,
                trigger="schedule",
                previous=previous,
            )

    ran: list[dict[str, Any]] = []
    for row in claimed:
        started = _utc(now)
        run_row = EstateScheduleRun(
            schedule_id=row.id,
            tenant_id=row.tenant_id,
            started_at=started,
            status="RUNNING",
            worker=worker,
        )
        db.add(run_row)
        db.commit()
        try:
            from db.tenancy import tenant_scope

            # Claiming is platform-wide; collection and every emitted event are
            # confined to the row's estate, never the daemon's ambient context.
            with tenant_scope(row.tenant_id):
                admitted_planes(json.loads(row.planes) if row.planes else None)
                report = runner(row) or {}
            verdict = str(report.get("verdict") or "UNKNOWN")
            coverage_state = str((report.get("coverage") or {}).get("summary", {})
                                 .get("coverage_state") or "UNKNOWN")
            run_row.status = "OK"
            run_row.estate_run_id = str(report.get("run_id") or "") or None
            run_row.verdict = verdict
            run_row.coverage_state = coverage_state
            run_row.detail = str(report.get("verdict_detail") or "")[:800] or None
            row.last_run_id = run_row.estate_run_id
            row.last_verdict = verdict
            row.last_coverage_state = coverage_state
            row.consecutive_failures = 0
            status = "OK"
            outcome = {"schedule": row.name, "status": status, "verdict": verdict,
                       "coverage_state": coverage_state, "run_id": run_row.estate_run_id}
        except Exception as exc:  # noqa: BLE001 - a failed run is recorded, not raised
            # a raised run can leave the session mid-transaction; roll back before
            # recording the failure, or the record itself would be unwritable
            db.rollback()
            run_row = db.get(EstateScheduleRun, run_row.id) or run_row
            run_row.status = "ERROR"
            run_row.verdict = "ERROR"
            run_row.detail = f"{type(exc).__name__}: {exc}"[:800]
            row.last_verdict = "ERROR"
            row.consecutive_failures = int(row.consecutive_failures or 0) + 1
            status = "ERROR"
            outcome = {"schedule": row.name, "status": status, "error": run_row.detail,
                       "consecutive_failures": row.consecutive_failures}
        run_row.finished_at = _utc()
        row.last_run_at = started
        # advance from the tick's clock, so a long outage does not queue N runs
        row.next_run_at = _advance(row, now=moment)
        row.claimed_by = None
        row.claimed_until = None
        db.commit()
        ran.append(outcome)

    return {
        "model": "cryptoscan.estate-schedule-tick/1",
        "worker": worker,
        "at": moment.isoformat(),
        "claimed": len(claimed),
        "ran": ran,
        "note": (
            "a schedule runs at most once per lease: the claim is a conditional UPDATE, so a second "
            "worker sees zero rows rather than a duplicate run"
        ),
    }
