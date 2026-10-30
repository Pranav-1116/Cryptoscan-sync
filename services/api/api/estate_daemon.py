"""The 24/7 estate loop — a daemon, not a cron entry (spec 93 §18).

Everything else in the estate engine was request-driven: a schedule row said
*when* a run should happen, and someone had to call ``cryptoscan tick`` for it to
happen at all. A product that runs continuously cannot depend on an external
cron, a developer's shell, or a human noticing that last night's run never
happened. This module is the thing that keeps running.

What it guarantees, and what it deliberately does not:

* **at most one run per schedule.** The claim is the conditional UPDATE in
  :func:`api.estate_schedule.claim_due`, so N daemons (or a daemon plus a manual
  ``tick``) never double-run a schedule. Replicas are safe by construction — no
  extra leader election is invented here.
* **no pile-up after downtime.** The next occurrence is computed from *now*, so
  18 hours offline produce one catch-up run, not eighteen.
* **the loop survives its own failures.** A raising cycle is recorded in the
  heartbeat and the loop backs off, then continues. An error counter that stops
  the daemon is how a monitoring product silently dies.
* **a liveness record you can query.** Every cycle writes ``estate_daemons``
  (started_at, last_cycle_at, cycles, last_error, next_wake_at) — the API's
  ``/estate/evidence/realtime`` reads it and distinguishes LIVE from STALE from
  NEVER_STARTED. A heartbeat that only exists in a log line is not evidence.
* **bounded, jittered wake-ups.** The next wake is the earliest due schedule,
  clamped between the poll floor and ceiling, with a small jitter so replicas do
  not thunder together.
* **graceful shutdown.** SIGTERM/SIGINT finish the run in flight, write a final
  heartbeat marked ``STOPPED``, and exit — no half-written run rows.

It does not invent work: if no schedule exists, the loop idles and says so
(``idle_reason`` in the heartbeat) instead of reporting healthy coverage.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

logger = logging.getLogger(__name__)

MODEL = "cryptoscan.estate-daemon/1"
DEFAULT_WORKER = "cryptoscan-daemon"
#: never sleep longer than this, so a schedule created while we sleep is noticed
MAX_SLEEP_SECONDS = 60.0
#: never spin faster than this, even with a due schedule every minute
MIN_SLEEP_SECONDS = 1.0
#: after this many consecutive failed cycles, back off instead of hammering
BACKOFF_AFTER = 3
BACKOFF_SECONDS = 30.0
STALE_AFTER_SECONDS = 180.0


def _utc(moment: datetime | None = None) -> datetime:
    moment = moment or datetime.now(timezone.utc)
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _iso(moment: datetime | None) -> str | None:
    return _utc(moment).isoformat() if moment else None


class EstateDaemon:
    """One long-running estate scheduler loop.

    ``db_factory`` returns a fresh session per cycle: a long-lived session that
    hits one error is a session stuck in a failed transaction, and the next cycle
    would inherit it. ``sleep``/``clock``/``now`` are injectable so the loop can
    be tested without waiting in real time.
    """

    def __init__(
        self,
        db_factory: Callable[[], Any],
        *,
        worker: str = DEFAULT_WORKER,
        poll_seconds: float = 30.0,
        lease_seconds: int = 900,
        limit: int = 20,
        runner: Callable[..., Mapping[str, Any]] | None = None,
        publisher: Callable[[str, dict[str, Any]], Any] | None = None,
        sleep: Callable[[float], Any] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] | None = None,
        jitter: Callable[[], float] | None = None,
        version: str = "1.0",
    ) -> None:
        self.db_factory = db_factory
        self.worker = worker
        self.poll_seconds = max(MIN_SLEEP_SECONDS, float(poll_seconds))
        self.lease_seconds = int(lease_seconds)
        self.limit = int(limit)
        self._runner = runner
        self._publisher = publisher
        self._sleep = sleep
        self._clock = clock
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._jitter = jitter or (lambda: random.uniform(0.0, 2.0))
        self.version = version
        self._stop = threading.Event()
        self.started_at = _utc(self._now())
        self.cycles = 0
        self.runs = 0
        self.failures = 0
        self.consecutive_failures = 0
        self.last_error: str | None = None
        self.last_cycle_at: datetime | None = None
        self.last_cycle_seconds: float | None = None
        self.next_wake_at: datetime | None = None
        self.idle_reason: str | None = "no cycle has run yet"

    # ------------------------------------------------------------------ state
    def stop(self, *_args: Any) -> None:
        """Signal a graceful stop; the cycle in flight finishes first."""
        self._stop.set()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def heartbeat(self, *, state: str = "RUNNING") -> dict[str, Any]:
        """The durable liveness record, in the shape the table stores."""
        return {
            "worker": self.worker,
            "state": state,
            "version": self.version,
            "started_at": _iso(self.started_at),
            "last_cycle_at": _iso(self.last_cycle_at),
            "last_cycle_seconds": self.last_cycle_seconds,
            "cycles": self.cycles,
            "runs": self.runs,
            "failures": self.failures,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
            "next_wake_at": _iso(self.next_wake_at),
            "idle_reason": self.idle_reason,
            "pid": _pid(),
        }

    def _persist_heartbeat(self, db: Any, *, state: str = "RUNNING") -> None:
        try:
            from api.estate_daemon_store import record_heartbeat

            record_heartbeat(db, self.heartbeat(state=state))
            db.commit()
        except Exception as exc:  # noqa: BLE001 — a broken heartbeat must not stop the loop
            logger.warning("estate_daemon_heartbeat_failed", extra={"error": str(exc)})
            try:
                db.rollback()
            except Exception:  # noqa: BLE001 — recorded, never silent
                logger.debug("estate_daemon_rollback_failed", exc_info=True)

    # ----------------------------------------------------------------- cycles
    def next_due(self, db: Any) -> tuple[datetime | None, str]:
        """The earliest enabled schedule, or a reason there is none to wait for."""
        from api import estate_schedule

        rows = estate_schedule.list_schedules(db, include_disabled=False)
        if not rows:
            return None, "no enabled schedule: nothing is due, and nothing is being covered"
        when = min(_utc(row.next_run_at) for row in rows)
        return when, f"next due at {_iso(when)} ({len(rows)} enabled schedule(s))"

    def run_cycle(self) -> dict[str, Any]:
        """One cycle: claim what is due, run it, record it, decide when to wake."""
        started = self._clock()
        moment = _utc(self._now())
        # why nothing ran is re-derived every cycle: a stale reason is worse than
        # no reason, because it looks like an explanation
        self.idle_reason = "no reason recorded for this cycle"
        session = None
        result: dict[str, Any] = {"worker": self.worker, "at": moment.isoformat(), "claimed": 0, "ran": []}
        try:
            session = self.db_factory()
            from api import estate_schedule
            from api.estate_events import sink

            events = sink(self._publisher)
            outcome = estate_schedule.tick(
                session,
                worker=self.worker,
                now=moment,
                lease_seconds=self.lease_seconds,
                limit=self.limit,
                runner=self._runner,
                on_event=events,
            )
            result.update({
                "claimed": outcome.get("claimed", 0),
                "ran": outcome.get("ran") or [],
                "events": events.summary(),
            })
            ran = list(outcome.get("ran") or [])
            self.runs += int(outcome.get("claimed") or 0)
            failed_runs = [item for item in ran if item.get("status") != "OK"]
            if failed_runs:
                # the cycle did its job (it recorded the failure); the *run* failed,
                # and that is what the heartbeat must show
                self.failures += len(failed_runs)
                self.consecutive_failures += len(failed_runs)
                self.last_error = str(failed_runs[0].get("error") or "run failed")
                self.idle_reason = None
            else:
                self.consecutive_failures = 0
                self.idle_reason = None if ran else "nothing due this cycle"
            result["failed_runs"] = len(failed_runs)
            if outcome.get("ran") and events.publish_failures:
                result["warning"] = (
                    f"{events.publish_failures} realtime event(s) could not be published; the runs themselves "
                    "are stored"
                )
        except Exception as exc:  # noqa: BLE001 — the loop must outlive a bad cycle
            self.failures += 1
            self.consecutive_failures += 1
            self.last_error = f"{type(exc).__name__}: {exc}"
            result["error"] = self.last_error
            logger.exception("estate_daemon_cycle_failed")
            if session is not None:
                try:
                    session.rollback()
                except Exception:  # noqa: BLE001 — recorded, never silent
                    logger.debug("estate_daemon_rollback_failed", exc_info=True)
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:  # noqa: BLE001 — recorded, never silent
                    logger.debug("estate_daemon_close_failed", exc_info=True)

        self.cycles += 1
        self.last_cycle_at = _utc(self._now())
        self.last_cycle_seconds = round(max(0.0, self._clock() - started), 3)

        # where to wake next: the earliest due schedule, clamped and jittered
        delay = self.poll_seconds
        session = None
        try:
            session = self.db_factory()
            due_at, reason = self.next_due(session)
            if not result.get("ran"):
                # why nothing ran is the schedule view's answer when there is one
                self.idle_reason = reason
            if due_at is not None:
                until = (due_at - self.last_cycle_at).total_seconds()
                delay = min(MAX_SLEEP_SECONDS, max(MIN_SLEEP_SECONDS, until))
        except Exception as exc:  # noqa: BLE001 — an unreadable schedule list must not stop us
            self.idle_reason = (
                f"the schedule table could not be read ({type(exc).__name__}: {exc}): nothing is being run"
            )
            result.setdefault("warnings", []).append(f"next wake undetermined: {exc}")
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:  # noqa: BLE001 — recorded, never silent
                    logger.debug("estate_daemon_close_failed", exc_info=True)

        if self.consecutive_failures >= BACKOFF_AFTER:
            delay = max(delay, BACKOFF_SECONDS)
            result["backoff_seconds"] = delay
        delay = min(MAX_SLEEP_SECONDS, max(MIN_SLEEP_SECONDS, delay)) + max(0.0, self._jitter())
        self.next_wake_at = self.last_cycle_at + timedelta(seconds=delay)
        result["sleep_seconds"] = round(delay, 3)
        result["next_wake_at"] = _iso(self.next_wake_at)
        self._write_heartbeat()
        return result

    def _write_heartbeat(self, *, state: str = "RUNNING") -> None:
        session = None
        try:
            session = self.db_factory()
            self._persist_heartbeat(session, state=state)
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:  # noqa: BLE001 — recorded, never silent
                    logger.debug("estate_daemon_close_failed", exc_info=True)

    def run_forever(self, *, max_cycles: int | None = None) -> dict[str, Any]:
        """Run cycles until stopped (or ``max_cycles``, which tests and ``--once`` use)."""
        self._write_heartbeat()
        while not self.stopping:
            cycle = self.run_cycle()
            logger.info(
                "estate_daemon_cycle",
                extra={"claimed": cycle.get("claimed"), "cycles": self.cycles,
                       "sleep_seconds": cycle.get("sleep_seconds")},
            )
            if max_cycles is not None and self.cycles >= max_cycles:
                break
            if self.stopping:
                break
            self._sleep(float(cycle.get("sleep_seconds") or self.poll_seconds))
        self._write_heartbeat(state="STOPPED")
        return {
            "model": MODEL,
            "worker": self.worker,
            "state": "STOPPED",
            "cycles": self.cycles,
            "runs": self.runs,
            "failures": self.failures,
            "last_error": self.last_error,
            "started_at": _iso(self.started_at),
            "stopped_at": _iso(self._now()),
        }


def _pid() -> int | None:
    try:
        import os

        return os.getpid()
    except Exception:  # noqa: BLE001 — an unavailable pid is recorded, then said
        logger.warning("estate_daemon_pid_unavailable", exc_info=True)
        return None


def stale_state(heartbeat: Mapping[str, Any] | None, *, now: datetime | None = None,
                stale_after: float = STALE_AFTER_SECONDS) -> dict[str, Any]:
    """LIVE / STALE / NEVER_STARTED, from the recorded heartbeat alone.

    A daemon that stopped writing is not "running with no changes" — it is a
    coverage gap, and the verdict says so.
    """
    moment = _utc(now)
    if not heartbeat:
        return {
            "state": "NEVER_STARTED",
            "age_seconds": None,
            "meaning": "no estate daemon has ever written a heartbeat: nothing is running the schedules",
            "next_action": "start one — `cryptoscan serve` (or set ESTATE_REALTIME=1 on the API)",
        }
    last = heartbeat.get("last_cycle_at")
    if not last:
        return {
            "state": "STALE",
            "age_seconds": None,
            "meaning": "a daemon registered but has never completed a cycle",
            "next_action": "check the daemon log; it started and then failed before its first cycle",
        }
    try:
        moment_last = _utc(datetime.fromisoformat(str(last)))
    except ValueError:
        return {"state": "STALE", "age_seconds": None,
                "meaning": "the heartbeat timestamp is unreadable",
                "next_action": "inspect the estate_daemons row"}
    age = (moment - moment_last).total_seconds()
    if heartbeat.get("state") == "STOPPED":
        return {
            "state": "STOPPED",
            "age_seconds": round(age, 3),
            "meaning": "the last daemon exited cleanly; schedules are no longer being run",
            "next_action": "start it again — `cryptoscan serve`",
        }
    if age > stale_after:
        return {
            "state": "STALE",
            "age_seconds": round(age, 3),
            "meaning": (
                f"the last cycle finished {round(age)}s ago, past the {int(stale_after)}s threshold: schedules "
                "are not being run"
            ),
            "next_action": "check the daemon process and its log; runs are not happening while this is stale",
        }
    return {
        "state": "LIVE",
        "age_seconds": round(age, 3),
        "meaning": "the daemon completed a cycle within the staleness threshold",
        "next_action": None,
    }
