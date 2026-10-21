"""Realtime report sweep: execute due compliance report schedules.

Scheduled reports (``report_schedules``) were previously only *computed* —
nothing ran them. The 24/7 daemon now executes every due schedule on each
tick, exactly like the monitor targets: due → render + snapshot + email →
``next_run_at`` advanced → a ``REPORT_GENERATED`` monitor event federated to
the SSE stream (``monitor.report_generated``).

Rules (same 24/7 discipline as the engine):

- a schedule with no completed scan yet is ``SKIPPED_NO_SCAN``, reported
  honestly, and left due (it will run as soon as a scan exists);
- failures never raise out of the sweep — one bad schedule cannot kill the
  daemon loop;
- the report snapshot table is the system of record; email is best-effort.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def run_due_report_schedules(session: Any, *, on_event=None) -> list[dict[str, Any]]:
    """Run every due report schedule once. Returns per-schedule outcomes.

    ``on_event`` is an optional callback ``(event_type, detail, payload)`` —
    the daemon wires it to monitor events so reports appear on the SSE feed.
    """
    from db.repositories.execution_control import required, ExecutionDenied
    if required():
        raise ExecutionDenied("Report processing has no controlled execution adapter")
    try:
        from db.repositories.report_schedule_repository import ReportScheduleRepository

        repo = ReportScheduleRepository(session)
        due = repo.due(now=datetime.now(timezone.utc))
    except Exception:  # noqa: BLE001 — table missing / repo broken: skip, never crash
        logger.exception("report_sweep_due_failed")
        return []

    outcomes: list[dict[str, Any]] = []
    for schedule in due:
        try:
            from api.routers.report_schedules import _run_schedule

            outcome = _run_schedule(schedule, session)
        except Exception as exc:  # noqa: BLE001 — one bad schedule never kills the loop
            logger.warning("report_schedule_failed", extra={"schedule": schedule.name})
            outcome = {"schedule": schedule.name, "status": "FAILED", "detail": f"{type(exc).__name__}: {exc}"[:500]}
        outcomes.append(outcome)
        status = str(outcome.get("status") or "FAILED")
        if on_event is not None:
            try:
                on_event(
                    "REPORT_GENERATED" if status == "GENERATED" else "REPORT_SKIPPED",
                    f"{schedule.name}: {status}",
                    {"schedule": schedule.name, "status": status, "detail": outcome.get("detail")},
                )
            except Exception:  # noqa: BLE001
                logger.exception("report_event_dispatch_failed")
        try:
            session.commit()
        except Exception:  # noqa: BLE001
            session.rollback()
            logger.exception("report_sweep_commit_failed")
    return outcomes
