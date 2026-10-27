"""Drift SLA escalation sweep (audit 31 §5.2, round 24).

The SLA metrics (`GET /drift/sla`, round 23) measure; this sweep acts.
On every monitor tick it evaluates open drift events against the report's
§5.2 windows and escalates the ones that *just* crossed a window —
alerting through the monitor's channels (CEF / signed webhook / email)
exactly once per breach rather than nagging every cycle.

Stateless by design: "just crossed" is (window, window + recent_window]
where ``recent_window`` defaults to 24h. A breach alerts on the first tick
after it happened and stays silent afterwards — the persistent signal is
the open drift event itself plus `GET /drift/sla`, not repeated pages. If
the monitor is down for more than ``recent_window``, a crossing can be
missed; that tradeoff (no state table) is deliberate and documented.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def run_sla_sweep(
    session: Any,
    *,
    now: datetime | None = None,
    on_alert: Callable[[str, str, dict], None] | None = None,
    recent_hours: float = 24.0,
    max_events: int = 5_000,
) -> dict[str, Any]:
    """Escalate drift events that crossed an SLA window since the last tick.

    One aggregated alert per severity (ack-window and resolve-window
    crossings reported together), plus a ``drift.sla_breach`` platform
    event per severity with the crossing details. Returns the crossing
    counts and the full SLA summary for the tick outcome.
    """
    from sqlalchemy import select

    from db.models.drift_event import DriftEvent
    from db.repositories.drift_repository import DriftRepository

    now = _aware(now) or datetime.now(timezone.utc)
    recent = recent_hours

    rows = (
        session.execute(
            select(DriftEvent)
            .where(DriftEvent.resolution_status.in_(["OPEN", "ACKNOWLEDGED"]))
            .order_by(DriftEvent.detected_at.desc())
            .limit(max_events)
        )
        .scalars()
        .all()
    )
    truncated = len(rows) == max_events

    crossings: dict[str, dict[str, list[dict]]] = {}
    for row in rows:
        detected = _aware(row.detected_at)
        if detected is None:
            continue
        severity = str(row.severity or "INFO").upper()
        targets = DriftRepository.SLA_TARGETS.get(severity) or {}
        age_h = (now - detected).total_seconds() / 3600.0
        ack_window = targets.get("acknowledge_hours")
        resolve_window = targets.get("resolve_hours")
        entry = {
            "drift_id": str(row.id),
            "drift_type": row.drift_type,
            "detected_at": detected.isoformat(),
            "age_hours": round(age_h, 2),
            "status": row.resolution_status,
        }
        bucket = crossings.setdefault(severity, {"acknowledge": [], "resolve": []})
        if (
            ack_window is not None
            and row.acknowledged_at is None
            and ack_window < age_h <= ack_window + recent
        ):
            bucket["acknowledge"].append(entry)
        if resolve_window is not None and resolve_window < age_h <= resolve_window + recent:
            bucket["resolve"].append(entry)

    for severity, bucket in sorted(crossings.items()):
        ack_crossed = bucket["acknowledge"]
        res_crossed = bucket["resolve"]
        if not ack_crossed and not res_crossed:
            continue
        def _fmt(hours: float) -> str:
            return f"{hours:g}h"

        parts = []
        if ack_crossed:
            parts.append(
                f"{len(ack_crossed)} event(s) unacknowledged past the "
                f"{_fmt(DriftRepository.SLA_TARGETS[severity]['acknowledge_hours'])} window"
            )
        if res_crossed:
            parts.append(
                f"{len(res_crossed)} event(s) unresolved past the "
                f"{_fmt(DriftRepository.SLA_TARGETS[severity]['resolve_hours'])} window"
            )
        issue = f"drift SLA breach ({severity}): " + "; ".join(parts)
        payload = {"severity": severity, "acknowledge_crossings": ack_crossed,
                   "resolve_crossings": res_crossed}
        if on_alert is not None:
            try:
                on_alert("drift-sla", issue, payload)
            except Exception:  # noqa: BLE001 — alerting must not kill the sweep
                logger.warning("sla_alert_failed", exc_info=True)
        try:
            from api.events.platform_events import emit_platform_event

            emit_platform_event(
                "drift.sla_breach",
                issue,
                {"source": "monitor-sweep", **payload},
                target_name="drift",
            )
        except Exception:
            logger.debug("sla_event_skipped", exc_info=True)
        logger.warning("drift_sla_breach", extra={"severity": severity,
                                                  "ack": len(ack_crossed),
                                                  "resolve": len(res_crossed)})

    summary = DriftRepository(session).sla_summary(now=now)
    return {
        "open_events_considered": len(rows),
        "truncated": truncated,
        "escalated_severities": sorted(
            sev for sev, bucket in crossings.items()
            if bucket["acknowledge"] or bucket["resolve"]
        ),
        "summary": summary,
    }
