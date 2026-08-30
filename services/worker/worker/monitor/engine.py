"""Continuous monitoring engine: due targets -> live scanners -> state + events.

One tick: pick every enabled target whose ``next_scan_at`` has passed, run it
through the same live scanners the manual flows use, store the rolling summary,
and record an event for every outcome. Design rules for 24/7 operation:

- the tick never raises — a failing target is data, not a crash;
- failures back off exponentially (interval × 2^failures, capped at 24 h) so a
  dead endpoint cannot hammer the network every tick;
- anything unscannable (cloud without credentials, unknown type) is reported
  as BLOCKED with the exact reason — never silently skipped;
- an ALERT fires only when a scan shows a *new* issue the previous summary did
  not have, so a steady-state weak endpoint alerts once, not every cycle.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from db.models.monitor import TARGET_TYPES, MonitorTarget
from db.repositories.monitor_repository import MonitorRepository

logger = logging.getLogger(__name__)

DEFAULT_INTERVALS: dict[str, int] = {
    "NETWORK": 900,    # 15 min — endpoint posture changes fast
    "CLOUD": 21_600,   # 6 h — account-level crypto config
    "REPO": 86_400,    # daily — source-driven
    "CONTAINER": 86_400,
    "PAYMENT": 3_600,     # hourly — HSM audit trails move fast
}
MAX_BACKOFF_SECONDS = 86_400

# A runner takes (config, session) and returns:
#   {"summary": {...}, "degraded": bool, "issues": [...]}   on success
#   {"blocked_reason": "..."}                                when it cannot run
# It raises only on genuine failure (unreachable, scanner error).
Runner = Callable[[dict, Any], dict]


def default_interval(target_type: str) -> int:
    return DEFAULT_INTERVALS.get(target_type, 86_400)


class MonitorEngine:
    def __init__(self, session: Any, *, runners: dict[str, Runner] | None = None, clock=None,
                 on_alert: Callable[[str, str, dict], None] | None = None):
        self.session = session
        self.repo = MonitorRepository(session)
        self.runners = runners if runners is not None else _default_runners()
        self._now = clock or (lambda: datetime.now(timezone.utc))
        self._on_alert = on_alert

    # ---------------------------------------------------------------- tick

    def tick(self) -> dict[str, Any]:
        """Run every due target once. Returns an honest per-target outcome list."""
        results = []
        for target in self.repo.due(now=self._now()):
            results.append(self.run_target(target))
        return {"ran": len(results), "results": results}

    def run_target(self, target: MonitorTarget) -> dict[str, Any]:
        now = self._now()
        interval = int(target.interval_seconds or default_interval(target.target_type))
        runner = self.runners.get(target.target_type)
        if runner is None:
            self._finish(
                target, now=now, interval=interval, status="BLOCKED",
                error=f"no runner for target type '{target.target_type}' (expected one of {TARGET_TYPES})",
                event_type="BLOCKED",
            )
            return self._outcome(target, "BLOCKED")

        try:
            result = runner(dict(target.config or {}), self.session)
        except Exception as exc:  # 24/7 rule: the target fails, the loop does not
            logger.warning("monitor_target_failed", extra={"target": target.name})
            failures = int(target.consecutive_failures or 0) + 1
            backoff = min(interval * (2 ** failures), MAX_BACKOFF_SECONDS)
            target.consecutive_failures = failures
            target.status = "FAILING" if failures >= 2 else "DEGRADED"
            target.last_error = f"{type(exc).__name__}: {exc}"[:500]
            target.next_scan_at = now + timedelta(seconds=backoff)
            self.repo.add_event(
                target=target, event_type="SCAN_FAILED",
                detail=target.last_error,
                payload={"consecutive_failures": failures, "retry_in_seconds": backoff},
            )
            return self._outcome(target, target.status)

        if result.get("blocked_reason"):
            self._finish(
                target, now=now, interval=interval, status="BLOCKED",
                error=str(result["blocked_reason"])[:500], event_type="BLOCKED",
            )
            return self._outcome(target, "BLOCKED")

        summary = dict(result.get("summary") or {})
        issues = sorted(set(result.get("issues") or summary.get("issues") or []))
        summary["issues"] = issues
        new_issues = self._new_issues(target, issues)
        target.consecutive_failures = 0
        target.last_error = None
        target.last_scan_at = now
        target.next_scan_at = now + timedelta(seconds=interval)
        target.last_summary = summary
        degraded = bool(result.get("degraded")) or bool(issues)
        target.status = "DEGRADED" if degraded else "OK"
        self.repo.add_event(
            target=target,
            event_type="SCAN_DEGRADED" if degraded else "SCAN_OK",
            detail=f"{len(issues)} issue(s)" if issues else "clean",
            payload=summary,
        )
        for issue in new_issues:
            self.repo.add_event(
                target=target, event_type="ALERT",
                detail=f"NEW: {issue}", payload={"issue": issue},
            )
            if self._on_alert is not None:
                try:
                    self._on_alert(target.name, issue, {"target_id": target.id, "issue": issue})
                except Exception:  # noqa: BLE001 — sink failures never kill the tick
                    logger.exception("alert_dispatch_failed")
        return self._outcome(target, target.status, new_issues=new_issues)

    # ------------------------------------------------------------- helpers

    def _new_issues(self, target: MonitorTarget, issues: list[str]) -> list[str]:
        previous = set((target.last_summary or {}).get("issues") or [])
        return [issue for issue in issues if issue not in previous]

    def _finish(self, target, *, now, interval, status, error, event_type) -> None:
        target.status = status
        target.last_error = error
        target.last_scan_at = now
        target.next_scan_at = now + timedelta(seconds=interval)
        self.repo.add_event(target=target, event_type=event_type, detail=error)

    @staticmethod
    def _outcome(target: MonitorTarget, status: str, *, new_issues: list[str] | None = None) -> dict:
        return {
            "target": target.name,
            "target_id": target.id,
            "status": status,
            "new_issues": new_issues or [],
            "next_scan_at": target.next_scan_at.isoformat() if target.next_scan_at else None,
        }


def _default_runners() -> dict[str, Runner]:
    from worker.monitor.runners import (
        cloud_runner,
        container_runner,
        network_runner,
        payment_runner,
        repo_runner,
    )

    return {
        "NETWORK": network_runner,
        "CLOUD": cloud_runner,
        "REPO": repo_runner,
        "CONTAINER": container_runner,
        "PAYMENT": payment_runner,
    }
