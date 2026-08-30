"""ZELNX Live Cloud Intelligence Engine — cloud scanner health monitoring
(§24).

Tracks per-collector health signals: heartbeat, event lag, API
rate-limit status, API errors, authentication status, queue depth, event
processing latency, last successful reconciliation, plugin health.

States: HEALTHY / DEGRADED / RATE_LIMITED / AUTH_FAILED / EVENT_DELAYED /
UNREACHABLE / FAILED / MAINTENANCE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
RATE_LIMITED = "RATE_LIMITED"
AUTH_FAILED = "AUTH_FAILED"
EVENT_DELAYED = "EVENT_DELAYED"
UNREACHABLE = "UNREACHABLE"
FAILED = "FAILED"
MAINTENANCE = "MAINTENANCE"

HEALTH_STATES = (HEALTHY, DEGRADED, RATE_LIMITED, AUTH_FAILED, EVENT_DELAYED,
                 UNREACHABLE, FAILED, MAINTENANCE)

# (name, weight, description)
SIGNALS = (
    ("heartbeat_ok", 3, "collector heartbeat"),
    ("event_lag", 2, "event processing lag"),
    ("rate_limited", 3, "API rate-limit status"),
    ("api_errors", 2, "API error rate"),
    ("auth_ok", 3, "authentication status"),
    ("queue_depth", 2, "event queue depth"),
    ("processing_latency", 2, "event processing latency"),
    ("last_reconciliation_ok", 2, "last successful reconciliation"),
    ("plugins_healthy", 1, "plugin health"),
)

# For signals stored as booleans: name -> callable(True means healthy?)
# (``event_lag`` / ``rate_limited`` / ``api_errors`` / ``processing_latency``
#  are stored inverted: True means the bad condition holds.)
def _signal_ok(name: str, value: bool) -> bool:
    if name in ("event_lag", "rate_limited", "api_errors", "processing_latency"):
        return not value
    return bool(value)


# signal name -> which states it flips to
_STATE_FROM_SIGNAL = {
    "heartbeat_ok": UNREACHABLE,
    "event_lag": EVENT_DELAYED,
    "rate_limited": RATE_LIMITED,
    "api_errors": DEGRADED,
    "auth_ok": AUTH_FAILED,
    "queue_depth": EVENT_DELAYED,
    "processing_latency": EVENT_DELAYED,
    "last_reconciliation_ok": DEGRADED,
    "plugins_healthy": FAILED,
}


@dataclass
class CollectorHealth:
    """Health snapshot of one collector."""

    collector_id: str
    state: str = HEALTHY
    score: float = 100.0
    signals: dict[str, Any] = field(default_factory=dict)
    state_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "collector_id": self.collector_id,
            "state": self.state,
            "score": self.score,
            "signals": dict(self.signals),
            "state_reason": self.state_reason,
        }


class CloudScannerHealthMonitor:
    """Aggregate health signals into a collector state."""

    def __init__(self) -> None:
        self._snapshots: dict[str, CollectorHealth] = {}
        self._history: list[dict[str, Any]] = []

    def snapshot(self, *, collector_id: str,
                 heartbeat_ok: bool = True,
                 event_lag_ok: bool = True,
                 rate_limited: bool = False,
                 api_errors: bool = False,
                 auth_ok: bool = True,
                 queue_depth: int = 0,
                 processing_latency_ok: bool = True,
                 last_reconciliation_ok: bool = True,
                 plugins_healthy: bool = True,
                 maintenance: bool = False) -> CollectorHealth:
        signals = {
            "heartbeat_ok": bool(heartbeat_ok),
            "event_lag": not event_lag_ok,
            "rate_limited": bool(rate_limited),
            "api_errors": bool(api_errors),
            "auth_ok": bool(auth_ok),
            "queue_depth": int(queue_depth),
            "processing_latency": not processing_latency_ok,
            "last_reconciliation_ok": bool(last_reconciliation_ok),
            "plugins_healthy": bool(plugins_healthy),
        }
        score = self._compute_score(signals)
        state, reason = self._state_from_signals(signals, maintenance)
        health = CollectorHealth(
            collector_id=collector_id,
            state=state,
            score=score,
            signals=signals,
            state_reason=reason,
        )
        self._snapshots[collector_id] = health
        self._history.append({
            "collector_id": collector_id,
            "state": state,
            "score": score,
            "recorded_at": "",
        })
        return health

    def get(self, collector_id: str) -> CollectorHealth | None:
        return self._snapshots.get(collector_id)

    def all(self) -> list[CollectorHealth]:
        return list(self._snapshots.values())

    def summary(self) -> dict[str, Any]:
        return {
            "collectors": len(self._snapshots),
            "by_state": {
                state: sum(1 for h in self._snapshots.values() if h.state == state)
                for state in HEALTH_STATES
            },
        }

    # ------------------------------------------------------------------ internals

    def _compute_score(self, signals: dict[str, Any]) -> float:
        score = 100.0
        penalty = 0.0
        max_penalty = sum(weight for _name, weight, _desc in SIGNALS)
        for (name, weight, _desc) in SIGNALS:
            value = signals.get(name, True)
            if name == "queue_depth":
                if value > 1000:
                    penalty += weight
                elif value > 100:
                    penalty += weight * 0.5
            elif isinstance(value, bool) and not _signal_ok(name, value):
                penalty += weight
        return max(0.0, round(score * (1 - min(1.0, penalty / max_penalty)), 1))

    def _state_from_signals(self, signals: dict[str, Any],
                            maintenance: bool) -> tuple[str, str]:
        if maintenance:
            return MAINTENANCE, "collector in planned maintenance"
        if not signals["heartbeat_ok"]:
            return UNREACHABLE, "no heartbeat from collector"
        if not signals["auth_ok"]:
            return AUTH_FAILED, "authentication failed"
        if signals["rate_limited"]:
            return RATE_LIMITED, "API rate limit exceeded"
        if signals["event_lag"] or signals["processing_latency"]:
            return EVENT_DELAYED, "event processing delayed"
        if not signals["plugins_healthy"]:
            return FAILED, "plugin failure"
        if signals["api_errors"] or not signals["last_reconciliation_ok"]:
            return DEGRADED, "API errors or reconciliation missed"
        if signals["queue_depth"] > 1000:
            return EVENT_DELAYED, "queue backlog"
        return HEALTHY, "all signals nominal"
