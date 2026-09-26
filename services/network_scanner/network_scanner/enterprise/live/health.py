"""Scanner Health Monitoring.

The scanner itself must be monitored:

    Heartbeat · CPU · Memory · Queue Depth · Scan Latency · API Errors ·
    Plugin Failures · Last Successful Scan

States: HEALTHY · DEGRADED · UNREACHABLE · FAILED · MAINTENANCE
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

HEALTH_STATES = ("HEALTHY", "DEGRADED", "UNREACHABLE", "FAILED", "MAINTENANCE")

DEFAULT_THRESHOLDS: dict[str, float] = {
    "cpu_percent": 85.0,
    "memory_percent": 85.0,
    "queue_depth": 10_000,
    "scan_latency_ms": 30_000,
    "api_errors": 10,
    "plugin_failures": 5,
    "heartbeat_stale_seconds": 120,
    "heartbeat_unreachable_seconds": 600,
}


@dataclass
class HealthSample:
    cpu: float = 0.0
    memory: float = 0.0
    queue_depth: int = 0
    scan_latency_ms: float = 0.0
    api_errors: int = 0
    plugin_failures: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"cpu": self.cpu, "memory": self.memory,
                "queue_depth": self.queue_depth,
                "scan_latency_ms": self.scan_latency_ms,
                "api_errors": self.api_errors,
                "plugin_failures": self.plugin_failures}


class ScannerHealthMonitor:
    """Tracks scanner liveness/load and derives a health state."""

    def __init__(self, *, thresholds: dict[str, float] | None = None,
                 clock: Callable[[], Any] | None = None,
                 agent_id: str = "scanner-1") -> None:
        merged = dict(DEFAULT_THRESHOLDS)
        if thresholds:
            merged.update(thresholds)
        self._thresholds = merged
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._agent_id = agent_id
        self._last_heartbeat: Any = None
        self._last_successful_scan: Any = None
        self._maintenance = False
        self._sample = HealthSample()
        self._history: list[dict[str, Any]] = []

    # ------------------------------------------------------------- inputs

    def heartbeat(self, *, now: Any | None = None) -> None:
        self._last_heartbeat = now if now is not None else self._clock()

    def mark_scan_success(self, *, now: Any | None = None) -> None:
        self._last_successful_scan = now if now is not None else self._clock()
        self.heartbeat(now=self._last_successful_scan)

    def tick(self, *, cpu: float = 0.0, memory: float = 0.0,
             queue_depth: int = 0, scan_latency_ms: float = 0.0,
             api_errors: int = 0, plugin_failures: int = 0,
             heartbeat: bool = True, now: Any | None = None) -> None:
        if heartbeat:
            self.heartbeat(now=now)
        self._sample = HealthSample(cpu=cpu, memory=memory,
                                    queue_depth=queue_depth,
                                    scan_latency_ms=scan_latency_ms,
                                    api_errors=api_errors,
                                    plugin_failures=plugin_failures)
        self._history.append(self._sample.to_dict())
        if len(self._history) > 500:
            self._history = self._history[-500:]

    def mark_maintenance(self, on: bool = True) -> None:
        self._maintenance = on
        if on:
            self._last_heartbeat = None

    # ------------------------------------------------------------- state

    def state(self, *, now: Any | None = None) -> str:
        now = now if now is not None else self._clock()
        if self._maintenance:
            return "MAINTENANCE"
        if self._last_heartbeat is None:
            return "UNREACHABLE"
        stale = self._seconds_since(self._last_heartbeat, now)
        if stale >= self._thresholds["heartbeat_unreachable_seconds"]:
            return "UNREACHABLE"
        if stale >= self._thresholds["heartbeat_stale_seconds"]:
            return "FAILED"
        sample = self._sample
        if (sample.cpu > self._thresholds["cpu_percent"]
                or sample.memory > self._thresholds["memory_percent"]
                or sample.queue_depth > self._thresholds["queue_depth"]
                or sample.scan_latency_ms > self._thresholds["scan_latency_ms"]
                or sample.api_errors > self._thresholds["api_errors"]
                or sample.plugin_failures > self._thresholds["plugin_failures"]):
            return "DEGRADED"
        return "HEALTHY"

    @staticmethod
    def _seconds_since(value: Any, now: Any) -> float:
        try:
            return (now - value).total_seconds()
        except Exception:
            return float("inf")

    def report(self, *, now: Any | None = None) -> dict[str, Any]:
        now = now if now is not None else self._clock()
        def iso(value: Any) -> Any:
            return value.isoformat() if hasattr(value, "isoformat") else value

        return {"agent_id": self._agent_id,
                "state": self.state(now=now),
                "last_heartbeat": iso(self._last_heartbeat),
                "last_successful_scan": iso(self._last_successful_scan),
                "maintenance": self._maintenance,
                "sample": self._sample.to_dict(),
                "history_len": len(self._history),
                "thresholds": dict(self._thresholds)}
