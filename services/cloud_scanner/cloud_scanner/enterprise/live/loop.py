"""ZELNX Live Cloud Intelligence Engine — 24/7 monitoring loop.

Wraps :class:`LiveCloudEngine` in a continuous cycle: poll connectors,
process events, run reconciliation, snapshot health, and emit reports.
Designed for testability (``poll`` injectable, ``clock`` injectable, no
real sleeping unless driven with a real interval).
"""

from __future__ import annotations

import time
from typing import Any, Callable

from cloud_scanner.enterprise.live.engine import LiveCloudEngine, LiveReport


class LiveMonitoringLoop:
    """Continuous 24/7 monitoring loop over the live engine."""

    def __init__(self, engine: LiveCloudEngine, *,
                 interval_seconds: float = 60.0,
                 clock: Callable[[], str] | None = None,
                 sleeper: Callable[[float], None] | None = None,
                 on_report: Callable[[LiveReport], None] | None = None,
                 max_cycles: int | None = None) -> None:
        self.engine = engine
        self.interval_seconds = interval_seconds
        self._clock = clock or (lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                      time.gmtime()))
        self._sleeper = sleeper or time.sleep
        self._on_report = on_report
        self._max_cycles = max_cycles
        self._reports: list[LiveReport] = []
        self._running = False

    def run_forever(self) -> None:
        """Run cycles until stopped (or ``max_cycles`` reached)."""
        self._running = True
        cycles = 0
        while self._running:
            if self._max_cycles is not None and cycles >= self._max_cycles:
                break
            report = self.engine.cycle(cycle_number=cycles + 1)
            self._reports.append(report)
            if self._on_report is not None:
                self._on_report(report)
            cycles += 1
            if self._max_cycles is None or cycles < self._max_cycles:
                self._sleeper(self.interval_seconds)

    def stop(self) -> None:
        self._running = False

    def run_once(self) -> LiveReport:
        """Run exactly one cycle."""
        report = self.engine.cycle(cycle_number=len(self._reports) + 1)
        self._reports.append(report)
        return report

    def reports(self) -> list[LiveReport]:
        return list(self._reports)

    def latest(self) -> LiveReport | None:
        return self._reports[-1] if self._reports else None

    def summary(self) -> dict[str, Any]:
        return {
            "cycles_run": len(self._reports),
            "interval_seconds": self.interval_seconds,
            "running": self._running,
        }
