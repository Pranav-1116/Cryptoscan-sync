"""Continuous monitoring modes.

Do not run expensive deep scans continuously against every asset.  The live
monitor separates work into five distinct modes:

MODE 1 — REAL-TIME EVENT MONITORING   (event listeners, no scanning)
MODE 2 — PASSIVE NETWORK MONITORING   (SPAN/TAP/flow/logs, no probing)
MODE 3 — PERIODIC LIGHTWEIGHT SCANNING (priority-tier intervals)
MODE 4 — SCHEDULED DEEP SCANNING      (weekly / policy-driven)
MODE 5 — CHANGE-TRIGGERED RESCANNING  (targeted, never a full restart)

Intervals are configuration-driven (``MonitoringPolicy``), never hard-coded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MONITORING_MODES = (
    "REALTIME_EVENT",
    "PASSIVE",
    "PERIODIC_LIGHTWEIGHT",
    "SCHEDULED_DEEP",
    "CHANGE_TRIGGERED",
)

# Priority tiers used by the scheduling engine.  Interval defaults here are
# only defaults — a MonitoringPolicy can override every value.
TIER_DEFAULT_INTERVALS: dict[str, int] = {
    "CRITICAL": 60,       # every minute + event-driven
    "HIGH": 300,          # every few minutes
    "STANDARD": 3600,     # hourly
    "LOW": 86400,         # daily
}

DEEP_SCAN_DEFAULT_INTERVAL = 7 * 86400  # weekly


@dataclass(frozen=True)
class MonitoringMode:
    """One of the five monitoring modes plus its policy knobs."""

    name: str
    description: str
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.name, "description": self.description,
                "enabled": self.enabled}


MODES: dict[str, MonitoringMode] = {
    "REALTIME_EVENT": MonitoringMode(
        "REALTIME_EVENT",
        "Event listeners react to device/cert/TLS/topology changes instantly"),
    "PASSIVE": MonitoringMode(
        "PASSIVE",
        "Passive sensors (SPAN/TAP/flow/firewall/VPN/DNS/LB logs, TLS handshake "
        "metadata, SIEM) feed crypto observations without active probing"),
    "PERIODIC_LIGHTWEIGHT": MonitoringMode(
        "PERIODIC_LIGHTWEIGHT",
        "Priority-based lightweight scans at configurable intervals"),
    "SCHEDULED_DEEP": MonitoringMode(
        "SCHEDULED_DEEP",
        "Full deep crypto scans on a weekly / policy-driven schedule"),
    "CHANGE_TRIGGERED": MonitoringMode(
        "CHANGE_TRIGGERED",
        "Targeted rescans only for the assets affected by a change"),
}


@dataclass
class MonitoringPolicy:
    """Configurable intervals for the scheduling engine (never hard-coded)."""

    intervals: dict[str, int] = field(
        default_factory=lambda: dict(TIER_DEFAULT_INTERVALS))
    deep_interval: int = DEEP_SCAN_DEFAULT_INTERVAL
    lightweight_scan_window: int = 300  # seconds after an event to collapse rescans

    def interval_for(self, tier: str) -> int:
        return self.intervals.get(tier, TIER_DEFAULT_INTERVALS["STANDARD"])

    def set_interval(self, tier: str, seconds: int) -> None:
        if tier not in TIER_DEFAULT_INTERVALS:
            raise ValueError(f"unknown tier '{tier}' (choose from {sorted(TIER_DEFAULT_INTERVALS)})")
        if seconds < 1:
            raise ValueError("interval must be >= 1 second")
        self.intervals[tier] = seconds

    def deep_due(self, last_deep_scan: Any, now: Any) -> bool:
        if last_deep_scan is None:
            return True
        try:
            elapsed = (now - last_deep_scan).total_seconds()
        except Exception:  # non-datetime inputs are treated as "due"
            return True
        return elapsed >= self.deep_interval

    def to_dict(self) -> dict[str, Any]:
        return {"intervals": dict(self.intervals),
                "deep_interval": self.deep_interval,
                "lightweight_scan_window": self.lightweight_scan_window}


def enabled_modes(overrides: dict[str, bool] | None = None) -> list[str]:
    """Names of enabled modes after applying ``{mode: enabled}`` overrides."""
    overrides = overrides or {}
    return [mode.name for mode in MODES.values()
            if overrides.get(mode.name, mode.enabled)]
