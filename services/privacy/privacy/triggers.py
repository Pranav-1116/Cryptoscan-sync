"""Scan triggers, scheduling and incremental scanning (spec #10, #11, #12).

Continuous/event-driven scanning is what lets the platform avoid re-scanning a
whole estate on every change. This module is the pure decision layer:

* :func:`resolve_schedule` maps a cadence keyword to a runnable schedule spec.
* :func:`event_for_change` maps an estate change to the affected scan type(s).
* :func:`is_incremental` decides when an incremental scan is safe (the previous
  baseline is fresh enough) and what *changed* is worth re-scanning.

No network, no timers -- the scheduler/worker owns execution. Here we decide
*what to do* deterministically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


#: supported cadence keywords -> (interval_seconds | None for on-change/on-demand)
SCHEDULES: dict[str, dict[str, Any]] = {
    "every_5_minutes": {"interval_s": 300, "kind": "interval"},
    "hourly": {"interval_s": 3600, "kind": "interval"},
    "daily": {"interval_s": 86400, "kind": "interval"},
    "weekly": {"interval_s": 604800, "kind": "interval"},
    "on_change": {"interval_s": None, "kind": "event"},
    "on_demand": {"interval_s": None, "kind": "manual"},
    "after_deployment": {"interval_s": None, "kind": "event"},
    "after_certificate_change": {"interval_s": None, "kind": "event"},
    "after_cloud_change": {"interval_s": None, "kind": "event"},
}


@dataclass
class Schedule:
    """A resolved schedule for one profile / asset class."""

    kind: str            # interval | event | manual
    interval_s: int | None
    events: list[str]    # which change events trigger a run

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "interval_s": self.interval_s,
                "events": list(self.events)}


def resolve_schedule(cadence: str) -> Schedule:
    """Resolve a cadence keyword into a :class:`Schedule`.

    ``on_change`` and the ``after_*`` cadences resolve to event-driven schedules
    with the matching event subscription; interval cadences get a fixed period.
    """
    key = (cadence or "on_demand").strip().lower()
    if key not in SCHEDULES:
        return Schedule(kind="manual", interval_s=None, events=[])
    spec = SCHEDULES[key]
    events: list[str] = []
    if spec["kind"] == "event":
        events = _events_for(key)
    return Schedule(kind=spec["kind"], interval_s=spec["interval_s"], events=events)


def _events_for(cadence: str) -> list[str]:
    """Map an event-driven cadence to the estate events it should subscribe to."""
    mapping = {
        "on_change": ["asset.created", "asset.changed", "certificate.changed",
                      "cloud.resource_changed", "firmware.changed",
                      "application.deployed"],
        "after_deployment": ["application.deployed"],
        "after_certificate_change": ["certificate.changed", "certificate.expiring"],
        "after_cloud_change": ["cloud.resource_changed", "cloud.config_changed"],
    }
    return mapping.get(cadence, [])


#: change events -> the scan types that should run in response (spec #11).
EVENT_TO_SCAN = {
    "asset.created": ("discovery",),
    "asset.changed": ("standard",),
    "certificate.changed": ("crypto", "certificate"),
    "certificate.expiring": ("crypto", "certificate"),
    "firmware.changed": ("hardware", "vendor"),
    "cloud.resource_changed": ("cloud",),
    "cloud.config_changed": ("cloud",),
    "application.deployed": ("crypto", "application"),
    "device.changed": ("hardware",),
}


def event_for_change(event: str) -> tuple[str, ...]:
    """Return the scan types to run for a given change event."""
    return EVENT_TO_SCAN.get(event, ("standard",))


@dataclass
class IncrementalDecision:
    """Whether an incremental scan is safe and what it should target."""

    incremental: bool
    reason: str
    baseline_age_s: int | None = None
    changed_assets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"incremental": self.incremental, "reason": self.reason,
                "baseline_age_s": self.baseline_age_s,
                "changed_assets": list(self.changed_assets)}


#: how old a baseline may be before a full recapture is required.
BASELINE_TTL_S = {"discovery": 7 * 86400, "standard": 3 * 86400, "deep": 14 * 86400}


def is_incremental(scan_type: str, *, baseline_at: float | None, now: float,
                   changed_assets: list[str] | None = None) -> IncrementalDecision:
    """Decide whether an incremental scan is safe for this scan type.

    A baseline is required (incremental compares new observations against it).
    If the baseline is older than the scan type's TTL, or there is no baseline,
    return ``incremental=False`` so the caller falls back to a full scan. If
    nothing is reported as changed, there is nothing to re-scan incrementally.
    """
    changed = [a for a in (changed_assets or []) if a]
    ttl = BASELINE_TTL_S.get(scan_type, 3 * 86400)
    if baseline_at is None:
        return IncrementalDecision(False, "no baseline snapshot; full scan required")
    age = max(0.0, now - baseline_at)
    if age > ttl:
        return IncrementalDecision(False, f"baseline too old ({round(age, 1)}s); full recapture required",
                                   baseline_age_s=round(age, 1))
    if not changed:
        return IncrementalDecision(True, "baseline fresh; no changed assets to re-scan",
                                   baseline_age_s=round(age, 1))
    return IncrementalDecision(True, "baseline fresh; incremental re-scan of changed assets",
                               baseline_age_s=round(age, 1), changed_assets=changed)
