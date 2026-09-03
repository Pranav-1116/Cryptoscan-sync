"""Deterministic adaptive scan scheduling (no AI/ML).

Assets are not all scanned on the same fixed cadence. The schedule is derived
from pure, auditable inputs:

* asset risk/criticality  -> base interval (higher risk scans more often)
* recent change           -> immediate targeted scan (interval collapses to 0)
* stability               -> stable low-risk assets scan least often
* required minimum        -> every asset is still reassessed on a bounded cadence

Intervals are chosen from an explicit, fixed set (the product's supported
frequencies) so behaviour is predictable and identical across runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

#: supported fixed cadences in seconds.
FREQUENCY_SECONDS = {
    "5m": 300,
    "15m": 900,
    "hourly": 3600,
    "6h": 21600,
    "daily": 86400,
    "weekly": 604800,
}


class RiskTier(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


#: base cadence by risk tier (stable asset with no changes)
BASE_FREQUENCY = {
    RiskTier.CRITICAL: "hourly",
    RiskTier.HIGH: "6h",
    RiskTier.MEDIUM: "daily",
    RiskTier.LOW: "weekly",
    RiskTier.UNKNOWN: "daily",
}
#: if a change occurred within this window, scan at the fastest cadence
CHANGE_TRIGGER_WINDOW = timedelta(hours=24)


@dataclass
class ScanSchedule:
    asset_id: str
    risk_tier: str
    frequency: str
    interval_seconds: int
    reason: str
    immediate: bool
    next_due_at: datetime | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "risk_tier": self.risk_tier,
            "frequency": self.frequency,
            "interval_seconds": self.interval_seconds,
            "reason": self.reason,
            "immediate": self.immediate,
            "next_due_at": self.next_due_at.isoformat() if self.next_due_at else None,
        }


def _norm_tier(value: Any) -> RiskTier:
    s = str(value or "").strip().upper()
    # map common severity/criticality vocabulary onto tiers
    aliases = {
        "SAFETY": RiskTier.CRITICAL, "CROWN_JEWEL": RiskTier.CRITICAL,
        "TIER0": RiskTier.CRITICAL, "TIER1": RiskTier.HIGH,
        "SEV1": RiskTier.CRITICAL, "SEV2": RiskTier.HIGH, "SEV3": RiskTier.MEDIUM,
        "SEV4": RiskTier.LOW,
    }
    s = aliases.get(s, s)
    try:
        return RiskTier(s)
    except ValueError:
        return RiskTier.UNKNOWN


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def schedule_for_asset(asset: dict[str, Any], *, now: datetime | None = None) -> ScanSchedule:
    """Compute the deterministic scan cadence for an asset."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    asset_id = str(asset.get("id") or asset.get("asset_id") or "?")
    tier = _norm_tier(asset.get("risk_tier") or asset.get("criticality")
                      or asset.get("risk"))

    # Recent change -> immediate targeted scan, regardless of tier.
    changed_at = _parse_dt(asset.get("last_changed_at") or asset.get("changed_at")
                           or asset.get("detected_at"))
    last_scan = _parse_dt(asset.get("last_scanned_at"))
    if asset.get("changed") is True or (
        changed_at is not None and (now - changed_at) < CHANGE_TRIGGER_WINDOW
        and (last_scan is None or changed_at > last_scan)):
        return ScanSchedule(
            asset_id=asset_id, risk_tier=tier.value, frequency="5m",
            interval_seconds=FREQUENCY_SECONDS["5m"], immediate=True,
            reason="asset changed within 24h after last scan -> immediate targeted scan",
            next_due_at=now,
        )

    frequency = BASE_FREQUENCY[tier]
    interval = FREQUENCY_SECONDS[frequency]
    # last-scan timestamp drives the next due; if never scanned, due now.
    if last_scan is None:
        next_due = now
        reason = f"never scanned ({tier.value}) -> due immediately"
    else:
        next_due = last_scan + timedelta(seconds=interval)
        reason = f"{tier.value} risk tier -> {frequency} cadence"
    return ScanSchedule(
        asset_id=asset_id, risk_tier=tier.value, frequency=frequency,
        interval_seconds=interval, immediate=False, reason=reason,
        next_due_at=next_due,
    )


def due_assets(assets: list[dict[str, Any]], *, now: datetime | None = None) -> list[ScanSchedule]:
    """Return the schedules for assets that are due for a scan (deterministic order)."""
    now = now or datetime.now(timezone.utc)
    due = []
    for asset in assets:
        s = schedule_for_asset(asset, now=now)
        if s.immediate or (s.next_due_at is not None and s.next_due_at <= now):
            due.append(s)
    due.sort(key=lambda s: (not s.immediate, s.next_due_at or now))
    return due
