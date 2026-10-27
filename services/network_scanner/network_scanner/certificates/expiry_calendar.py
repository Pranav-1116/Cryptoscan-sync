"""Deterministic certificate expiry calendar and SLA buckets.

Given an iterable of certificate dicts (with ``not_after`` /
``days_until_expiry``) this produces a tiered expiry calendar that maps onto
renewal SLA windows. There is no ML — every bucket is a fixed-day rule:

- ``expired``          not_after is in the past
- ``critical``         0–7 days     (renew immediately — outage risk)
- ``warning``          8–30 days    (renew within the week)
- ``scheduled``        31–90 days   (plan the change window)
- ``healthy``          >90 days
- ``unknown``          no parseable expiry

It re-computes remaining days from ``not_after`` when present so stored
``days_until_expiry`` values that drift between scans never go stale in the
API response.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

# tier -> (inclusive lower days, inclusive upper days); None bound = open.
_SLA_TIERS: tuple[tuple[str, int, int | None, str], ...] = (
    ("critical", 0, 7, "CRITICAL"),
    ("warning", 8, 30, "HIGH"),
    ("scheduled", 31, 90, "MEDIUM"),
    ("healthy", 91, None, "INFO"),
)

TIER_ORDER = ["expired", "critical", "warning", "scheduled", "healthy", "unknown"]


def _coerce_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        txt = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(txt)
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def days_remaining(cert: dict[str, Any], *, now: datetime | None = None) -> int | None:
    """Whole days until expiry (negative when expired); None if unknown."""
    not_after = _coerce_dt(cert.get("not_after"))
    if not_after is not None:
        reference = now or datetime.now(timezone.utc)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        delta = not_after - reference.astimezone(timezone.utc)
        return int(delta.total_seconds() // 86_400)
    stored = cert.get("days_until_expiry")
    if isinstance(stored, (int, float)):
        return int(stored)
    return None


def tier_for_days(days: int | None) -> tuple[str, str]:
    """Return (tier, severity) for a remaining-days value."""
    if days is None:
        return "unknown", "INFO"
    if days < 0:
        return "expired", "CRITICAL"
    for tier, low, high, severity in _SLA_TIERS:
        if days >= low and (high is None or days <= high):
            return tier, severity
    return "healthy", "INFO"


def build_expiry_calendar(
    certs: Iterable[dict[str, Any]],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the tiered expiry calendar + per-certificate entries."""
    reference = now or datetime.now(timezone.utc)
    buckets: dict[str, list[dict[str, Any]]] = {t: [] for t in TIER_ORDER}

    for cert in certs:
        days = days_remaining(cert, now=reference)
        tier, severity = tier_for_days(days)
        entries = buckets[tier]
        entries.append({
            "subject": cert.get("subject") or cert.get("common_name"),
            "fingerprint_sha256": cert.get("fingerprint_sha256"),
            "issuer": cert.get("issuer"),
            "not_after": (_coerce_dt(cert.get("not_after")).isoformat()
                          if _coerce_dt(cert.get("not_after")) else None),
            "days_until_expiry": days,
            "severity": severity,
            "renewal_status": cert.get("renewal_status"),
            "renewal_ticket": cert.get("renewal_ticket"),
            "usages": cert.get("usages") or [],
        })

    # most urgent first within each bucket
    for tier in TIER_ORDER:
        buckets[tier].sort(
            key=lambda e: (e["days_until_expiry"] is None,
                           e["days_until_expiry"] if e["days_until_expiry"] is not None else 0))

    counts = {tier: len(buckets[tier]) for tier in TIER_ORDER}
    actionable = counts["expired"] + counts["critical"] + counts["warning"]
    return {
        "generated_at": reference.astimezone(timezone.utc).isoformat(),
        "sla_tiers": {
            "critical": "0-7 days",
            "warning": "8-30 days",
            "scheduled": "31-90 days",
            "healthy": ">90 days",
        },
        "counts": counts,
        "total_tracked": sum(counts.values()),
        "actionable_count": actionable,
        "healthy_count": counts["healthy"],
        "buckets": buckets,
    }
