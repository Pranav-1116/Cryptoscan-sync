"""Key/certificate expiry alerting with fixed 90/60/30/7-day rules + SLA.

Deterministic, rule-based. Given a set of tracked certificates/keys (with
``not_after`` and an owning team/SLA tier), produce the alert events that fire
on each milestone and track SLA state:

- RENEWAL_SCHEDULED (≤90d), UPCOMING (≤60d), URGENT (≤30d), CRITICAL (≤7d),
  EXPIRED (past).
- Each asset has an SLA lead-time (days before expiry by which renewal must
  complete). If the window is inside the SLA lead and the asset is not yet
  renewed, SLA is AT_RISK; once expired it is BREACHED.

This complements network_scanner.certificates.expiry_calendar by producing
*alert events* and *SLA state*, not just the calendar buckets.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Iterable

# Fixed, deterministic milestones (days-until-expiry threshold → rule).
ALERT_RULES: list[dict] = [
    {"code": "EXPIRED",          "at_days": -1,  "severity": "CRITICAL", "label": "expired"},
    {"code": "EXPIRY_7D",        "at_days": 7,   "severity": "CRITICAL", "label": "expires within 7 days"},
    {"code": "EXPIRY_30D",       "at_days": 30,  "severity": "HIGH",     "label": "expires within 30 days"},
    {"code": "EXPIRY_60D",       "at_days": 60,  "severity": "MEDIUM",   "label": "expires within 60 days"},
    {"code": "EXPIRY_90D",       "at_days": 90,  "severity": "LOW",      "label": "expires within 90 days"},
]

# Default SLA lead times per asset tier (renewal must be complete this many
# days before expiry).
DEFAULT_SLA_LEAD_DAYS = {
    "tier1": 60,   # customer-facing / internet edge
    "tier2": 30,   # internal services
    "tier3": 14,   # dev / non-prod
}


def _coerce_dt(value: Any) -> dt.datetime | None:
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if isinstance(value, str):
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            return None
    return None


def days_until_expiry(not_after: Any, now: dt.datetime) -> int | None:
    na = _coerce_dt(not_after)
    if na is None:
        return None
    return (na - now).days


def rules_for_days(days: int | None) -> list[dict]:
    """Return the alert rules that have fired for a days-remaining value."""
    if days is None:
        return []
    if days < 0:
        # Expired: the EXPIRED rule supersedes all forward-looking milestones.
        return [next(r for r in ALERT_RULES if r["code"] == "EXPIRED")]
    return [r for r in ALERT_RULES if r["code"] != "EXPIRED" and days <= r["at_days"]]


def sla_state(days: int | None, asset: dict, *, now: dt.datetime) -> dict:
    """Compute SLA status for an asset given its renewal state."""
    if days is None:
        return {"status": "UNKNOWN", "breached": False, "lead_days": None}
    tier = asset.get("sla_tier", "tier2")
    lead = int(asset.get("sla_lead_days") or DEFAULT_SLA_LEAD_DAYS.get(tier, 30))
    renewed = bool(asset.get("renewed") or asset.get("renewal_ticket_closed"))
    if days < 0:
        return {"status": "BREACHED", "breached": True, "lead_days": lead,
                "detail": "asset expired before renewal completed"}
    if renewed:
        return {"status": "MET", "breached": False, "lead_days": lead}
    if days <= lead:
        return {"status": "AT_RISK", "breached": False, "lead_days": lead,
                "detail": f"within {lead}-day SLA renewal lead, not yet renewed"}
    return {"status": "ON_TRACK", "breached": False, "lead_days": lead}


def evaluate_asset(asset: dict, *, now: dt.datetime | None = None) -> dict:
    reference = now or dt.datetime.now(dt.timezone.utc)
    days = days_until_expiry(asset.get("not_after"), reference)
    rules = rules_for_days(days)
    sla = sla_state(days, asset, now=reference)
    return {
        "id": asset.get("id") or asset.get("fingerprint_sha256") or asset.get("subject"),
        "subject": asset.get("subject") or asset.get("common_name"),
        "type": asset.get("type", "certificate"),
        "owner": asset.get("owner") or asset.get("team"),
        "sla_tier": asset.get("sla_tier", "tier2"),
        "not_after": _coerce_dt(asset.get("not_after")).isoformat() if _coerce_dt(asset.get("not_after")) else None,
        "days_until_expiry": days,
        "renewed": bool(asset.get("renewed")),
        "alerts": [{"code": r["code"], "severity": r["severity"], "label": r["label"]} for r in rules],
        "highest_severity": rules[0]["severity"] if rules else "INFO",
        "sla": sla,
    }


def run_expiry_campaign(assets: Iterable[dict], *, now: dt.datetime | None = None) -> dict:
    """Evaluate all assets and roll up an alert + SLA campaign summary."""
    reference = now or dt.datetime.now(dt.timezone.utc)
    results = [evaluate_asset(a, now=reference) for a in assets]

    open_alerts: list[dict] = []
    counts = {"EXPIRED": 0, "EXPIRY_7D": 0, "EXPIRY_30D": 0, "EXPIRY_60D": 0, "EXPIRY_90D": 0}
    sla_counts = {"BREACHED": 0, "AT_RISK": 0, "ON_TRACK": 0, "MET": 0, "UNKNOWN": 0}
    for r in results:
        sla_counts[r["sla"]["status"]] = sla_counts.get(r["sla"]["status"], 0) + 1
        for a in r["alerts"]:
            counts[a["code"]] = counts.get(a["code"], 0) + 1
        if r["alerts"]:
            open_alerts.append({
                "id": r["id"], "subject": r["subject"], "owner": r["owner"],
                "days_until_expiry": r["days_until_expiry"],
                "severity": r["highest_severity"],
                "sla_status": r["sla"]["status"],
                "codes": [a["code"] for a in r["alerts"]],
            })

    open_alerts.sort(key=lambda x: (x["days_until_expiry"] is None,
                                    x["days_until_expiry"] if x["days_until_expiry"] is not None else 0))
    return {
        "generated_at": reference.isoformat(),
        "rules": [r["code"] for r in ALERT_RULES],
        "total_assets": len(results),
        "alert_counts": counts,
        "sla_counts": sla_counts,
        "sla_breached": sla_counts["BREACHED"],
        "sla_at_risk": sla_counts["AT_RISK"],
        "actionable_alerts": len(open_alerts),
        "alerts": open_alerts,
        "assets": results,
    }
