"""Deterministic remediation-SLA policy (no AI/ML).

Maps a finding's severity (and whether it is on a safety/critical asset) to a
fixed remediation deadline, then classifies open findings as ON_TRACK, AT_RISK
(inside the warning window), or BREACHED (past the deadline). Breaches age out in
days-overdue. Everything is pure clock + lookup-table arithmetic so the same
finding always produces the same SLA state — auditable and replayable.

Default SLA table (calendar days from detection), overridable per policy:

    CRITICAL  7      HIGH  30      MEDIUM  90      LOW  180      INFO  365
Critical assets (safety controllers, payment/HSM, customer-data) halve the
window. The warning threshold flags an item as AT_RISK when the remaining time
is within a configurable fraction (default 20%) of its window.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Iterable

#: remediation window in days by finding severity
DEFAULT_SLA_DAYS = {
    "CRITICAL": 7,
    "HIGH": 30,
    "MEDIUM": 90,
    "LOW": 180,
    "INFO": 365,
    "UNKNOWN": 90,
}
#: criticality tiers that compress the window (safety/payment/crown-jewel)
CRITICAL_ASSET_TIERS = frozenset({"SAFETY", "CRITICAL", "HSM", "PAYMENT", "TIER0", "CROWN_JEWEL"})
#: fraction of the window within which an open item is considered AT_RISK
WARN_FRACTION = 0.20


class SlaState(str, Enum):
    OPEN = "OPEN"
    ON_TRACK = "ON_TRACK"
    AT_RISK = "AT_RISK"
    BREACHED = "BREACHED"
    RESOLVED = "RESOLVED"


def _now(now: datetime | None) -> datetime:
    n = now or datetime.now(timezone.utc)
    return n if n.tzinfo else n.replace(tzinfo=timezone.utc)


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _norm_severity(value: Any) -> str:
    s = str(value or "").strip().upper()
    return s if s in DEFAULT_SLA_DAYS else "UNKNOWN"


def sla_window_days(severity: str, asset_criticality: str | None = None,
                    sla_days: dict[str, int] | None = None) -> int:
    """Resolve the SLA window (days) for a finding on an asset."""
    table = sla_days or DEFAULT_SLA_DAYS
    sev = _norm_severity(severity)
    days = int(table.get(sev, table["UNKNOWN"]))
    crit = str(asset_criticality or "").strip().upper()
    if crit in CRITICAL_ASSET_TIERS:
        days = max(1, days // 2)
    return days


def due_date(detected_at: datetime, severity: str,
             asset_criticality: str | None = None,
             sla_days: dict[str, int] | None = None) -> datetime:
    days = sla_window_days(severity, asset_criticality, sla_days)
    return detected_at + timedelta(days=days)


@dataclass
class SlaItem:
    finding_id: str
    severity: str
    detected_at: datetime
    due_at: datetime
    resolved_at: datetime | None
    asset_criticality: str | None = None
    window_days: int = 0

    @property
    def is_resolved(self) -> bool:
        return self.resolved_at is not None


@dataclass
class SlaStatus:
    finding_id: str
    severity: str
    state: SlaState
    due_at: datetime
    days_remaining: float | None
    days_overdue: float
    window_days: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "state": self.state.value,
            "due_at": self.due_at.isoformat(),
            "days_remaining": None if self.days_remaining is None else round(self.days_remaining, 2),
            "days_overdue": round(self.days_overdue, 2),
            "window_days": self.window_days,
        }


def _status_for(item: SlaItem, now: datetime, sla_days: dict[str, int]) -> SlaStatus:
    if item.is_resolved:
        # resolved — but note if it was fixed after the deadline (late fix)
        resolved = item.resolved_at
        state = SlaState.RESOLVED
        overdue = max(0.0, (resolved - item.due_at).total_seconds() / 86400.0)
        return SlaStatus(item.finding_id, item.severity, state, item.due_at,
                         days_remaining=None, days_overdue=overdue,
                         window_days=item.window_days)

    remaining = (item.due_at - now).total_seconds() / 86400.0
    if remaining < 0:
        return SlaStatus(item.finding_id, item.severity, SlaState.BREACHED, item.due_at,
                         days_remaining=round(remaining, 2), days_overdue=abs(remaining),
                         window_days=item.window_days)
    warn_window = item.window_days * WARN_FRACTION
    state = SlaState.AT_RISK if remaining <= warn_window else SlaState.ON_TRACK
    return SlaStatus(item.finding_id, item.severity, state, item.due_at,
                     days_remaining=round(remaining, 2), days_overdue=0.0,
                     window_days=item.window_days)


def evaluate_item(finding: dict[str, Any], *, now: datetime | None = None,
                  sla_days: dict[str, int] | None = None) -> SlaStatus:
    """Evaluate a single finding (dict with detected_at/severity/criticality)."""
    n = _now(now)
    detected = _parse_dt(finding.get("detected_at") or finding.get("first_seen")
                         or finding.get("created_at"))
    if detected is None:
        detected = n
    severity = _norm_severity(finding.get("severity") or finding.get("confidence"))
    crit = finding.get("asset_criticality") or finding.get("criticality")
    window = sla_window_days(severity, crit, sla_days)
    due = due_date(detected, severity, crit, sla_days)
    resolved = _parse_dt(finding.get("resolved_at") or finding.get("fixed_at"))
    item = SlaItem(
        finding_id=str(finding.get("id") or finding.get("finding_id") or "?"),
        severity=severity, detected_at=detected, due_at=due,
        resolved_at=resolved, asset_criticality=crit, window_days=window,
    )
    return _status_for(item, n, sla_days or DEFAULT_SLA_DAYS)


@dataclass
class SlaReport:
    total: int = 0
    open_total: int = 0
    on_track: int = 0
    at_risk: int = 0
    breached: int = 0
    resolved: int = 0
    resolved_late: int = 0
    items: list[SlaStatus] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "open_total": self.open_total,
            "on_track": self.on_track,
            "at_risk": self.at_risk,
            "breached": self.breached,
            "resolved": self.resolved,
            "resolved_late": self.resolved_late,
            "breach_rate": round(self.breached / self.open_total, 4) if self.open_total else 0.0,
            "items": [i.as_dict() for i in self.items],
        }


def evaluate_findings(findings: Iterable[dict[str, Any]], *, now: datetime | None = None,
                      sla_days: dict[str, int] | None = None) -> SlaReport:
    n = _now(now)
    table = sla_days or DEFAULT_SLA_DAYS
    report = SlaReport()
    for f in findings:
        st = evaluate_item(f, now=n, sla_days=table)
        report.total += 1
        if st.state == SlaState.RESOLVED:
            report.resolved += 1
            if st.days_overdue > 0:
                report.resolved_late += 1
        else:
            report.open_total += 1
            if st.state == SlaState.ON_TRACK:
                report.on_track += 1
            elif st.state == SlaState.AT_RISK:
                report.at_risk += 1
            elif st.state == SlaState.BREACHED:
                report.breached += 1
        report.items.append(st)
    # deterministic ordering: breached first, then most-overdue / soonest-due
    report.items.sort(key=lambda s: (
        s.state != SlaState.BREACHED,
        s.state != SlaState.AT_RISK,
        s.days_remaining if s.days_remaining is not None else 1e9,
    ))
    return report
