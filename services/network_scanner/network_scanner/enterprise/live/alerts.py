"""Alert Engine — severity-based alerts with correlation + deduplication.

Severities: INFO · LOW · MEDIUM · HIGH · CRITICAL.

Every alert carries: WHAT_CHANGED, WHEN, WHERE, WHO_OWNS_ASSET, EVIDENCE,
IMPACT, DEPENDENCIES, RECOMMENDED_ACTION.

Deduplication is essential for 24/7 monitoring — do NOT generate 10,000
alerts because one certificate affects 10,000 endpoints.  Events are
correlated by root cause, impact-grouped, and surfaced as ONE incident.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

_SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}


@dataclass
class Alert:
    severity: str
    title: str
    what_changed: str = ""
    when: Any = None
    where: str = ""
    owner: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    impact: str = ""
    dependencies: list[str] = field(default_factory=list)
    recommended_action: str = ""
    correlation_key: str = ""
    source: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity '{self.severity}'")

    def to_dict(self) -> dict[str, Any]:
        when = self.when
        if hasattr(when, "isoformat"):
            when = when.isoformat()
        return {"severity": self.severity, "title": self.title,
                "what_changed": self.what_changed, "when": when,
                "where": self.where, "who_owns_asset": self.owner,
                "evidence": list(self.evidence), "impact": self.impact,
                "dependencies": list(self.dependencies),
                "recommended_action": self.recommended_action,
                "correlation_key": self.correlation_key,
                "source": self.source}


@dataclass
class CorrelatedIncident:
    """One incident after root-cause correlation + impact grouping."""

    correlation_key: str
    severity: str
    title: str
    affected_assets: list[str] = field(default_factory=list)
    impacted_count: int = 0
    alerts_collapsed: int = 0
    first_seen: Any = None
    last_seen: Any = None
    recommended_action: str = ""
    sample_evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        def iso(value: Any) -> Any:
            return value.isoformat() if hasattr(value, "isoformat") else value

        return {"correlation_key": self.correlation_key,
                "severity": self.severity, "title": self.title,
                "affected_assets": list(self.affected_assets),
                "impacted_count": self.impacted_count,
                "alerts_collapsed": self.alerts_collapsed,
                "first_seen": iso(self.first_seen),
                "last_seen": iso(self.last_seen),
                "recommended_action": self.recommended_action,
                "sample_evidence": list(self.sample_evidence)}


class AlertDeduplicator:
    """Groups alerts by correlation key into a single incident.

    ``key_for`` maps an alert to its root cause key (e.g. the rotated root
    CA's fingerprint).  Alerts sharing the key collapse into one incident
    with ``impacted_count`` = summed dependency/affected counts.
    """

    def __init__(self, *,
                 key_for: Callable[[Alert], str] | None = None,
                 window_seconds: int = 3600,
                 clock: Callable[[], Any] | None = None) -> None:
        self._key_for = key_for or (lambda alert: alert.correlation_key or alert.title)
        self._window = window_seconds
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def correlate(self, alerts: Iterable[Alert], *,
                  now: Any | None = None) -> list[CorrelatedIncident]:
        now = now if now is not None else self._clock()
        buckets: dict[str, list[Alert]] = {}
        for alert in alerts:
            buckets.setdefault(self._key_for(alert), []).append(alert)

        incidents: list[CorrelatedIncident] = []
        for key, group in buckets.items():
            group.sort(key=lambda a: _SEVERITY_RANK[a.severity], reverse=True)
            top = group[0]
            affected: list[str] = []
            impacted = 0
            for alert in group:
                for asset in (alert.dependencies or []):
                    if asset not in affected:
                        affected.append(asset)
                if alert.where and alert.where not in affected:
                    affected.append(alert.where)
            incidents.append(CorrelatedIncident(
                correlation_key=key,
                severity=top.severity,
                title=top.title,
                affected_assets=affected[:200],
                impacted_count=len(affected),
                alerts_collapsed=len(group),
                first_seen=group[0].when or now,
                last_seen=now,
                recommended_action=top.recommended_action,
                sample_evidence=top.evidence[:5],
            ))
        incidents.sort(key=lambda i: _SEVERITY_RANK[i.severity], reverse=True)
        return incidents


class AlertEngine:
    """Raises severity-based alerts; drains as correlated incidents."""

    def __init__(self, *, deduplicator: AlertDeduplicator | None = None,
                 clock: Callable[[], Any] | None = None,
                 sink: Callable[[Alert], None] | None = None) -> None:
        self._deduplicator = deduplicator or AlertDeduplicator()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._pending: list[Alert] = []
        self._history: list[Alert] = []
        self._sink = sink

    def raise_alert(self, *, severity: str, title: str,
                    what_changed: str = "", where: str = "", owner: str = "",
                    evidence: Iterable[dict[str, Any]] | None = None,
                    impact: str = "", dependencies: Iterable[str] = (),
                    recommended_action: str = "",
                    correlation_key: str = "",
                    source: str = "", when: Any = None) -> Alert:
        alert = Alert(
            severity=severity, title=title, what_changed=what_changed,
            when=when if when is not None else self._clock(),
            where=where, owner=owner, evidence=list(evidence or []),
            impact=impact, dependencies=list(dependencies),
            recommended_action=recommended_action,
            correlation_key=correlation_key, source=source,
        )
        self._pending.append(alert)
        self._history.append(alert)
        if self._sink is not None:
            self._sink(alert)
        return alert

    def pending(self) -> list[Alert]:
        return list(self._pending)

    def history(self) -> list[Alert]:
        return list(self._history)

    def drain(self, *, correlate: bool = True) -> list[CorrelatedIncident] | list[Alert]:
        """Return pending alerts; when ``correlate`` is True they are grouped
        into single incidents by root cause."""
        pending, self._pending = self._pending, []
        if not correlate:
            return pending
        return self._deduplicator.correlate(pending)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [alert.to_dict() for alert in self._history]


def alert_id(alert: Alert) -> str:
    """Deterministic id for an alert (for sinks/audit)."""
    payload = json.dumps({"severity": alert.severity, "title": alert.title,
                          "where": alert.where, "when": str(alert.when)},
                         sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
