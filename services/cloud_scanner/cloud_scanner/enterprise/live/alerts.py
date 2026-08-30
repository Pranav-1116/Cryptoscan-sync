"""ZELNX Live Cloud Intelligence Engine — intelligent alert correlation
(§20).

Prevents alert storms: a root-CA change impacting 400 AWS + 250 Azure +
150 GCP certificates produces ONE root incident (``ROOT CA CHANGE`` with
AWS IMPACT / AZURE IMPACT / GCP IMPACT), not 800 separate alerts.

Correlation keys are configurable; by default events are correlated on
the provider resource that is the ROOT CAUSE (e.g. the CA that issued the
certificates).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.live.event_schema import CloudEvent

CorrelationKey = Callable[[CloudEvent], str]


def default_correlation_key(event: CloudEvent) -> str:
    """Correlate by CA / issuer when present, else by provider + event type.

    The CA is deliberately NOT provider-prefixed: a root-CA change that
    impacts AWS, Azure AND GCP certificates must produce ONE incident
    (§20), with per-provider impact counts inside the alert.
    """
    issuer = (event.provider_metadata.get("issuer")
              or event.provider_metadata.get("ca_id")
              or event.provider_metadata.get("root_ca"))
    if issuer:
        return f"ca:{issuer}"
    return f"{event.provider}:{event.event_type}"


@dataclass
class CorrelatedAlert:
    """One aggregated alert produced from many raw events."""

    correlation_key: str
    incident_type: str = ""
    title: str = ""
    severity: str = "LOW"
    provider_impacts: dict[str, int] = field(default_factory=dict)
    resource_count: int = 0
    event_ids: list[str] = field(default_factory=list)
    sample_resources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_key": self.correlation_key,
            "incident_type": self.incident_type,
            "title": self.title,
            "severity": self.severity,
            "provider_impacts": dict(self.provider_impacts),
            "resource_count": self.resource_count,
            "event_ids": list(self.event_ids),
            "sample_resources": list(self.sample_resources),
        }


class AlertCorrelationEngine:
    """Aggregate many related events into ONE incident."""

    def __init__(self, *, correlation_key: CorrelationKey | None = None,
                 window: str = "3600") -> None:
        self._key = correlation_key or default_correlation_key
        self._window = window
        self._alerts: list[CorrelatedAlert] = []

    def correlate(self, events: list[CloudEvent]) -> list[CorrelatedAlert]:
        """Correlate a batch of events into alerts."""
        groups: dict[str, list[CloudEvent]] = {}
        for event in events:
            groups.setdefault(self._key(event), []).append(event)
        alerts: list[CorrelatedAlert] = []
        for key, group in groups.items():
            provider_counts: dict[str, int] = {}
            resources: list[str] = []
            for event in group:
                provider_counts[event.provider] = provider_counts.get(event.provider, 0) + 1
                if event.resource_id and event.resource_id not in resources:
                    resources.append(event.resource_id)
            incident_type = group[0].provider_metadata.get("incident_type") \
                or incident_type_for_key(key)
            severity = severity_for_count(len(group))
            alerts.append(CorrelatedAlert(
                correlation_key=key,
                incident_type=incident_type,
                title=f"{incident_type} affecting {len(group)} resources "
                      f"across {len(provider_counts)} provider(s)",
                severity=severity,
                provider_impacts=dict(provider_counts),
                resource_count=len(group),
                event_ids=[e.event_id for e in group],
                sample_resources=resources[:20],
            ))
        self._alerts.extend(alerts)
        return alerts

    def alerts(self) -> list[CorrelatedAlert]:
        return list(self._alerts)

    def summary(self) -> dict[str, Any]:
        return {
            "alerts": len(self._alerts),
            "events_correlated": sum(a.resource_count for a in self._alerts),
        }


def incident_type_for_key(key: str) -> str:
    lowered = key.lower()
    if "ca:" in lowered or "root" in lowered:
        return "ROOT_CA_CHANGE"
    if "certificate" in lowered:
        return "CERTIFICATE_CHANGE"
    if "key" in lowered:
        return "KEY_CHANGE"
    if "network" in lowered or "tls" in lowered:
        return "NETWORK_CHANGE"
    return "CLOUD_CHANGE"


def severity_for_count(count: int) -> str:
    if count >= 100:
        return "CRITICAL"
    if count >= 10:
        return "HIGH"
    if count >= 3:
        return "MEDIUM"
    return "LOW"
