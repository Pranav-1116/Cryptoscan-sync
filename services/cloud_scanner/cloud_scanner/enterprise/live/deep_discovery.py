"""ZELNX Live Cloud Intelligence Engine — event-triggered deep discovery
(§14) and continuous cross-cloud monitoring (§15).

§14 — never deep-scan everything:

    EVENT → CHANGE CLASSIFIER → IMPACT ANALYSIS → SELECT REQUIRED SCANNER

e.g. an AWS load-balancer certificate change selects: certificate scanner +
TLS scanner + dependency resolver + PQC engine.

§15 — cross-cloud blast radius: an AWS certificate change finds Azure
consumers and GCP dependencies, and the dependency graph works across
providers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.live.change_classifier import (
    classify_change,
)
from cloud_scanner.enterprise.live.event_schema import CloudEvent

ImpactResolver = Callable[[CloudEvent, str], dict[str, list[str]]]


@dataclass
class DeepDiscoveryPlan:
    """The targeted scan plan for one event (§14)."""

    event_id: str
    resource_id: str
    event_type: str
    change_type: str
    scanners: list[str] = field(default_factory=list)
    deep: bool = False
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "resource_id": self.resource_id,
            "event_type": self.event_type,
            "change_type": self.change_type,
            "scanners": list(self.scanners),
            "deep": self.deep,
            "rationale": self.rationale,
        }


DEEP_SCANNERS = {"dependency_graph", "pqc_readiness", "compliance_mapping",
                 "tls_discovery", "network_crypto", "iam_access"}


class DeepDiscoveryPlanner:
    """Select the minimal scanner set for each change."""

    def __init__(self, *, impact_resolver: ImpactResolver | None = None) -> None:
        self._impact = impact_resolver or (lambda event, change_type: {})

    def plan(self, event: CloudEvent) -> DeepDiscoveryPlan:
        classified = classify_change(event)
        scanners = list(classified.scanners)
        extra = self._impact(event, classified.change_type) or {}
        scanners += list(extra.get("scanners") or [])
        seen: list[str] = []
        for scanner in scanners:
            if scanner not in seen:
                seen.append(scanner)
        deep = bool(set(seen) & DEEP_SCANNERS)
        rationale = (
            f"change_type={classified.change_type} selects "
            f"{', '.join(seen)}" + (" (deep)" if deep else "")
        )
        return DeepDiscoveryPlan(
            event_id=event.event_id,
            resource_id=event.resource_id,
            event_type=event.event_type,
            change_type=classified.change_type,
            scanners=seen,
            deep=deep,
            rationale=rationale,
        )


@dataclass
class CrossCloudImpact:
    """Global blast radius of a change across providers (§15)."""

    resource_id: str
    event_type: str = ""
    source_provider: str = ""
    impact_by_provider: dict[str, list[str]] = field(default_factory=dict)
    total_impacted: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "event_type": self.event_type,
            "source_provider": self.source_provider,
            "impact_by_provider": {
                provider: list(resources)
                for provider, resources in self.impact_by_provider.items()
            },
            "total_impacted": self.total_impacted,
        }


class CrossCloudMonitor:
    """Find consumers/dependencies across providers for every change.

    ``find_cross_cloud_impact(resource_id)`` returns
    ``{"aws": [...], "azure": [...], "gcp": [...]}`` — injectable.
    """

    def __init__(self, *, find_cross_cloud_impact=None) -> None:
        self._find = find_cross_cloud_impact or (lambda resource_id: {})
        self._impacts: list[CrossCloudImpact] = []

    def watch(self, event: CloudEvent) -> CrossCloudImpact | None:
        if not event.resource_id:
            return None
        impact_by_provider = self._find(event.resource_id) or {}
        total = sum(len(resources) for resources in impact_by_provider.values())
        impact = CrossCloudImpact(
            resource_id=event.resource_id,
            event_type=event.event_type,
            source_provider=event.provider,
            impact_by_provider={str(k): [str(r) for r in v]
                                for k, v in impact_by_provider.items()},
            total_impacted=total,
        )
        self._impacts.append(impact)
        return impact

    def impacts(self) -> list[CrossCloudImpact]:
        return list(self._impacts)

    def summary(self) -> dict[str, Any]:
        return {
            "impacts": len(self._impacts),
            "total_resources_impacted": sum(i.total_impacted for i in self._impacts),
            "cross_provider_chains": sum(
                1 for i in self._impacts if len(i.impact_by_provider) > 1
            ),
        }
