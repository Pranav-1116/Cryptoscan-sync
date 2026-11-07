"""The collector contract every adapter obeys.

An adapter is a translator, not a witness: it can only emit events for
observations that carry their evidence references. Anything it cannot
translate becomes a named refusal — never an invented event, never a
silent drop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class CollectorRef:
    """Who observed, and through which authorized surface."""

    collector_id: str
    collector_version: str
    source_type: str  # must be in validate_event's source_type vocabulary


@dataclass
class Refusal:
    observation_ref: str
    reason: str


@dataclass
class Translation:
    events: list[dict[str, Any]] = field(default_factory=list)
    refusals: list[Refusal] = field(default_factory=list)

    @property
    def accepted(self) -> int:
        return len(self.events)

    @property
    def refused(self) -> int:
        return len(self.refusals)


def translated(*events: dict[str, Any]) -> Translation:
    return Translation(events=list(events))


def refused(observation_ref: str, reason: str) -> Translation:
    return Translation(refusals=[Refusal(observation_ref=observation_ref,
                                         reason=reason)])


def observation_ref(observation: Mapping[str, Any]) -> str:
    return str(observation.get("observation_id") or observation.get("id") or "unidentified-observation")


def require_evidence(observation: Mapping[str, Any]) -> tuple[list[str], str | None]:
    """Evidence references are mandatory: an observation without evidence is
    a claim, not an event."""
    evidence = observation.get("evidence_ids") or []
    if isinstance(evidence, Sequence) and not isinstance(evidence, str):
        ids = [str(e) for e in evidence if str(e).strip()]
        if ids:
            return ids, None
    return [], ("an observation without evidence references is not an event: "
                "refused, never fabricated")


def base_event(ref: CollectorRef, *, event_type: str, category: str,
               logging_kind: str, severity: str, asset_id: str,
               observed_at: str, evidence_ids: Sequence[str],
               tenant_id: str,
               business_system_id: str | None = None,
               investigation_status: str = "OBSERVED") -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "event_type": event_type,
        "category": category,
        "logging_kind": logging_kind,
        "severity": severity,
        "asset_id": asset_id,
        "business_system_id": business_system_id,
        "source": {
            "collector_id": ref.collector_id,
            "collector_version": ref.collector_version,
            "source_type": ref.source_type,
        },
        "observation": {"observed_at": observed_at},
        "evidence": {"evidence_ids": list(evidence_ids)},
        "investigation_status": investigation_status,
    }
