"""If this HSM fails, what breaks? Hardware → application → business system.

An HBOM answers "what is in the estate". It does not answer the question a bank's
operations lead actually asks during an incident, which is the chain the review
drew:

    HSM-01 → Payment API → Payment Processing → Card Authorization (CRITICAL)

This module walks that chain over **evidenced hops only**, and it is careful
about the two ways a blast radius usually lies:

* **It does not count what is not a dependency.** Only edge kinds in
  :data:`~universal_vendor.hardware.relationships.APPLICATION_EDGE_KINDS` are
  walked, so a certificate a device terminates is reported as at risk *with* the
  device rather than as an application that depends on it.
* **It does not report an unknown as a zero.** An application that depends on the
  device but is named by no service record is listed under ``unmapped`` and said
  out loud in the statement. "3 applications affected, 2 of them unmapped" is a
  different answer from "1 application affected", and only one of them is true.

A service record is evidence about a mapping, so it carries its own
:class:`~universal_vendor.hardware.relationships.Evidence`: the CMDB row or the
config that names both the application and the business system. A record with no
evidence is refused at construction — the same rule the hardware edges follow,
applied to the hop that reaches the business.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from universal_vendor.hardware.relationships import (
    Evidence,
    HardwareEdge,
    UnevidencedRelationship,
    blast_radius,
)

SCHEMA = "cryptoscan.hardware-impact/1"

CRITICALITY_ORDER: dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_CONFIDENCE_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

UNMAPPED = "UNMAPPED"


class ImpactRejected(ValueError):
    """A service record or an impact query the evidence does not support."""


@dataclass(frozen=True)
class ServiceRecord:
    """One service, the applications that implement it, and what it supports.

    ``business_system`` is the thing the bank calls critical — Card Authorization,
    Payments Processing, SWIFT Gateway. ``criticality`` is the bank's own label,
    not a score this module invents.
    """

    name: str
    applications: tuple[str, ...]
    business_system: str
    criticality: str
    evidence: Evidence

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ImpactRejected("a service needs a name")
        if not self.applications:
            raise ImpactRejected(
                f"service {self.name!r} names no application, so it cannot be reached "
                "from any hardware failure")
        if not self.business_system.strip():
            raise ImpactRejected(f"service {self.name!r} maps to no business system")
        level = self.criticality.upper()
        if level not in CRITICALITY_ORDER:
            raise ImpactRejected(
                f"{self.criticality!r} is not one of {sorted(CRITICALITY_ORDER)}")
        if not isinstance(self.evidence, Evidence):
            raise UnevidencedRelationship(
                f"service {self.name!r} needs the record that names its applications")
        object.__setattr__(self, "criticality", level)

    @property
    def confidence(self) -> str:
        return self.evidence.confidence

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "applications": list(self.applications),
                "business_system": self.business_system,
                "criticality": self.criticality, "confidence": self.confidence,
                "evidence": self.evidence.to_dict()}


@dataclass
class ImpactReport:
    """Everything a failure of one appliance would reach."""

    hardware: str
    applications: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    business_systems: list[str] = field(default_factory=list)
    critical_systems: list[str] = field(default_factory=list)
    unmapped_applications: list[str] = field(default_factory=list)
    hops: list[dict[str, Any]] = field(default_factory=list)
    lowest_confidence: str | None = None

    @property
    def statement(self) -> str:
        """The sentence an operator reads at 03:00."""
        if not self.applications:
            return (f"no evidenced application depends on {self.hardware}: a failure "
                    "would reach nothing this estate can prove")
        parts = [f"{self.hardware} failure reaches {len(self.applications)} application(s)"]
        parts.append(f"{len(self.services)} service(s)")
        if self.critical_systems:
            parts.append(f"{len(self.critical_systems)} critical business system(s) "
                         f"({', '.join(self.critical_systems)})")
        elif self.business_systems:
            parts.append(f"{len(self.business_systems)} business system(s)")
        if self.unmapped_applications:
            parts.append(f"{len(self.unmapped_applications)} application(s) with no "
                         f"business mapping ({', '.join(self.unmapped_applications)})")
        return "; ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "hardware": self.hardware,
            "applications": list(self.applications),
            "services": list(self.services),
            "business_systems": list(self.business_systems),
            "critical_business_systems": list(self.critical_systems),
            "unmapped_applications": list(self.unmapped_applications),
            "applications_affected": len(self.applications),
            "services_affected": len(self.services),
            "business_systems_affected": len(self.business_systems),
            "critical_systems_affected": len(self.critical_systems),
            "lowest_confidence": self.lowest_confidence,
            "statement": self.statement,
            "hops": list(self.hops),
        }


def failure_impact(hardware: str,
                   edges: Iterable[HardwareEdge | Mapping[str, Any]],
                   *,
                   services: Iterable[ServiceRecord] = (),
                   system_of: Mapping[str, str] | None = None,
                   business_system_of: Mapping[str, str] | None = None) -> ImpactReport:
    """Walk hardware → application → service → business system, evidenced only.

    ``system_of`` and ``business_system_of`` are passed through to
    :func:`~universal_vendor.hardware.relationships.blast_radius` so the two
    modules cannot disagree about which application sits on which system.
    """
    flat = [edge.to_dict() if isinstance(edge, HardwareEdge) else dict(edge)
            for edge in edges]
    radius = blast_radius(hardware, flat, system_of=system_of,
                          business_system_of=business_system_of)
    applications = list(radius["applications"])

    records = list(services)
    report = ImpactReport(hardware=hardware, applications=applications)
    confidences: list[str] = [radius["lowest_confidence"]] if radius["lowest_confidence"] else []

    mapped: set[str] = set()
    systems: list[tuple[str, str]] = []
    for record in records:
        touched = sorted(set(record.applications) & set(applications), key=str.lower)
        if not touched:
            continue
        report.services.append(record.name)
        systems.append((record.business_system, record.criticality))
        mapped.update(touched)
        confidences.append(record.confidence)
        report.hops.append({
            "service": record.name,
            "applications": touched,
            "business_system": record.business_system,
            "criticality": record.criticality,
            "service_evidence": record.evidence.to_dict(),
            "application_evidence": [
                {"application": app, "evidence_ids": [item["evidence_id"]
                                                      for item in edge.get("evidence") or ()],
                 "confidence": edge.get("confidence")}
                for app in touched for edge in flat
                if edge.get("hardware") == hardware and edge.get("subject") == app],
        })

    report.business_systems = sorted({name for name, _ in systems}, key=str.lower)
    report.critical_systems = sorted(
        {name for name, level in systems if level == "CRITICAL"}, key=str.lower)
    report.unmapped_applications = sorted(set(applications) - mapped, key=str.lower)
    if confidences:
        report.lowest_confidence = min(confidences,
                                       key=lambda level: _CONFIDENCE_ORDER.get(level, 0))
    return report
