"""Evidence-backed hardware relationships (§6, §7 of the hardware review).

The review's sharpest point: an HSM and a payment API both existing does not
mean the API uses the HSM. "Evidence first, relationship second" — so this module
will not mint a ``USES_HSM`` edge without a piece of evidence that names both
ends, and it records the evidence on the edge rather than in a comment.

Where an edge may come from
---------------------------
* ``CONFIG`` — a configuration source that names the HSM: a PKCS#11 provider line
  (``/usr/lib/libCryptoki2.so`` pointing at ``HSM-01``), a KMIP client block, an
  ``application.yml`` key. This is the strongest evidence short of tracing a
  syscall, because it is what the application itself was told to do.
* ``OBSERVED`` — a runtime observation: a connection from the application's host
  to the appliance, a PKCS#11 session count moving. Strong, but proves contact
  at one instant rather than intent.
* ``DECLARED`` — an inventory or CMDB entry a human maintains. Weakest: it can be
  a year out of date, so it is capped at MEDIUM confidence and never HIGH.

The refusal is the feature
--------------------------
:func:`derive_edges` raises :class:`UnevidencedRelationship` when asked to link an
application to hardware with no supporting record. A caller cannot get an edge by
asserting one; it has to produce the record. That is what keeps the digital twin
from filling up with plausible-looking dependencies nobody can point at.

Blast radius
------------
:func:`blast_radius` answers the question that makes this worth doing: *if
HSM-01 went away, which applications, which business systems, and which payment
flows would notice?* It walks only edges that carry evidence, and it reports the
evidence for every hop rather than a bare count.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.hardware-relationship/1"

#: Evidence sources, strongest first, with the confidence each may claim.
SOURCE_CONFIDENCE: dict[str, str] = {
    "CONFIG": "HIGH",
    "OBSERVED": "HIGH",
    "DECLARED": "MEDIUM",
}

#: The edge kinds this module will produce. A relationship is typed, so the twin
#: can tell "uses" from "hosts" from "terminates TLS for".
EDGE_KINDS = ("USES_HSM", "USES_TPM", "RUNS_ON", "PART_OF_CLUSTER", "HOSTS",
              "TERMINATES_TLS", "FRONTS")

#: The kinds whose ``subject`` is an application (or a system). Only these count
#: as blast radius: a certificate terminated by a device is a thing that would
#: break, not a thing that depends on it, and counting it inflated every radius
#: by the number of certificates on the device.
APPLICATION_EDGE_KINDS = frozenset({"USES_HSM", "USES_TPM", "RUNS_ON", "HOSTS"})

#: Tokens that must never appear in an evidence payload — the evidence pointer is
#: a location, not a value, and a config snippet can carry a credential.
_SECRET_TOKENS = ("private_key", "password", "pin", "secret", "key_material",
                  "auth_value", "token_value")


class UnevidencedRelationship(ValueError):
    """Refused: an edge was requested with nothing behind it."""


@dataclass(frozen=True)
class Evidence:
    """A pointer to the record that justifies an edge.

    ``pointer`` is a location (file path, object reference, device id), never the
    value read there — a PKCS#11 configuration can carry a PIN, and an evidence
    pointer is rendered in the console and stored in BOM documents.
    """

    kind: str                  # CONFIG | OBSERVED | DECLARED
    reference: str             # where a reviewer can look
    captured_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.kind not in SOURCE_CONFIDENCE:
            raise UnevidencedRelationship(
                f"evidence kind {self.kind!r} is not one of {sorted(SOURCE_CONFIDENCE)}")
        if not self.reference.strip():
            raise UnevidencedRelationship("evidence needs a reference a reviewer can open")
        lowered = self.reference.lower()
        for token in _SECRET_TOKENS:
            if token in lowered:
                raise UnevidencedRelationship(
                    f"evidence reference mentions {token!r}; point at the file, not the value")

    @property
    def confidence(self) -> str:
        return SOURCE_CONFIDENCE[self.kind]

    @property
    def evidence_id(self) -> str:
        """Stable id, so the same evidence cited twice is the same evidence."""
        digest = hashlib.sha256(f"{self.kind}|{self.reference}".encode()).hexdigest()
        return f"EV-{digest[:12]}"

    def to_dict(self) -> dict[str, Any]:
        return {"evidence_id": self.evidence_id, "kind": self.kind,
                "reference": self.reference, "captured_at": self.captured_at,
                "confidence": self.confidence}


@dataclass(frozen=True)
class HardwareEdge:
    """``subject —kind→ hardware``, with the evidence that proves it."""

    subject: str               # application / system / certificate
    hardware: str              # HSM-01, TPM of host-7, …
    kind: str
    evidence: tuple[Evidence, ...]

    def __post_init__(self) -> None:
        if self.kind not in EDGE_KINDS:
            raise UnevidencedRelationship(f"edge kind {self.kind!r} is not one of {EDGE_KINDS}")
        if not self.evidence:
            raise UnevidencedRelationship(
                f"{self.subject} -> {self.hardware} ({self.kind}) was requested with no evidence")

    @property
    def confidence(self) -> str:
        """The *weakest* piece of supporting evidence, not the strongest.

        An edge PROVEN by a config file and merely DECLARED in a CMDB is a
        config-proven edge; an edge with no config and one stale declaration is a
        declared edge. Taking the minimum is what stops a weak citation riding on
        a strong one.
        """
        order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return min((e.confidence for e in self.evidence), key=lambda c: order[c])

    def to_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "subject": self.subject, "hardware": self.hardware,
                "kind": self.kind, "confidence": self.confidence,
                "evidence": [e.to_dict() for e in self.evidence],
                "sources": sorted({e.kind for e in self.evidence})}


# --------------------------------------------------------------------------- #
# deriving edges from what a collector actually saw
# --------------------------------------------------------------------------- #

#: Configuration signals that name an HSM. Each is (pattern, kind) where pattern
#: has one capture group holding the appliance name.
#: The window after the marker is bounded rather than "rest of file": a PKCS#11
#: block is a few lines, and an unbounded match would attach an application to
#: whatever token name appeared 400 lines later in the same config.
_WINDOW = r"[\s\S]{0,240}?"

_HSM_CONFIG_SIGNALS: tuple[tuple[str, str], ...] = (
    (rf"pkcs11{_WINDOW}(?:label|token)\s*[=:]\s*[\"']?([A-Za-z0-9_.:-]+)", "PKCS#11"),
    (rf"kmip{_WINDOW}(?:server|host)\s*[=:]\s*[\"']?([A-Za-z0-9_.:-]+)", "KMIP"),
    (r"hsm[_-]?(?:name|id|endpoint)\s*[=:]\s*[\"']?([A-Za-z0-9_.:-]+)", "HSM reference"),
)

#: A slot number is not an appliance. Without this, ``pkcs11: slot=1`` produced an
#: edge to a hardware asset called "1", which is worse than no edge at all.
_NOT_AN_APPLIANCE = re.compile(r"^\d+$")


def derive_edges(application: str, *, config_text: str | None = None,
                 config_reference: str | None = None,
                 observed_connections: Iterable[str] = (),
                 declared: Iterable[str] = ()) -> list[HardwareEdge]:
    """Turn evidence about one application into typed edges, or none at all.

    Returns an empty list when there is nothing to go on — an empty list is a
    finding ("no dependency was observed"), not a failure. Raising is reserved
    for the contradictory case: an edge explicitly declared with no record.
    """
    edges: list[HardwareEdge] = []
    if config_text:
        reference = config_reference or "config (location not recorded)"
        for pattern, label in _HSM_CONFIG_SIGNALS:
            for match in re.finditer(pattern, config_text, re.IGNORECASE):
                appliance = match.group(1)
                if _NOT_AN_APPLIANCE.match(appliance):
                    continue
                edges.append(HardwareEdge(
                    subject=application, hardware=appliance, kind="USES_HSM",
                    evidence=(Evidence("CONFIG", f"{reference}#{label}:{appliance}"),)))

    observed = sorted({name for name in observed_connections if name})
    for appliance in observed:
        edges.append(HardwareEdge(
            subject=application, hardware=appliance, kind="USES_HSM",
            evidence=(Evidence("OBSERVED", f"connection-log:{application}->{appliance}"),)))

    for appliance in sorted({name for name in declared if name}):
        edges.append(HardwareEdge(
            subject=application, hardware=appliance, kind="USES_HSM",
            evidence=(Evidence("DECLARED", f"cmdb:application/{application}/hardware/{appliance}"),)))

    # The same subject->hardware pair seen from two sources is one edge with two
    # citations, not two edges: the twin counts dependencies, not rows.
    merged: dict[tuple[str, str, str], HardwareEdge] = {}
    for edge in edges:
        key = (edge.subject, edge.hardware, edge.kind)
        if key in merged:
            previous = merged[key]
            merged[key] = HardwareEdge(previous.subject, previous.hardware, previous.kind,
                                       previous.evidence + edge.evidence)
        else:
            merged[key] = edge
    return list(merged.values())


def require_evidence(subject: str, hardware: str, kind: str,
                     evidence: Iterable[Evidence]) -> HardwareEdge:
    """Build an edge and raise if the caller could not evidence it.

    This exists so a caller that *wants* to assert a dependency has to produce the
    record in the same expression, which is where the review wanted the refusal.
    """
    collected = tuple(evidence)
    if not collected:
        raise UnevidencedRelationship(
            f"refusing to record {subject} -{kind}-> {hardware}: no evidence was supplied. "
            "A relationship without evidence is a guess with a database row around it")
    return HardwareEdge(subject=subject, hardware=hardware, kind=kind, evidence=collected)


# --------------------------------------------------------------------------- #
# what a failure would reach
# --------------------------------------------------------------------------- #

def blast_radius(hardware: str, edges: Iterable[HardwareEdge | Mapping[str, Any]],
                 *, system_of: Mapping[str, str] | None = None,
                 business_system_of: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Which applications, systems and business flows depend on ``hardware``.

    Only evidenced edges are walked. Each hop is reported with the confidence of
    the edge that carried it, so a reader can tell a config-proven dependency from
    a CMDB guess without opening the artifact.
    """
    touching = []
    for edge in edges:
        payload = edge.to_dict() if isinstance(edge, HardwareEdge) else dict(edge)
        if payload.get("hardware") != hardware:
            continue
        if not payload.get("evidence"):
            continue  # defensive: an edge with no evidence is not a dependency
        if payload.get("kind") not in APPLICATION_EDGE_KINDS:
            # A certificate the device terminates is at risk *with* the device;
            # it is not an application that depends on it.
            continue
        touching.append(payload)

    applications = sorted({payload["subject"] for payload in touching})
    systems = sorted({(system_of or {}).get(app, "UNMAPPED") for app in applications})
    flows = sorted({(business_system_of or {}).get(system, "UNMAPPED") for system in systems})
    return {
        "hardware": hardware,
        "applications": applications,
        "systems": systems,
        "business_flows": flows,
        "unmapped_applications": [app for app in applications
                                  if (system_of or {}).get(app) is None],
        "lowest_confidence": (min((payload["confidence"] for payload in touching),
                                  key=lambda c: {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[c])
                              if touching else None),
        "edges": touching,
        "application_edge_kinds": sorted(APPLICATION_EDGE_KINDS),
        "applications_affected": len(applications),
        "systems_affected": len([s for s in systems if s != "UNMAPPED"]),
    }
