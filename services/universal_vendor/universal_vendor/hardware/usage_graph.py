"""Who uses which HSM, and what it can do — both only with evidence.

The review's picture is short and the whole point is the arrows:

    HSM-01 ──USED_BY──▶ Payment API
           ──USED_BY──▶ Card Authorization
           ──SUPPORTS─▶ RSA-3072 / ECDSA-P256 / ML-DSA

:mod:`~universal_vendor.hardware.relationships` already refuses an edge with no
evidence. This module is the layer above it, and it is where the *application*
side of that rule is decided:

* **A config file names both ends, or there is no edge.** ``derive_edges`` reads
  a PKCS#11/KMIP/HSM block out of an application's configuration and records the
  pointer (file + block) as the evidence. An application that merely exists and
  an appliance that merely exists produce nothing.
* **A name in a config is not an asset id.** A token label that matches no
  discovered appliance is reported ``UNRESOLVED`` — the estate has a dependency
  on something it has not discovered, which is a finding, not an edge to
  pretend away. A label two appliances both claim is ``AMBIGUOUS`` and is
  refused outright: guessing which HSM an application uses is how a blast
  radius becomes fiction.
* **Capability is not a relationship between two assets.** ``SUPPORTS`` links an
  appliance to an algorithm, so it is modelled as
  :class:`CapabilitySupport` rather than squeezed into ``HardwareEdge`` (whose
  second end is always hardware). Folding an algorithm name into the hardware
  column would have made ``blast_radius`` treat RSA-3072 as a device.

Every record here carries an ``evidence_id`` from
:class:`~universal_vendor.hardware.relationships.Evidence`, so the console and
the BOM documents can point at the record instead of the claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from universal_vendor.hardware.relationships import (
    Evidence,
    HardwareEdge,
    UnevidencedRelationship,
    derive_edges,
)

SCHEMA = "cryptoscan.hardware-usage-graph/1"

RESOLVED, UNRESOLVED, AMBIGUOUS = "RESOLVED", "UNRESOLVED", "AMBIGUOUS"

#: Algorithm families this module recognises for the ``SUPPORTS`` projection. The
#: list is a *classification*, not an allowlist: an algorithm outside it is still
#: reported, with ``family="other"``, because an unknown ML-* name from a new
#: firmware is a fact worth keeping.
PQC_PREFIXES = ("ML-", "SLH-DSA", "SPHINCS", "FN-DSA", "FALCON", "KYBER", "DILITHIUM",
                "XMSS", "LMS", "HSS")

_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("RSA", ("RSA", "RSASSA", "RSAES", "PS256", "PS384", "PS512")),
    ("ECDSA", ("ECDSA", "EC-", "P-256", "P-384", "P-521", "SECP")),
    ("EdDSA", ("ED25519", "ED448")),
    ("AES", ("AES",)),
    ("SHA", ("SHA",)),
    ("HMAC", ("HMAC",)),
)


class AmbiguousUsage(ValueError):
    """A config names a label that more than one appliance claims."""


class UsageRejected(ValueError):
    """A usage record was requested that the evidence does not support."""


def algorithm_family(name: str) -> str:
    upper = (name or "").upper()
    if any(upper.startswith(prefix.upper()) for prefix in PQC_PREFIXES):
        return "PQC"
    for family, prefixes in _FAMILIES:
        if any(upper.startswith(prefix.upper()) for prefix in prefixes):
            return family
    return "other"


def is_pqc(name: str) -> bool:
    return algorithm_family(name) == "PQC"


@dataclass(frozen=True)
class CapabilitySupport:
    """``hardware —SUPPORTS→ algorithm``, evidenced by the observation that named it."""

    hardware: str
    algorithm: str
    evidence: tuple[Evidence, ...]

    def __post_init__(self) -> None:
        if not self.algorithm.strip():
            raise UsageRejected("a capability needs an algorithm")
        if not self.evidence:
            raise UnevidencedRelationship(
                f"refusing to claim {self.hardware} supports {self.algorithm}: no evidence")

    @property
    def family(self) -> str:
        return algorithm_family(self.algorithm)

    @property
    def pqc(self) -> bool:
        return self.family == "PQC"

    @property
    def confidence(self) -> str:
        order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return min((item.confidence for item in self.evidence),
                   key=lambda level: order[level])

    def to_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "kind": "SUPPORTS", "hardware": self.hardware,
                "algorithm": self.algorithm, "family": self.family, "pqc": self.pqc,
                "confidence": self.confidence,
                "evidence": [item.to_dict() for item in self.evidence]}


@dataclass
class UsageEdge:
    """One ``application —USES_HSM→ hardware`` claim and how well it resolves.

    ``hardware_id`` is filled in when the name a config used (a token label) maps
    to exactly one discovered asset: the config says ``PAYMENTS01``, the estate
    calls it ``HSM-01``, and the edge should carry the identity the rest of the
    twin uses.
    """

    edge: HardwareEdge
    resolution: str = RESOLVED
    candidates: tuple[str, ...] = ()
    hardware_id: str | None = None

    def __post_init__(self) -> None:
        if self.resolution not in {RESOLVED, UNRESOLVED, AMBIGUOUS}:
            raise UsageRejected(f"{self.resolution!r} is not a usage resolution")
        if self.resolution == AMBIGUOUS and len(self.candidates) < 2:
            raise UsageRejected("an ambiguous usage needs at least two candidates")

    def to_dict(self) -> dict[str, Any]:
        payload = self.edge.to_dict()
        payload.update({"resolution": self.resolution,
                        "candidates": list(self.candidates),
                        "resolved_hardware": self.hardware_id})
        return payload


def resolve_usage(edges: Iterable[HardwareEdge],
                  known_hardware: Iterable[str], *,
                  labels: Mapping[str, Sequence[str]] | None = None) -> list[UsageEdge]:
    """Sort each derived edge into RESOLVED / UNRESOLVED / AMBIGUOUS.

    ``labels`` maps a name an application uses — a PKCS#11 token label, a DNS name
    — to the asset id(s) carrying it; a name absent from ``labels`` is looked up
    as an asset id itself.

    Ambiguity is a *refusal*, not a coin flip: an application whose config names
    ``PAYMENTS01`` while two appliances both carry that label is not evidence for
    either, and an edge to the wrong HSM is worse than an honest hole in the
    graph.
    """
    known = {str(name) for name in known_hardware}
    by_label: dict[str, list[str]] = {}
    for label, assets in (labels or {}).items():
        by_label[label.lower()] = [str(asset) for asset in assets]
    for name in known:
        by_label.setdefault(name.lower(), []).append(name)
    resolved: list[UsageEdge] = []
    for edge in edges:
        matches = sorted(set(by_label.get(edge.hardware.lower(), [])))
        if len(matches) > 1:
            resolved.append(UsageEdge(edge, AMBIGUOUS, tuple(matches)))
        elif matches:
            resolved.append(UsageEdge(edge, RESOLVED, tuple(matches),
                                      hardware_id=matches[0]))
        else:
            resolved.append(UsageEdge(edge, UNRESOLVED, ()))
    return resolved


@dataclass
class UsageGraph:
    """Applications, their evidenced appliance use, and what the appliances can do."""

    edges: list[UsageEdge] = field(default_factory=list)
    capabilities: list[CapabilitySupport] = field(default_factory=list)
    hardware: list[str] = field(default_factory=list)

    def add_edges(self, edges: Iterable[UsageEdge]) -> None:
        self.edges.extend(edges)

    def add_capabilities(self, capabilities: Iterable[CapabilitySupport]) -> None:
        self.capabilities.extend(capabilities)

    # -- the review's two views ------------------------------------------- #

    def resolved_edges(self) -> list[HardwareEdge]:
        """The edges with their hardware rewritten to the resolved asset id.

        A config names ``PAYMENTS01``; the estate calls the appliance ``HSM-01``.
        Anything that walks the graph afterwards — blast radius, business impact —
        must see the id the rest of the twin uses, or it will look for an asset
        called after a token label and find nothing.
        """
        edges: list[HardwareEdge] = []
        for item in self.edges:
            if item.resolution != RESOLVED or not item.hardware_id:
                continue
            edges.append(HardwareEdge(subject=item.edge.subject,
                                      hardware=item.hardware_id,
                                      kind=item.edge.kind,
                                      evidence=item.edge.evidence))
        return edges

    def used_by(self, hardware: str) -> list[dict[str, Any]]:
        """``HSM-01 —USED_BY→ [Payment API, Card Authorization]``.

        Only RESOLVED edges appear. An unresolved claim is listed separately by
        :meth:`unresolved`, because "an application depends on something we have
        not discovered" is a finding an operator needs, and it is not the same
        finding as "these applications use this appliance".
        """
        return [{"application": item.edge.subject, "confidence": item.edge.confidence,
                 "kind": item.edge.kind,
                 "named_in_config_as": item.edge.hardware,
                 "evidence_ids": [evidence.evidence_id
                                  for evidence in item.edge.evidence]}
                for item in self.edges
                if item.resolution == RESOLVED
                and (item.hardware_id or item.edge.hardware).lower() == hardware.lower()]

    def supports(self, hardware: str) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.capabilities
                if item.hardware.lower() == hardware.lower()]

    def unresolved(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.edges if item.resolution != RESOLVED]

    def of_application(self, application: str) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.edges
                if item.edge.subject.lower() == application.lower()]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "hardware": list(self.hardware),
            "usage": [item.to_dict() for item in self.edges],
            "capabilities": [item.to_dict() for item in self.capabilities],
            "resolved": sum(1 for item in self.edges if item.resolution == RESOLVED),
            "unresolved": sum(1 for item in self.edges if item.resolution == UNRESOLVED),
            "ambiguous": sum(1 for item in self.edges if item.resolution == AMBIGUOUS),
        }


def edges_from_config(application: str, *, reference: str, text: str) -> list[HardwareEdge]:
    """Read one application's configuration into evidenced usage edges."""
    return derive_edges(application, config_text=text, config_reference=reference)


def capabilities_from_observation(hardware: str, observation: Mapping[str, Any], *,
                                  reference: str) -> list[CapabilitySupport]:
    """The ``SUPPORTS`` links implied by one HSM observation.

    ``observation`` is the shape the HSM scanner already produces
    (``supported_algorithms``, ``pqc_algorithms``). Duplicates across the two
    fields are collapsed: an appliance that lists ML-DSA in both is one
    capability, not two.
    """
    algorithms: list[str] = []
    for name in list(observation.get("supported_algorithms") or []) + \
            list(observation.get("pqc_algorithms") or []):
        text = str(name).strip()
        if text and text not in algorithms:
            algorithms.append(text)
    if not algorithms:
        return []
    evidence = Evidence("CONFIG", reference) if not reference else Evidence(
        "OBSERVED" if str(reference).startswith("observed:") else "CONFIG", reference)
    return [CapabilitySupport(hardware=hardware, algorithm=name, evidence=(evidence,))
            for name in algorithms]


def build_graph(*, applications: Sequence[tuple[str, str, str]],
                hardware: Mapping[str, Mapping[str, Any]],
                observations: Mapping[str, Mapping[str, Any]] | None = None,
                labels: Mapping[str, Sequence[str]] | None = None,
                observation_reference: Callable[[str], str] | None = None) -> UsageGraph:
    """Assemble the graph from configs and observations.

    ``applications`` is ``(application, config_reference, config_text)``;
    ``hardware`` is ``{asset_id: observation}`` from the HSM scanner.
    """
    graph = UsageGraph(hardware=sorted(hardware))
    derived: list[HardwareEdge] = []
    for application, reference, text in applications:
        derived.extend(edges_from_config(application, reference=reference, text=text))
    graph.add_edges(resolve_usage(derived, hardware, labels=labels))
    for asset_id, observation in (observations or {}).items():
        reference = (observation_reference or (lambda name: f"observed:{name}"))(asset_id)
        graph.add_capabilities(
            capabilities_from_observation(asset_id, observation, reference=reference))
    return graph
