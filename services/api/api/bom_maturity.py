"""Six BOMs, one projection engine, six different depths — stated per BOM.

The projection architecture is the same for all six: every BOM is a view of one
evidence graph stamped with one ``projection_id``. What is **not** the same is how
much evidence sits behind each view. CBOM and SBOM are fed by collectors that
read a source of truth; HBOM and VBOM depend on planes most estates do not
connect (HSM/KMIP, vendor declarations), so on a real estate they are thinner
for a structural reason, not because anything is broken.

This module turns that into a measured answer instead of a vibe:

``depth``
    the strongest evidence class behind the BOM's components, computed from the
    graph — never a percentage:

    ``OBSERVED``        at least one component rests on runtime/network/audit observation
    ``CONFIGURED``      strongest is configuration, static parse or certificate metadata
    ``DECLARED_ONLY``   only vendor declarations or imported records back it
    ``UNBACKED``        components exist and none of them cites an evidence record
    ``EMPTY``           the projection has no components for this estate

``ceiling``
    the deepest class this projection can *ever* reach given what it consumes,
    declared here from reading the projector. VBOM consuming
    ``VENDOR_DECLARED`` cannot reach ``OBSERVED`` no matter how good the estate
    is, and saying so is the difference between a maturity statement and a bug
    report.

``observed`` / ``unbacked`` counts are measured from the projection's own
components and its evidence ids — the same numbers the BOM export shows, so a
reader can reconcile the two screens.

No percentage, no score, and no ordering that implies "quality". A BOM that is
``EMPTY`` on a fresh install is empty, not failing.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

SCHEMA = "cryptoscan.bom-maturity/1"

OBSERVED = "OBSERVED"
CONFIGURED = "CONFIGURED"
DECLARED_ONLY = "DECLARED_ONLY"
UNBACKED = "UNBACKED"
EMPTY = "EMPTY"

#: strongest → weakest
DEPTHS: tuple[str, ...] = (OBSERVED, CONFIGURED, DECLARED_ONLY, UNBACKED, EMPTY)

DEPTH_MEANING: dict[str, str] = {
    OBSERVED: "at least one component rests on runtime, network or audit observation",
    CONFIGURED: "the strongest support is configuration, a static parse or certificate metadata",
    DECLARED_ONLY: "only vendor declarations or imported records support these components",
    UNBACKED: "components exist but none cites an evidence record",
    EMPTY: "this projection holds no components for this estate",
}

#: evidence type → the depth it can support on its own
_EVIDENCE_DEPTH: dict[str, str] = {
    "RUNTIME_OBSERVED": OBSERVED,
    "NETWORK_ACTIVE_OBSERVED": OBSERVED,
    "NETWORK_PASSIVE_OBSERVED": OBSERVED,
    "AUDIT_OBSERVED": OBSERVED,
    "CERTIFICATE_OBSERVED": CONFIGURED,
    "STATIC_OBSERVED": CONFIGURED,
    "CONFIGURED": CONFIGURED,
    "VENDOR_DECLARED": DECLARED_ONLY,
    "IMPORTED": DECLARED_ONLY,
    "INFERRED": DECLARED_ONLY,
    "UNKNOWN": UNBACKED,
}

RANK = {depth: index for index, depth in enumerate(DEPTHS)}


class BomDepth:
    """What one BOM projection consumes and the deepest class it can reach."""

    __slots__ = ("kind", "label", "consumes", "ceiling", "question", "cannot_claim")

    def __init__(
        self,
        *,
        kind: str,
        label: str,
        consumes: str,
        ceiling: str,
        question: str,
        cannot_claim: str,
    ) -> None:
        if ceiling not in DEPTHS:
            raise ValueError(f"unknown ceiling {ceiling!r}")
        self.kind = kind
        self.label = label
        self.consumes = consumes
        self.ceiling = ceiling
        self.question = question
        self.cannot_claim = cannot_claim


#: Ordered as the console shows them. The order is by how directly each BOM is
#: fed by a collector that reads a source of truth — not by a quality score.
BOMS: tuple[BomDepth, ...] = (
    BomDepth(
        kind="CBOM",
        label="Cryptography BOM",
        consumes=(
            "every crypto artefact on every plane (capability, configured, runtime-observed, "
            "network-observed) plus certificate metadata"
        ),
        ceiling=OBSERVED,
        question="what cryptographic algorithms exist, and which are actually used?",
        cannot_claim=(
            "a CBOM can reach runtime evidence — where a runtime collector runs. On hosts with no "
            "invocation instrumentation its artefacts stop at CONFIGURED, and the depth below says "
            "which of the two this estate got"
        ),
    ),
    BomDepth(
        kind="SBOM",
        label="Software BOM",
        consumes="PACKAGE, LIBRARY and IMAGE assets from static analysis, runtime process maps and image scans",
        ceiling=OBSERVED,
        question="what software is present, and which crypto libraries does it carry?",
        cannot_claim=(
            "a package list is inventory. It supports 'this library is installed', never 'this "
            "library's cipher was used' — the CBOM/runtime side is what closes that gap, and only "
            "where instrumentation runs"
        ),
    ),
    BomDepth(
        kind="TECHBOM",
        label="Technology BOM",
        consumes="SYSTEM, APPLICATION, SERVICE, HOST and platform assets from cloud, Kubernetes and CMDB planes",
        ceiling=CONFIGURED,
        question="which systems, applications and platforms make up the estate?",
        cannot_claim=(
            "it is the estate's structure. Its components are rarely crypto-bearing themselves, so "
            "it does not observe crypto even when the estate is fully instrumented"
        ),
    ),
    BomDepth(
        kind="NBOM",
        label="Network BOM",
        consumes=(
            "NETWORK_ENDPOINT, LOAD_BALANCER, API_GATEWAY, DATABASE, MESSAGE_BROKER and "
            "CLOUD_RESOURCE assets feed it; TLS probes and cloud APIs are what back them"
        ),
        ceiling=OBSERVED,
        question="what is exposed on the network, and what does it negotiate?",
        cannot_claim=(
            "the ceiling is OBSERVED but only TLS/SSH/IPsec endpoints get there. Brokers, Oracle "
            "TNS and proprietary gateways are inventoried from CMDB and never negotiated, so an "
            "NBOM row for one of those is DECLARED_ONLY however healthy the estate looks"
        ),
    ),
    BomDepth(
        kind="HBOM",
        label="Hardware BOM",
        consumes="HARDWARE, FIRMWARE and HOST assets, mostly from the HSM plane and CMDB",
        ceiling=CONFIGURED,
        question="which HSMs, firmware and physical crypto devices are in the estate?",
        cannot_claim=(
            "reachable only when the HSM/KMIP plane is configured. Without it the projection is "
            "EMPTY for a structural reason: the estate may hold HSMs that this build never asked"
        ),
    ),
    BomDepth(
        kind="VBOM",
        label="Vendor BOM",
        consumes="VENDOR assets, backed by VENDOR_DECLARED evidence and vendor questionnaires",
        ceiling=DECLARED_ONLY,
        question="what do the vendors say their products support?",
        cannot_claim=(
            "a declaration is not a fact about this estate and can never become one: VBOM's ceiling "
            "is DECLARED_ONLY by construction. A vendor with no questionnaire response is "
            "NOT_OBSERVED, not 'no crypto'"
        ),
    ),
)

BOM_INDEX = {bom.kind: bom for bom in BOMS}


def _depth_for(kind: str, projection: Mapping[str, Any], evidence_types: Mapping[str, str]) -> dict[str, Any]:
    """Measure one projection's depth from its own components."""
    components: Sequence[Mapping[str, Any]] = projection.get("components") or []  # type: ignore[assignment]
    backing: dict[str, int] = {}
    observed = configured = declared = unbacked = 0
    for component in components:
        ids = [str(item) for item in (component.get("evidence_ids") or [])]
        depths = {
            _EVIDENCE_DEPTH.get(str(evidence_types.get(evidence_id) or "UNKNOWN"), UNBACKED)
            for evidence_id in ids
        }
        kind_of = min(depths, key=lambda item: RANK[item]) if depths else UNBACKED
        backing[kind_of] = backing.get(kind_of, 0) + 1
        if kind_of == OBSERVED:
            observed += 1
        elif kind_of == CONFIGURED:
            configured += 1
        elif kind_of == DECLARED_ONLY:
            declared += 1
        else:
            unbacked += 1

    bom = BOM_INDEX[kind]
    if not components:
        depth = EMPTY
    else:
        strongest = min(backing, key=lambda item: RANK[item])
        # A projection can never exceed what it consumes: take the weaker of the
        # measured evidence class and the declared ceiling.
        depth = strongest if RANK[strongest] >= RANK[bom.ceiling] else bom.ceiling
    return {
        "components": len(components),
        "relationships": len(projection.get("relationships") or []),
        "evidence_ids": len(projection.get("evidence_ids") or []),
        "by_component_depth": dict(sorted(backing.items())),
        "observed_components": observed,
        "configured_components": configured,
        "declared_components": declared,
        "unbacked_components": unbacked,
        "depth": depth,
    }


def measure(graph: Any) -> dict[str, Any]:
    """Depth for all six BOMs over one graph, plus the ranking it implies."""
    evidence_types = {
        str(record.get("evidence_id")): str(record.get("evidence_type") or "UNKNOWN")
        for record in graph.evidence()
    }
    projections = {kind: graph.project(kind) for kind in BOM_INDEX}
    rows: list[dict[str, Any]] = []
    for kind, bom in BOM_INDEX.items():
        measured = _depth_for(kind, projections[kind], evidence_types)
        rows.append(
            {
                "kind": kind,
                "label": bom.label,
                "question": bom.question,
                "consumes": bom.consumes,
                "ceiling": bom.ceiling,
                "ceiling_meaning": DEPTH_MEANING[bom.ceiling],
                "cannot_claim": bom.cannot_claim,
                **measured,
                "depth_meaning": DEPTH_MEANING[measured["depth"]],
                "at_ceiling": measured["depth"] == bom.ceiling,
            }
        )
    by_depth: dict[str, int] = {depth: 0 for depth in DEPTHS}
    for row in rows:
        by_depth[row["depth"]] = by_depth.get(row["depth"], 0) + 1
    ordered = sorted(rows, key=lambda row: (RANK[row["depth"]], row["kind"]))
    return {
        "schema": SCHEMA,
        "estate": graph.estate,
        "projection_id": graph.fingerprint(),
        "boms": rows,
        "depths": list(DEPTHS),
        "depth_meaning": DEPTH_MEANING,
        "rollup": {
            "boms": len(rows),
            "by_depth": by_depth,
            "observed": by_depth.get(OBSERVED, 0),
            "at_ceiling": len([row for row in rows if row["at_ceiling"]]),
        },
        "deepest": [row["kind"] for row in ordered if row["depth"] != EMPTY][:1],
        "shallowest": [row["kind"] for row in ordered if row["depth"] != EMPTY][-1:],
        "claim": (
            "all six BOMs are projections of one evidence graph; they are not equally deep, and this "
            "reports where each one stops for this estate. It is not a quality score and no "
            "percentage is computed — a BOM at its ceiling is working as designed, and a BOM that is "
            "EMPTY needs a plane, not a fix"
        ),
        "note": (
            "depth is the strongest evidence class behind a BOM's components. The ceiling is what "
            "that projection can ever reach given what it consumes: VBOM cannot become OBSERVED, "
            "and TECHBOM describes structure rather than crypto"
        ),
    }


__all__ = [
    "BOMS",
    "BOM_INDEX",
    "CONFIGURED",
    "DECLARED_ONLY",
    "DEPTHS",
    "DEPTH_MEANING",
    "EMPTY",
    "OBSERVED",
    "SCHEMA",
    "UNBACKED",
    "measure",
]
