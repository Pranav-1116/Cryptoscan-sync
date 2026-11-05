"""How this build stands against the Digital Twin specification.

``docs/DIGITAL-TWIN-SPEC.md`` is the product specification for the Digital Twin: eight
layers, twelve sections, nineteen relationship types, thirteen screens and a proposed
storage split. A specification that nobody measures against the tree rots into a wish
list — the same failure the accuracy gate exists to prevent for detectors.

So every requirement in that document is encoded here as a row with three things:

* a **status** — ``SUPPORTED``, ``PARTIAL`` or ``ABSENT``;
* a **proof** — the file, symbol or route that makes the claim checkable, never a
  sentence asserting it;
* a **gap** — what the build does *not* do, in the same words the boundary documents
  use. A row that is not ``SUPPORTED`` must carry one, and a test fails without it.

The register is data, not prose: ``GET /api/v1/estate/evidence/twin/spec-conformance``
serves exactly this document, so the specification, the console and the code cannot
disagree about what is built.

Two rules for editing it:

1. **Never promote a status without changing the code.** A row is a claim about the
   tree; if it is not demonstrable at a proof, it is ``ABSENT``.
2. **Never delete a gap because it is inconvenient.** Every enterprise scenario now has
   a model, but nine of the ten are ``PARTIAL``: the rows exist so a bank's reviewer
   finds what a partial cannot see before a pilot does.
"""

from __future__ import annotations

from typing import Any

from shared_models import estate_graph, estate_twin

SPEC_SCHEMA = "cryptoscan.digital-twin-spec-conformance/1"

#: the document this register is written against
SPEC_PATH = "docs/DIGITAL-TWIN-SPEC.md"

#: the working guide that predates it and covers the same object operationally
COMPANION_GUIDE = "docs/bank-environment/94-cryptoscan-digital-twin.md"

SUPPORTED = "SUPPORTED"
PARTIAL = "PARTIAL"
ABSENT = "ABSENT"

STATUS_MEANING: dict[str, str] = {
    SUPPORTED: "implemented, and the proof is in the tree",
    PARTIAL: "the core exists; the stated gap is real and is not planned for this build",
    ABSENT: "not implemented. Listed so it is found here rather than in a pilot",
}


def _row(
    row_id: str,
    title: str,
    status: str,
    proof: tuple[str, ...],
    gap: str = "",
    note: str = "",
) -> dict[str, Any]:
    return {
        "id": row_id,
        "title": title,
        "status": status,
        "proof": list(proof),
        "gap": gap,
        "note": note,
    }


# --------------------------------------------------------------------------- #
# §1–§12 — the twelve sections of the specification
# --------------------------------------------------------------------------- #

SECTIONS: tuple[dict[str, Any], ...] = (
    _row(
        "s1-definition", "§1 what the Digital Twin is", SUPPORTED,
        ("shared/shared_models/shared_models/estate_twin.py:TWIN_SCHEMA", "/estate/evidence/twin"),
        note=(
            "the twin is a projection of one evidence store, not a second database: "
            "every read endpoint is derived from the stored estate graph"
        ),
    ),
    _row(
        "s2-why", "§2 why the estate needs one", SUPPORTED,
        ("shared/shared_models/shared_models/estate_graph.py:RELATIONSHIP_PREDICATES", "/estate/evidence/graph"),
        note=(
            "the cross-source questions in §2 — does the payment API depend on HSM-01, "
            "which vendor supplies it, what breaks if it stops — are answered by the "
            "edge model with its basis and evidence id, not by a join of inventories"
        ),
    ),
    _row(
        "s3-pipeline", "§3 observations → twin → intelligence", SUPPORTED,
        ("shared/shared_models/shared_models/estate_graph.py:build_graph", "shared/shared_models/shared_models/estate_twin.py:snapshot"),
        note=(
            "collection → evidence validation (`fact` legality in cbom.facts) → "
            "normalisation → canonical identity → correlation → twin; a relationship "
            "without a basis is refused rather than drawn"
        ),
    ),
    _row(
        "s4-eight-layers", "§4 the eight layers", PARTIAL,
        ("shared/shared_models/shared_models/estate_twin.py:placement_model", "/estate/evidence/twin/placement"),
        gap=(
            "layer 7's expression language is bounded: conditions over one evidence record's "
            "facts plus set/unset, with no arithmetic, aggregation, cross-record join or "
            "temporal operator. A scenario needing any of those is refused rather than "
            "approximated, and network segmentation has no model at all"
        ),
    ),
    _row(
        "s5-six-boms", "§5 the six BOMs are projections of the twin", SUPPORTED,
        ("shared/shared_models/shared_models/estate_graph.py:BOM_KINDS", "/estate/evidence/boms/{kind}/export"),
        note=(
            "a test fails if a second inventory per BOM type appears; the twin is the "
            "shared model and BOMs are materialised on demand from it"
        ),
    ),
    _row(
        "s6-worked-example", "§6 the payment-API walkthrough", SUPPORTED,
        ("docs/bank-environment/05-practical-bank-walkthrough.md", "/twin/why"),
        note=(
            "the four questions in §6 (HSM failure, certificate change, library "
            "vulnerability, PQC migration) each resolve to a route: impact, compare, "
            "impact by algorithm, and the PQC scenario"
        ),
    ),
    _row(
        "s7-storage", "§7 hybrid storage (Postgres + graph + object store)", PARTIAL,
        (
            "services/database/db/models/estate_catalog.py:EstateAssetRecord",
            "services/graph_engine/graph_engine/builders/cypher_writes.py",
        ),
        gap=(
            "the twin's own graph export now covers the specification's 22 node labels — "
            "asset types, evidence types and the four placement levels that used to be "
            "asset properties only (SPEC_GRAPH_LABELS, graph_label_coverage) — and the "
            "loader writes each family under its own label with a validated kind label. "
            "What is still true: the legacy cypher_writes projection in graph_engine is a "
            "separate, narrower eight-label schema used by the older dashboards, and "
            "evidence objects are stored in PostgreSQL with content hashes rather than in "
            "a MinIO/S3 tier, with no Redis dependency — the estate graph is rebuilt in "
            "process, Redis is optional and the graph store is rebuildable"
        ),
    ),
    _row(
        "s8-update-lifecycle", "§8 the update lifecycle and asset states", SUPPORTED,
        (
            "services/cbom/cbom/cbom_dependency.py:LIFECYCLE_STATES",
            "services/api/api/routers/inventory.py:transition_asset_lifecycle",
        ),
        note=(
            "FIRST_SEEN / ACTIVE / CHANGED / SUPERSEDED / REMOVED / UNKNOWN exist for "
            "assets and edges; an asset that stops being observed is not marked removed, "
            "because a failed collector and a decommissioned host look identical"
        ),
    ),
    _row(
        "s9-ui", "§9 the thirteen investigation screens", PARTIAL,
        ("frontend/src/pages/DigitalTwin.tsx", "frontend/src/pages/EstateTwin.tsx"),
        gap=(
            "all thirteen investigations exist, but not as thirteen separate routes: the "
            "asset, relationship, crypto, network, hardware and vendor views live on their "
            "own pages and the twin page carries overview, placement, completeness and "
            "history. Selecting an edge now answers 'why' with its collector, source, "
            "timestamp and hash (and names the refusal when the edge was never "
            "established), but only from the asset investigation — there is no canvas "
            "where an edge on the drawn graph opens its evidence"
        ),
    ),
    _row(
        "s10-limits", "§10 what the twin cannot guarantee", SUPPORTED,
        ("/estate/evidence/twin/completeness", "/estate/evidence/twin/why"),
        note=(
            "every listed defect is an output: coverage, unresolved relationships, "
            "collection failures and unknown facts are counted, not hidden"
        ),
    ),
    _row(
        "s11-priorities", "§11 P0–P3 implementation order", SUPPORTED,
        ("docs/bank-environment/94-cryptoscan-digital-twin.md:Status in this repository",),
        note=(
            "P0 (canonical identity, evidence-backed relationships, Postgres record, graph "
            "projection, UNKNOWN semantics), P1 (cross-BOM correlation, history, why, "
            "blast radius) and P2 (PQC impact, threat correlation, simulation) are built; "
            "P3 scale qualification is a deployment exercise, not a code gap"
        ),
    ),
    _row(
        "s12-design-decision", "§12 the twin is not another scanner or database", SUPPORTED,
        ("shared/shared_models/shared_models/estate_twin.py:graph_from_snapshot",),
        note=(
            "the twin can be rebuilt from a stored snapshot (`graph_from_snapshot`), which "
            "is what makes it a projection rather than a system of record"
        ),
    ),
)


# --------------------------------------------------------------------------- #
# §4 — the eight layers
# --------------------------------------------------------------------------- #

LAYERS: tuple[dict[str, Any], ...] = (
    _row(
        "layer-1-estate", "Layer 1 — estate model", SUPPORTED,
        ("shared/shared_models/shared_models/estate_twin.py:ESTATE_LEVELS", "/estate/evidence/twin/placement"),
        note=(
            "BANK → ORGANIZATION → DEPARTMENT → REGION → DATA_CENTER → "
            "CLOUD_ENVIRONMENT → ENVIRONMENT → BUSINESS_SYSTEM, each derived from an "
            "asserted attribute only; an unasserted level is reported as unobserved "
            "with the reason, never filled in from the level below"
        ),
    ),
    _row(
        "layer-2-asset", "Layer 2 — asset model", SUPPORTED,
        ("shared/shared_models/shared_models/estate_graph.py:ASSET_TYPES", "services/database/db/models/estate_catalog.py:EstateAssetRecord"),
        note=(
            "32 asset types incl. CA (root/intermediate), HSM, KMS_KEY, FIRMWARE, "
            "PRODUCT, HARDWARE, NETWORK_ENDPOINT; canonical id with aliases in the "
            "identity block, first/last seen and observation count on the record"
        ),
    ),
    _row(
        "layer-3-relationship", "Layer 3 — relationship model", SUPPORTED,
        ("shared/shared_models/shared_models/estate_graph.py:RELATIONSHIP_PREDICATES", "shared/shared_models/shared_models/estate_graph.py:RELATIONSHIP_BASES"),
        note=(
            "32 predicates against the specification's 18 names (see RELATIONSHIP_MAP); "
            "every edge carries basis, evidence type, observed_at, confidence and a "
            "lifecycle state, and a use-predicate without a usage basis is refused"
        ),
    ),
    _row(
        "layer-4-crypto", "Layer 4 — cryptographic graph", SUPPORTED,
        ("/estate/evidence/twin/crypto-graph", "services/cbom/cbom/facts.py"),
        note=(
            "library capability, source reference, configuration, runtime observation and "
            "network-negotiated crypto are distinct fact classes; a capability fact can "
            "never be promoted into a usage claim"
        ),
    ),
    _row(
        "layer-5-evidence", "Layer 5 — evidence graph", SUPPORTED,
        ("/estate/evidence/twin/why", "services/database/db/models/estate_catalog.py:EstateRelationshipRecord"),
        note=(
            "evidence id, collector, evidence type, observed_at and a hash-chained record "
            "per fact; a contradiction is stored as a conflict, both sides kept"
        ),
    ),
    _row(
        "layer-6-time", "Layer 6 — time and historical twin", SUPPORTED,
        ("/estate/evidence/twin/snapshots", "/estate/evidence/twin/compare"),
        note=(
            "stored snapshots, point-in-time replay, run-to-run diffs, and a change "
            "journal per asset; a vanished asset is a coverage event before it is a "
            "removal"
        ),
    ),
    _row(
        "layer-7-simulation", "Layer 7 — simulation twin", PARTIAL,
        ("shared/shared_models/shared_models/estate_twin.py:SIMULATION_KINDS", "/estate/evidence/twin/simulate"),
        gap=(
            "eight fact-editing scenarios (seven built-in plus CUSTOM, a validated expression "
            "over one evidence record's facts) and four cascades run against a copy — the "
            "trust-path cascade walks issued_by, signed_by, verified_by, uses_certificate and "
            "terminates_tls_for, so a compromised CA reaches what it vouches for and not what "
            "merely shares a host — with the live projection id asserted unchanged. What the "
            "language still cannot express: arithmetic, aggregation, cross-record joins, "
            "ordered multi-step timelines and network segmentation. What the trust walk still "
            "cannot see: trust-store membership per host, cross-signing and alternate chains, "
            "revocation (CRL/OCSP, soft-fail) and name constraints, so its radius is a superset "
            "of a correct PKI walk"
        ),
    ),
    _row(
        "layer-8-intelligence", "Layer 8 — intelligence and impact", SUPPORTED,
        ("/estate/evidence/twin/impact", "shared/shared_models/shared_models/attack_patterns.py:correlate"),
        note=(
            "blast radius over established edges, capability blockers, adversary-pattern "
            "correlation that refuses to assign SECURITY_INCIDENT, and the PQC/agility "
            "views that consume the same graph"
        ),
    ),
)


# --------------------------------------------------------------------------- #
# §4 layer 3 — the specification's relationship vocabulary, and what it maps to
# --------------------------------------------------------------------------- #
#
# ``None`` means the build has no predicate for the name. There are none today; the
# mapping exists so that a name added to the specification tomorrow fails this test
# instead of quietly having no home.

RELATIONSHIP_MAP: dict[str, str | None] = {
    "CONTAINS": "contains",
    "RUNS_ON": "runs_on",
    "DEPENDS_ON": "depends_on",
    "USES_CRYPTO_LIBRARY": "uses_crypto_library",
    "USES_ALGORITHM": "uses_algorithm",
    "USES_CERTIFICATE": "uses_certificate",
    "USES_HSM": "uses_hsm",
    "USES_KMS": "uses_kms",
    "CONNECTS_TO": "connects_to",
    "ROUTES_TO": "routes_to",
    "TERMINATES_TLS": "terminates_tls_for",
    "RE_ENCRYPTS": "re_encrypts",
    "HOSTED_ON": "hosted_on",
    "DEPLOYED_AS": "deployed_as",
    "PROVIDED_BY": "provided_by",
    "OWNED_BY": "owned_by",
    "SIGNED_BY": "signed_by",
    "BACKED_BY": "backs_with",
}


# --------------------------------------------------------------------------- #
# §9 — the thirteen screens, and where each investigation lives today
# --------------------------------------------------------------------------- #

SCREENS: tuple[dict[str, Any], ...] = (
    {
        "id": "twin-overview", "title": "Twin Overview",
        "route": "/digital-twin", "component": "frontend/src/pages/DigitalTwin.tsx",
        "api": "/api/v1/estate/evidence/twin",
        "note": "placement, summary, completeness and the history entry point",
    },
    {
        "id": "asset-explorer", "title": "Asset Explorer",
        "route": "/assets", "component": "frontend/src/pages/Assets.tsx",
        "api": "/api/v1/estate/evidence/twin/search",
        "note": "search across the twin by name, id, alias or attribute",
    },
    {
        "id": "relationship-graph", "title": "Relationship Graph",
        "route": "/graph", "component": "frontend/src/pages/Graph.tsx",
        "api": "/api/v1/estate/evidence/twin/graph",
        "note": "the estate graph export, and the curated dependency graph",
    },
    {
        "id": "crypto-graph", "title": "Cryptographic Graph",
        "route": "/crypto", "component": "frontend/src/pages/Crypto.tsx",
        "api": "/api/v1/estate/evidence/twin/crypto-graph",
        "note": "algorithms, providers and the fact class behind each",
    },
    {
        "id": "network-topology", "title": "Network Topology",
        "route": "/network", "component": "frontend/src/pages/Network.tsx",
        "api": "/api/v1/estate/evidence/graph",
        "note": "endpoints, listeners and the edges observed on the wire",
    },
    {
        "id": "hardware-hsm", "title": "Hardware & HSM",
        "route": "/hardware", "component": "frontend/src/pages/Hardware.tsx",
        "api": "/api/v1/hbom",
        "note": "hardware fleet, firmware and PQC capability where it is declared",
    },
    {
        "id": "vendor-dependencies", "title": "Vendor Dependencies",
        "route": "/vendor", "component": "frontend/src/pages/Vendor.tsx",
        "api": "/api/v1/vbom",
        "note": "suppliers, products, declared crypto and due-diligence revisions",
    },
    {
        "id": "evidence-explorer", "title": "Evidence Explorer",
        "route": "/evidence", "component": "frontend/src/pages/Evidence.tsx",
        "api": "/api/v1/estate/evidence/twin/why",
        "note": (
            "the page browses evidence records; the per-edge question is answered by the "
            "why route and the asset drill-down, not by a dedicated edge-first screen"
        ),
    },
    {
        "id": "historical-twin", "title": "Historical Twin",
        "route": "/estate-twin", "component": "frontend/src/pages/EstateTwin.tsx",
        "api": "/api/v1/estate/evidence/twin/snapshots",
        "note": "snapshot list, compare, and replay as of a stored state",
    },
    {
        "id": "drift-analysis", "title": "Drift Analysis",
        "route": "/drift", "component": "frontend/src/pages/Drift.tsx",
        "api": "/api/v1/drift",
        "note": "approved baselines, events and the CI gate",
    },
    {
        "id": "blast-radius", "title": "Blast Radius",
        "route": "/what-if", "component": "frontend/src/pages/WhatIf.tsx",
        "api": "/api/v1/estate/evidence/twin/impact",
        "note": "impact preview and cascade over established edges only",
    },
    {
        "id": "simulation-lab", "title": "Simulation Lab",
        "route": "/simulation", "component": "frontend/src/pages/Simulation.tsx",
        "api": "/api/v1/estate/evidence/twin/simulate",
        "note": "scenarios on a copy, with the live-projection assertion surfaced",
    },
    {
        "id": "pqc-impact", "title": "PQC Impact",
        "route": "/pqc", "component": "frontend/src/pages/Pqc.tsx",
        "api": "/api/v1/estate/evidence/twin/simulate",
        "note": "quantum posture plus the MIGRATE_QUANTUM_VULNERABLE scenario",
    },
)


# --------------------------------------------------------------------------- #
# §8 — the update lifecycle the specification names
# --------------------------------------------------------------------------- #

PIPELINE_STEPS: tuple[dict[str, Any], ...] = (
    _row("discover", "1 DISCOVER", SUPPORTED, ("services/api/api/routers/collection.py",)),
    _row("validate", "2 VALIDATE", SUPPORTED, ("services/cbom/cbom/facts.py",)),
    _row("normalize", "3 NORMALIZE", SUPPORTED, ("services/normalization/normalization/",)),
    _row("identify", "4 IDENTIFY", SUPPORTED, ("shared/shared_models/shared_models/asset_identity.py", "shared/shared_models/shared_models/subject_resolution.py")),
    _row("correlate", "5 CORRELATE", SUPPORTED, ("shared/shared_models/shared_models/estate_graph.py",)),
    _row("update", "6 UPDATE", SUPPORTED, ("shared/shared_models/shared_models/estate_graph.py:build_graph",)),
    _row("project", "7 PROJECT", SUPPORTED, ("shared/shared_models/shared_models/estate_graph.py:BOM_KINDS",)),
    _row("snapshot", "8 SNAPSHOT", SUPPORTED, ("/estate/evidence/twin/snapshots",)),
    _row("monitor", "9 MONITOR", SUPPORTED, ("/estate/evidence/twin/compare",)),
    _row("analyze", "10 ANALYZE", SUPPORTED, ("/estate/evidence/twin/completeness",)),
    _row("simulate", "11 SIMULATE", SUPPORTED, ("/estate/evidence/twin/simulate",)),
)


# --------------------------------------------------------------------------- #
# §8 — asset and relationship lifecycle states
# --------------------------------------------------------------------------- #

LIFECYCLE_STATES: dict[str, str] = {
    "FIRST_SEEN": "the first observation that established the record",
    "ACTIVE": "observed and unchanged",
    "CHANGED": "observed with a different value",
    "SUPERSEDED": "replaced by a newer record; the old one is kept beside it",
    "REMOVED": "explicitly absent from a completed observation of its own plane",
    "UNKNOWN": "not observable right now. NOT proof of removal",
}


def _coverage() -> dict[str, Any]:
    predicates = set(estate_graph.RELATIONSHIP_PREDICATES)
    mapped = {name: pred for name, pred in RELATIONSHIP_MAP.items() if pred}
    unmapped = [name for name, pred in RELATIONSHIP_MAP.items() if not pred]
    missing_predicates = sorted({pred for pred in mapped.values()} - predicates)
    statuses = {SUPPORTED: 0, PARTIAL: 0, ABSENT: 0}
    for row in (*SECTIONS, *LAYERS):
        statuses[row["status"]] += 1
    return {
        "relationship_types_in_spec": len(RELATIONSHIP_MAP),
        "relationship_types_mapped": len(mapped),
        "relationship_types_unmapped": unmapped,
        "mapped_predicates_missing_from_build": missing_predicates,
        "predicates_in_build": len(estate_graph.RELATIONSHIP_PREDICATES),
        "sections": statuses,
        "screens": len(SCREENS),
        "pipeline_steps": len(PIPELINE_STEPS),
        "simulation_kinds": len(estate_twin.SIMULATION_KINDS),
    }


def conformance() -> dict[str, Any]:
    """The specification, the tree's answer, and every gap between them.

    Deterministic and read-only: no clock, no database, no request context. Two calls
    against the same checkout return the same document, which is what makes it usable
    as a release artefact rather than a status page.
    """
    coverage = _coverage()
    gaps = [
        {"id": row["id"], "title": row["title"], "status": row["status"], "gap": row["gap"]}
        for row in (*SECTIONS, *LAYERS)
        if row["status"] != SUPPORTED
    ]
    return {
        "schema": SPEC_SCHEMA,
        "spec": SPEC_PATH,
        "companion": COMPANION_GUIDE,
        "statuses": dict(STATUS_MEANING),
        "coverage": coverage,
        "sections": [dict(row) for row in SECTIONS],
        "layers": [dict(row) for row in LAYERS],
        "relationships": {
            "spec_vocabulary": dict(RELATIONSHIP_MAP),
            "build_vocabulary": list(estate_graph.RELATIONSHIP_PREDICATES),
            "bases": list(estate_graph.RELATIONSHIP_BASES),
        },
        "screens": [dict(row) for row in SCREENS],
        "pipeline": [dict(row) for row in PIPELINE_STEPS],
        "lifecycle": dict(LIFECYCLE_STATES),
        "gaps": gaps,
        "note": (
            "this is a conformance register, not a score. A PARTIAL row is a deliberate "
            "boundary with a stated cost, and an ABSENT row is listed so that it is found "
            "here rather than in a pilot"
        ),
    }


__all__ = [
    "ABSENT",
    "COMPANION_GUIDE",
    "LAYERS",
    "LIFECYCLE_STATES",
    "PARTIAL",
    "PIPELINE_STEPS",
    "RELATIONSHIP_MAP",
    "SCREENS",
    "SECTIONS",
    "SPEC_PATH",
    "SPEC_SCHEMA",
    "STATUS_MEANING",
    "SUPPORTED",
    "conformance",
]
