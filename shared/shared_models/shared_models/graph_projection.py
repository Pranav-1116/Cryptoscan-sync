"""Rebuildable graph projection contract (gap analysis §C).

"Keep Neo4j rebuildable from authoritative evidence. The database stores
unique identifiers, evidence links and mapping results."
Acceptance: "Rebuilding Neo4j from authoritative records produces the same
logical graph."

A projection is built from authoritative rows — each node carries its unique
identifier, its evidence links and its mapping results; each edge carries
its evidence links. Rebuilding from the same rows in any order, with any
duplicates, produces the identical logical graph (digest equality via
:func:`same_logical_graph`). House rules enforced here:

- a row with no unique identifier is refused — an unidentifiable row cannot
  be a graph node;
- a relationship missing either end is refused;
- an edge with no evidence links is flagged ``UNKNOWN`` provenance and is
  never reported as proven: "every graph relationship should have evidence
  behind it".
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping

PROJECTION_SCHEMA = "cryptoscan.graph-projection/1"

PROVEN = "PROVEN"
UNKNOWN = "UNKNOWN"

EDGE_PROVENANCE = frozenset({PROVEN, UNKNOWN})


def _ids(values: Iterable[Any]) -> list[str]:
    return sorted({str(v) for v in values if str(v).strip()})


def build_projection(*, assets: Iterable[Mapping[str, Any]],
                     relationships: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Build the logical graph from authoritative rows.

    Nodes are keyed by their unique identifier (``identifier``). Duplicate
    rows collapse and their evidence unions — a re-read of the same
    authoritative store is never a bigger graph. Edges with evidence are
    PROVEN; edges without are UNKNOWN, never silently proven.
    """
    nodes: dict[str, dict[str, Any]] = {}
    duplicates = 0
    for row in assets:
        identifier = str(row.get("identifier") or "").strip()
        if not identifier:
            raise ValueError(
                "a graph node needs a unique identifier: an unidentifiable "
                "row cannot be a node")
        if identifier in nodes:
            duplicates += 1
        entry = nodes.setdefault(identifier, {
            "identifier": identifier,
            "evidence_ids": set(),
            "mapping_results": {},
        })
        entry["evidence_ids"] |= set(_ids(row.get("evidence_ids") or []))
        mapping = row.get("mapping_results") or {}
        if not isinstance(mapping, dict):
            raise ValueError(f"mapping_results for {identifier!r} must be a dict")
        entry["mapping_results"].update(mapping)

    edges: dict[tuple, dict[str, Any]] = {}
    for row in relationships:
        subject = str(row.get("subject") or "").strip()
        predicate = str(row.get("predicate") or "").strip()
        obj = str(row.get("object") or "").strip()
        if not (subject and predicate and obj):
            raise ValueError(
                "a relationship needs subject, predicate and object: an edge "
                "with a missing end is not a relationship")
        key = (subject, predicate, obj)
        if key in edges:
            duplicates += 1
        entry = edges.setdefault(key, {
            "subject": subject, "predicate": predicate, "object": obj,
            "evidence_ids": set(),
        })
        entry["evidence_ids"] |= set(_ids(row.get("evidence_ids") or []))

    def _materialise_nodes() -> list[dict[str, Any]]:
        out = []
        for entry in nodes.values():
            row = dict(entry)
            row["evidence_ids"] = sorted(row["evidence_ids"])
            out.append(row)
        return sorted(out, key=lambda r: r["identifier"])

    def _materialise_edges() -> list[dict[str, Any]]:
        out = []
        for entry in edges.values():
            row = dict(entry)
            row["evidence_ids"] = sorted(row["evidence_ids"])
            row["provenance"] = PROVEN if row["evidence_ids"] else UNKNOWN
            out.append(row)
        return sorted(out, key=lambda r: json.dumps(
            (r["subject"], r["predicate"], r["object"]), sort_keys=True))

    nodes_out = _materialise_nodes()
    edges_out = _materialise_edges()
    material = json.dumps(
        {"nodes": nodes_out, "edges": edges_out, "version": PROJECTION_SCHEMA},
        sort_keys=True, default=str).encode()
    return {
        "schema": PROJECTION_SCHEMA,
        "nodes": nodes_out,
        "edges": edges_out,
        "node_count": len(nodes_out),
        "edge_count": len(edges_out),
        "duplicates_collapsed": duplicates,
        "unproven_edges": sum(1 for row in edges_out if row["provenance"] == UNKNOWN),
        "graph_digest": "sha256:" + hashlib.sha256(material).hexdigest(),
        "note": ("rebuilding from the same authoritative rows reproduces "
                 "this digest; an edge without evidence links is UNKNOWN "
                 "provenance, never proven"),
    }


def same_logical_graph(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    """Two projections are the same logical graph iff their digests match."""
    return bool(a.get("graph_digest")) and a.get("graph_digest") == b.get("graph_digest")
