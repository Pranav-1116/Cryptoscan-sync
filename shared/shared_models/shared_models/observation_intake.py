"""Observation intake and projection rebuild (gap analysis §C acceptance).

Two database acceptance rows, kept as pure functions so they can be proved:

* "Duplicate observations do not create duplicate assets or relationships."
  — intake canonicalises each observation's identity and collapses repeats,
  counting what it collapsed. A re-run of the same collector run is not new
  estate.

* "Rebuilding Neo4j from authoritative records produces the same logical
  graph." — :func:`rebuild_projection` digests the logical graph (vertices and
  edges, order-insensitive) so a rebuild from the same authoritative rows —
  in any order, with duplicates removed — produces the same graph digest.

The graph digest is a *reproducibility* proof, not an authenticity one: it
says two rebuilds agree, not that the rows are true.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping

INTAKE_SCHEMA = "cryptoscan.observation-intake/1"
PROJECTION_VERSION = "projection/1"


def _clean_ids(values: Iterable[Any]) -> list[str]:
    return sorted({str(v) for v in values if str(v).strip()})


def _asset_key(observation: Mapping[str, Any]) -> tuple:
    """Canonical identity for an asset observation.

    Identity is (asset_id) when the source names one, else the content key
    (plane, type, locator). Two observations of the same asset collapse.
    """
    asset_id = str(observation.get("asset_id") or "").strip()
    if asset_id:
        return ("id", asset_id)
    return ("content",
            str(observation.get("plane") or ""),
            str(observation.get("asset_type") or ""),
            str(observation.get("locator") or ""))


def _relationship_key(row: Mapping[str, Any]) -> tuple:
    return (str(row.get("subject") or ""), str(row.get("predicate") or ""),
            str(row.get("object") or ""))


def ingest_observations(
        observations: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Collapse duplicate observations into unique assets and relationships.

    Repeats are not errors and not estate: they are merged, their evidence
    unioned, and counted in ``duplicates_collapsed``. An observation with no
    identity at all (no asset_id and no locator) is refused — an unplaceable
    observation is not a fact about anything.
    """
    rows = [dict(o) for o in observations]
    assets: dict[tuple, dict[str, Any]] = {}
    relationships: dict[tuple, dict[str, Any]] = {}
    duplicates = 0

    for row in rows:
        if row.get("kind") == "relationship":
            key = _relationship_key(row)
            if not all(key):
                raise ValueError(
                    "a relationship observation needs subject, predicate and "
                    "object: an edge with a missing end is not a relationship")
            entry = relationships.setdefault(key, {
                "subject": key[0], "predicate": key[1], "object": key[2],
                "evidence_ids": set(), "observations": 0,
            })
            entry["observations"] += 1
            if entry["observations"] > 1:
                duplicates += 1
            entry["evidence_ids"] |= {str(e) for e in
                                      (row.get("evidence_ids") or [])
                                      if str(e).strip()}
            continue

        key = _asset_key(row)
        if key[0] == "content" and not key[3]:
            raise ValueError(
                "an observation needs an asset_id or a locator: an "
                "unplaceable observation is not a fact about anything")
        entry = assets.setdefault(key, {
            "asset_id": row.get("asset_id") or None,
            "plane": row.get("plane"), "asset_type": row.get("asset_type"),
            "locator": row.get("locator"),
            "evidence_ids": set(), "observations": 0,
        })
        entry["observations"] += 1
        if entry["observations"] > 1:
            duplicates += 1
        entry["evidence_ids"] |= {str(e) for e in
                                  (row.get("evidence_ids") or [])
                                  if str(e).strip()}

    def _materialise(entries: dict) -> list[dict[str, Any]]:
        out = []
        for entry in entries.values():
            row = dict(entry)
            row["evidence_ids"] = sorted(row["evidence_ids"])
            out.append(row)
        return sorted(out, key=lambda r: json.dumps(r, sort_keys=True,
                                                    default=str))

    return {
        "schema": INTAKE_SCHEMA,
        "assets": _materialise(assets),
        "relationships": _materialise(relationships),
        "duplicates_collapsed": duplicates,
        "note": ("duplicate observations collapse into one asset or "
                 "relationship with their evidence unioned: a re-run is not "
                 "new estate"),
    }


def rebuild_projection(
        intake: Mapping[str, Any]) -> dict[str, Any]:
    """The logical graph digest of an intake result — order-insensitive.

    Rebuild the projection from the same authoritative rows and the digest
    matches; feed it a different estate and it does not.
    """
    def _strip(row: Mapping[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in row.items() if k != "observations"}

    def _order(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        return sorted((_strip(r) for r in rows),
                      key=lambda v: json.dumps(v, sort_keys=True, default=str))

    vertices = _order(intake.get("assets", []))
    edges = _order(intake.get("relationships", []))
    material = json.dumps({"vertices": vertices, "edges": edges,
                           "version": PROJECTION_VERSION},
                          sort_keys=True, default=str).encode()
    return {
        "schema": INTAKE_SCHEMA,
        "projection_version": PROJECTION_VERSION,
        "vertex_count": len(vertices),
        "edge_count": len(edges),
        "graph_digest": "sha256:" + hashlib.sha256(material).hexdigest(),
        "note": ("the graph digest proves two rebuilds agree on the logical "
                 "graph; it does not prove the rows are true"),
    }
