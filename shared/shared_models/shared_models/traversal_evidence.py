"""Bounded witness explanations. Evidence pointers are not verified observations.

One deterministic minimum-hop witness per destination, not all possible paths.
Counts/classification are owned by callers and must never be inferred from a
bounded explanation list. No path confidence or failure probability is invented.
"""

from __future__ import annotations
from collections import defaultdict, deque
from copy import deepcopy
from datetime import datetime
import json
from typing import Mapping
from shared_models.dependency_semantics import edge_relation, propagates, system_id
from shared_models.relationship_lifecycle import effective_state, current, possible, lifecycle_payload, utc

SCHEMA = "cryptoscan.traversal-evidence/1"
MAX_WITNESSES = 500
PROVENANCE = ("OBSERVED", "DECLARED", "SCANNER_DERIVED", "INFERRED", "UNATTRIBUTED")
METADATA_FIELDS = (
    "provenance",
    "source",
    "evidence_ref",
    "evidence_refs",
    "confidence",
    "confidence_meaning",
    "observed_at",
    "last_verified",
    "created_by",
    "assertion_source",
    "role",
    "evidence_refs_total",
    "evidence_refs_truncated",
)


def provenance(value):
    text = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    return text if text in PROVENANCE else "UNATTRIBUTED"


def metadata(row):
    if row.get("evidence_refs_json") is not None and "evidence_refs" not in row:
        row = dict(row)
        try:
            decoded = json.loads(row["evidence_refs_json"])
            if isinstance(decoded, list):
                row["evidence_refs"] = decoded
        except (ValueError, TypeError):
            pass  # missing/invalid references remain an explicit evidence gap
    return {
        key: value.isoformat() if isinstance(value, datetime) else deepcopy(value)
        for key in METADATA_FIELDS
        if (value := row.get(key)) is not None
    }


def system_dependency_metadata(row):
    """Persisted origin, NOT verification of its truth or runtime behavior."""
    source = getattr(row, "source", None)
    return {
        "provenance": {"manual": "DECLARED", "imported": "DECLARED", "discovered": "SCANNER_DERIVED"}.get(
            source, "UNATTRIBUTED"
        ),
        "relationship_source": source,
        "evidence_ref": getattr(row, "evidence_ref", None),
        "confidence": getattr(row, "confidence", None),
        "confidence_meaning": getattr(row, "confidence_meaning", None),
        "created_by": getattr(row, "created_by", None),
        "last_verified": row.last_verified.isoformat() if getattr(row, "last_verified", None) else None,
    }


def timestamp(value, now):
    if value is None:
        return {"value": None, "status": "MISSING", "age_seconds": None}
    try:
        instant = utc(value)
        age = (utc(now) - instant).total_seconds()
        return {
            "value": instant.isoformat(),
            "status": "FUTURE" if age < 0 else "DATED",
            "age_seconds": age if age >= 0 else None,
        }
    except (ValueError, TypeError, OverflowError):
        return {"value": str(value), "status": "INVALID", "age_seconds": None}


def edge_evidence(row: Mapping, *, now):
    props = {**metadata(row), **lifecycle_payload(row)}
    # IDs remain oriented consumer -> provider, even for upstream witnesses.
    src, dst = str(row.get("from") or ""), str(row.get("to") or "")
    refs = []
    for key in ("evidence_ref", "lifecycle_evidence_ref"):
        if row.get(key) is not None and row[key] not in refs:
            refs.append(deepcopy(row[key]))
    raw = props.get("evidence_refs") or []
    if isinstance(raw, list):
        for ref in raw[:50]:
            if ref not in refs:
                refs.append(deepcopy(ref))
    refs_truncated = (
        len(refs) > 50 or isinstance(raw, list) and len(raw) > 50 or bool(props.get("evidence_refs_truncated"))
    )
    props.pop("evidence_refs", None)  # never duplicate the unbounded raw reference array
    props.pop("evidence_refs_total", None)
    props.pop("evidence_refs_truncated", None)
    state = effective_state(row, now=now)
    props.setdefault("lifecycle_state", "ACTIVE")
    props.setdefault("projection_state", "ACTIVE")
    return {
        "from": src,
        "to": dst,
        "relation": edge_relation(row),
        **props,
        "identity": {
            k: row[k]
            for k in (
                "artifact_id",
                "digest",
                "sbom_artifact_id",
                "sbom_sha256",
                "deployment_key",
                "environment",
                "identity_source",
                "artifact_evidence_ref",
                "byte_count",
            )
            if row.get(k) is not None
        },
        "provenance": provenance(row.get("provenance")),
        "evidence_references": refs[:50],
        "references_truncated": refs_truncated,
        "evidence_missing": not refs,
        "references_verified_by_traversal": False,
        "confidence_meaning": row.get("confidence_meaning") or "unspecified; not a failure probability",
        "freshness": {
            "as_of": utc(now).isoformat(),
            "eligibility": state,
            "validity": "UNBOUNDED" if row.get("valid_until") is None else "DEADLINE_SUPPLIED",
            "observation": timestamp(row.get("observed_at"), now),
            "confirmation": timestamp(row.get("last_confirmed_at"), now),
            "verification_timestamp": timestamp(row.get("last_verified"), now),
            "note": "A deadline or recent confirmation does not turn a declaration into observed runtime use.",
        },
    }


def path_evidence(nodes, edges, *, now, direction="downstream", scope="current"):
    edges = [edge_evidence(e, now=now) for e in edges]
    classes = sorted({e["provenance"] for e in edges})
    valid = len(nodes) == len(edges) + 1
    for index, edge in enumerate(edges):
        if index + 1 >= len(nodes):
            edge["walk_direction"] = "INVALID"
            valid = False
            continue
        forward = (edge["from"], edge["to"]) == (str(nodes[index]), str(nodes[index + 1]))
        backward = (edge["to"], edge["from"]) == (str(nodes[index]), str(nodes[index + 1]))
        edge["walk_direction"] = "downstream" if forward else "upstream" if backward else "INVALID"
        valid = valid and (
            backward if direction == "upstream" else forward or backward if direction == "mixed" else forward
        )
    return {
        "schema": SCHEMA,
        "available": bool(nodes) and valid,
        "nodes": list(nodes),
        "edges": edges,
        "hops": len(edges),
        "direction": direction,
        "scope": scope,
        "provenance_classes": classes,
        "mixed_provenance": len(classes) > 1,
        "evidence_gap_count": sum(e["evidence_missing"] for e in edges),
        "unbounded_edge_count": sum(e["freshness"]["validity"] == "UNBOUNDED" for e in edges),
        "note": "One modeled witness; per-edge evidence only. No aggregate confidence, runtime-failure or all-paths claim.",
    }


def edge_key(edge):
    return (
        str(edge.get("to")),
        edge_relation(edge),
        str(edge.get("record_id") or edge.get("id") or ""),
        str(edge.get("source") or ""),
        json.dumps(metadata(edge), sort_keys=True, default=str),
    )


def walk_paths(
    edges,
    seeds,
    *,
    known,
    now,
    hops=12,
    reverse=False,
    potential=False,
    targets=None,
    limit=MAX_WITNESSES,
    system_policy=True,
):
    """Canonical System edges only; preserving physical orientation in a path."""
    known = set(known)
    seeds = sorted(set(seeds) & known)
    adjacency = defaultdict(list)
    for edge in edges:
        src, dst = edge.get("from"), edge.get("to")
        if src not in known or dst not in known or (system_policy and not propagates(edge_relation(edge))):
            continue
        if not (possible(edge, now=now) if potential else current(edge, now=now)):
            continue
        adjacency[dst if reverse else src].append(edge)
    for values in adjacency.values():
        values.sort(key=lambda e: (str(e["from"] if reverse else e["to"]), edge_key(e)))
    parent = {seed: None for seed in seeds}
    depths = {seed: 0 for seed in seeds}
    queue = deque(seeds)
    while queue:
        node = queue.popleft()
        if depths[node] >= min(12, hops):
            continue
        for edge in adjacency[node]:
            nxt = edge["from"] if reverse else edge["to"]
            if nxt in parent:
                continue
            parent[nxt] = (node, edge)
            depths[nxt] = depths[node] + 1
            queue.append(nxt)
    wanted = set(targets) if targets is not None else set(parent) - set(seeds)
    result = {}
    for target in sorted(wanted)[:limit]:
        if target not in parent:
            continue
        nodes, links = [target], []
        while parent[nodes[-1]] is not None:
            previous, edge = parent[nodes[-1]]
            nodes.append(previous)
            links.append(edge)
        result[target] = path_evidence(
            list(reversed(nodes)),
            list(reversed(links)),
            now=now,
            direction="upstream" if reverse else "downstream",
            scope="potential" if potential else "current",
        )
    return result


def envelope(paths, requested, *, now, limit=MAX_WITNESSES):
    requested = sorted(set(requested))
    selected = requested[:limit]
    rows = [{"system_id": sid, **paths[sid]} for sid in selected if sid in paths]
    missing = [sid for sid in selected if sid not in paths or not paths[sid].get("available")]
    return {
        "schema": SCHEMA,
        "as_of": utc(now).isoformat(),
        "paths": rows,
        "requested_count": len(requested),
        "returned_count": len(rows),
        "limit": limit,
        "missing_witness_count": len(missing),
        "missing_system_ids": missing[:200],
        "missing_system_ids_truncated": len(missing) > 200,
        "truncated": len(requested) > limit,
        "complete_for_requested_systems": len(requested) <= limit and not missing,
        "all_paths": False,
        "note": "Explanations are bounded; omitted or missing witnesses do not change exposure counts or prove absence.",
    }


def canonical_dependencies(rows):
    """Twin source/target endpoints must not become a provenance source string."""
    return [
        {
            **metadata({**r, "source": r.get("relationship_source")}),
            **lifecycle_payload(r),
            "from": system_id(r.get("source")),
            "to": system_id(r.get("target")),
            "label": edge_relation(r),
        }
        for r in rows
    ]


def native_path(row, *, now, direction="downstream"):
    """Native query witnesses only; never export/recompute a replacement path."""
    from shared_models.dependency_semantics import stored_relation

    edges = []
    for edge in row.get("path_edges") or []:
        props = dict(edge.get("properties") or {})
        label = stored_relation(props) if edge.get("type") == "CALLS" else edge.get("type")
        edges.append({**props, "from": edge.get("from"), "to": edge.get("to"), "label": label})
    return path_evidence(row.get("path_nodes") or [], edges, now=now, direction=direction)


def native_properties(row):
    """Neo4j cannot store nested reference maps as relationship properties."""
    data = metadata(row)
    refs = data.pop("evidence_refs", None)
    data["evidence_refs_json"] = json.dumps(refs[:50], sort_keys=True) if isinstance(refs, list) else None
    prior_total = data.get("evidence_refs_total")
    count = len(refs) if isinstance(refs, list) else 0
    data["evidence_refs_total"] = max(count, prior_total) if isinstance(prior_total, int) else count
    data["evidence_refs_truncated"] = bool(data.get("evidence_refs_truncated")) or count > 50
    return data
