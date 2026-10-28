"""Load a twin graph export into a graph store (spec 94 §20–§21).

The boundary this module keeps:

    evidence (truth) → canonical records → **this export** → graph store (a copy)

A graph store is never the source of truth, and this loader is where that stays
true in practice. Three rules, each enforced rather than documented:

1. **Nothing new is minted.** Every node and relationship comes from the export,
   which comes from the estate graph, which comes from evidence. The loader has no
   parameter that adds a fact, and it refuses an export whose schema it does not
   know rather than best-effort importing it.
2. **Identifiers are validated, not interpolated blindly.** Cypher cannot
   parameterise labels or relationship types, so they must be built into the
   statement text. Every label and type is checked against the graph's own
   vocabulary (`ASSET_TYPES`, `EVIDENCE_TYPES`, `RELATIONSHIP_PREDICATES`) before it
   is allowed anywhere near a statement — an unvalidated interpolation here would be
   the one place a caller could inject arbitrary Cypher.
3. **Loading is idempotent and verifiable.** Every write is a `MERGE` on the
   deterministic id, so re-loading the same snapshot converges instead of
   duplicating. The loader then reads its own counts back and reports a mismatch as
   a failure — "I wrote 400 nodes" is a claim; "the store contains 400" is a fact.

What it deliberately does **not** do: delete anything by default. Pruning nodes that
are no longer in the export is a destructive operation on a bank's graph, so it is
opt-in, scoped to one estate, and reports exactly what it would remove first.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Sequence

from shared_models.estate_graph import (
    ASSET_TYPES,
    EVIDENCE_TYPES,
    RELATIONSHIP_PREDICATES,
)

EXPORT_SCHEMA = "cryptoscan.estate-graph-export/1"
LOADER_SCHEMA = "cryptoscan.estate-graph-load/1"

#: labels/type tokens that may appear in generated Cypher. Stricter than the
#: vocabulary itself on purpose: no spaces, no backticks, no unicode.
_SAFE_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{0,39}$")

ASSET_LABEL = "EstateAsset"
EVIDENCE_LABEL = "EstateEvidence"
UNRESOLVED_TYPE = "UNRESOLVED_CANDIDATE"
SUPPORTS_TYPE = "SUPPORTS"

#: relationship types the loader will write. ``SUPPORTS`` is added by the export;
#: everything else must be a predicate the estate graph itself allows.
_ALLOWED_REL_TYPES = {predicate.upper() for predicate in RELATIONSHIP_PREDICATES} | {
    SUPPORTS_TYPE,
    UNRESOLVED_TYPE,
}


class ExportRejected(ValueError):
    """The export is not something this loader will write."""


def _check_token(value: str, *, allowed: Iterable[str] | None, what: str) -> str:
    token = str(value or "").strip().upper()
    if not _SAFE_TOKEN.match(token):
        raise ExportRejected(
            f"refusing to write {what} {value!r}: not a plain identifier. Labels and relationship "
            "types are built into Cypher statements, so anything that is not a known token is rejected"
        )
    if allowed is not None and token not in {str(item).upper() for item in allowed}:
        raise ExportRejected(
            f"refusing to write {what} {value!r}: not in the estate vocabulary "
            f"({', '.join(sorted(str(item) for item in allowed))[:200]})"
        )
    return token


def validate_export(export: Mapping[str, Any]) -> dict[str, Any]:
    """Check the export before a single statement is built.

    Returns the validated counts. Raises :class:`ExportRejected` with the reason —
    a partial load is worse than no load, so this runs to completion first.
    """
    if not isinstance(export, Mapping):
        raise ExportRejected("export must be an object")
    schema = str(export.get("schema") or "")
    if schema != EXPORT_SCHEMA:
        raise ExportRejected(
            f"unknown export schema {schema!r}; this loader writes {EXPORT_SCHEMA}. Importing an "
            "unrecognised document would be guessing at its meaning"
        )
    projection_id = str(export.get("projection_id") or "")
    if not projection_id:
        raise ExportRejected("export has no projection_id — a copy without provenance is not loadable")

    nodes = list(export.get("nodes") or [])
    relationships = list(export.get("relationships") or [])
    unresolved = list(export.get("unresolved") or [])

    seen_ids: set[str] = set()
    for node in nodes:
        node_id = str(node.get("id") or "")
        if not node_id:
            raise ExportRejected("a node has no id — identity is not optional in a graph")
        if node_id in seen_ids:
            raise ExportRejected(f"duplicate node id {node_id!r}")
        seen_ids.add(node_id)
        labels = node.get("labels") or []
        if not labels:
            raise ExportRejected(f"node {node_id!r} has no labels")
        for label in labels:
            if str(label).upper() in {"ASSET", "EVIDENCE"}:
                continue
            _check_token(
                str(label),
                allowed=set(ASSET_TYPES) | set(EVIDENCE_TYPES),
                what="node label",
            )

    for edge in relationships:
        rel_type = _check_token(str(edge.get("type") or ""), allowed=_ALLOWED_REL_TYPES, what="relationship type")
        if rel_type == UNRESOLVED_TYPE:
            raise ExportRejected(
                "an UNRESOLVED candidate must ship in `unresolved`, not as a relationship — a refused "
                "edge drawn as an edge is an assumption with a line around it"
            )
        for end in ("from", "to"):
            if str(edge.get(end) or "") not in seen_ids:
                raise ExportRejected(
                    f"relationship {rel_type} references {end}={edge.get(end)!r}, which is not in this "
                    "export. A dangling edge is exactly the kind of fact a graph store would keep forever"
                )

    for edge in unresolved:
        if str(edge.get("from") or "") not in seen_ids or str(edge.get("to") or "") not in seen_ids:
            raise ExportRejected("an unresolved candidate references a node that is not in this export")

    return {
        "projection_id": projection_id,
        "estate": export.get("estate"),
        "nodes": len(nodes),
        "relationships": len(relationships),
        "unresolved": len(unresolved),
    }


def _batches(items: Sequence[Any], size: int) -> list[Sequence[Any]]:
    size = max(1, int(size))
    return [items[index:index + size] for index in range(0, len(items), size)]


def node_statement(label: str, *, evidence: bool = False) -> str:
    """MERGE-by-id upsert for one label.

    ``MERGE`` on the deterministic id rather than ``CREATE`` is what makes a
    re-load converge: the same snapshot loaded twice must not double the store.
    """
    label_token = _check_token(label, allowed=set(ASSET_TYPES) | set(EVIDENCE_TYPES), what="node label")
    extra = f"{EVIDENCE_LABEL}:{label_token}" if evidence else f"{ASSET_LABEL}:{label_token}"
    return (
        f"UNWIND $rows AS row\n"
        f"MERGE (n {{id: row.id}})\n"
        f"SET n:{extra}\n"
        f"SET n += row.properties\n"
        f"SET n.projection_id = row.projection_id, n.estate = row.estate, n.last_loaded_at = row.loaded_at\n"
    )


def relationship_statement(rel_type: str, *, unresolved: bool = False) -> str:
    type_token = _check_token(rel_type, allowed=_ALLOWED_REL_TYPES, what="relationship type")
    if unresolved:
        return (
            "UNWIND $rows AS row\n"
            "MATCH (a {id: row.from}), (b {id: row.to})\n"
            "MERGE (a)-[r:UNRESOLVED_CANDIDATE {from: row.from, to: row.to, "
            "predicate: row.predicate}]->(b)\n"
            "SET r += row.properties\n"
            "SET r.projection_id = row.projection_id\n"
        )
    return (
        f"UNWIND $rows AS row\n"
        f"MATCH (a {{id: row.from}}), (b {{id: row.to}})\n"
        f"MERGE (a)-[r:{type_token} {{from: row.from, to: row.to}}]->(b)\n"
        f"SET r += row.properties\n"
        f"SET r.projection_id = row.projection_id\n"
    )


def plan(export: Mapping[str, Any], *, loaded_at: str, batch_size: int = 500) -> list[dict[str, Any]]:
    """Every statement the load will run, before anything runs.

    Pure and inspectable: a bank can read exactly what will be written, and a test
    can assert on it without a database. ``dry_run`` in :func:`load` uses this to
    return the same shape without touching a server.
    """
    counts = validate_export(export)
    projection_id = counts["projection_id"]
    estate = counts["estate"]

    def params(rows: list[dict[str, Any]]) -> dict[str, Any]:
        return {"rows": rows}

    work: list[dict[str, Any]] = []

    # nodes, grouped by label so each statement names one label
    by_label: dict[tuple[str, bool], list[dict[str, Any]]] = {}
    for node in export.get("nodes") or []:
        labels = [str(label) for label in (node.get("labels") or [])]
        kind_label = next((label for label in labels if label.upper() not in {"ASSET", "EVIDENCE"}), "UNKNOWN")
        is_evidence = any(label.upper() == "EVIDENCE" for label in labels)
        by_label.setdefault((kind_label, is_evidence), []).append(
            {
                "id": str(node["id"]),
                "properties": dict(node.get("properties") or {}),
                "projection_id": projection_id,
                "estate": estate,
                "loaded_at": loaded_at,
            }
        )
    for (label, is_evidence), rows in sorted(by_label.items()):
        for batch in _batches(rows, batch_size):
            work.append(
                {
                    "kind": "node",
                    "label": label,
                    "cypher": node_statement(label, evidence=is_evidence),
                    "params": params(list(batch)),
                    "rows": len(batch),
                }
            )

    by_type: dict[str, list[dict[str, Any]]] = {}
    for edge in export.get("relationships") or []:
        rel_type = str(edge.get("type") or "").upper()
        by_type.setdefault(rel_type, []).append(
            {
                "from": str(edge["from"]),
                "to": str(edge["to"]),
                "properties": dict(edge.get("properties") or {}),
                "projection_id": projection_id,
            }
        )
    for rel_type, rows in sorted(by_type.items()):
        for batch in _batches(rows, batch_size):
            work.append(
                {
                    "kind": "relationship",
                    "type": rel_type,
                    "cypher": relationship_statement(rel_type),
                    "params": params(list(batch)),
                    "rows": len(batch),
                }
            )

    # unresolved candidates are drawn, but as a distinct type that can never be
    # mistaken for an established relationship
    candidates = [
        {
            "from": str(edge.get("from")),
            "to": str(edge.get("to")),
            "predicate": (edge.get("properties") or {}).get("attempted_predicate"),
            "properties": dict(edge.get("properties") or {}),
            "projection_id": projection_id,
        }
        for edge in export.get("unresolved") or []
    ]
    for batch in _batches(candidates, batch_size):
        work.append(
            {
                "kind": "unresolved",
                "type": UNRESOLVED_TYPE,
                "cypher": relationship_statement(UNRESOLVED_TYPE, unresolved=True),
                "params": params(list(batch)),
                "rows": len(batch),
            }
        )

    return work


def prune(export: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Statements that remove nodes of this estate which the export no longer has.

    Never part of a normal load. Called only when the caller explicitly asks to
    prune, and always after the load succeeded, so an interrupted load cannot leave
    the store emptier than the evidence.
    """
    counts = validate_export(export)
    keep = [str(node["id"]) for node in export.get("nodes") or []]
    return [
        {
            "kind": "prune",
            "cypher": (
                "MATCH (n) WHERE n.estate = $estate AND NOT n.id IN $keep\n"
                "DETACH DELETE n\n"
                "RETURN count(n) AS removed"
            ),
            "params": {"estate": counts["estate"], "keep": keep},
        }
    ]


def load(
    export: Mapping[str, Any],
    *,
    driver: Any,
    database: str | None = None,
    batch_size: int = 500,
    dry_run: bool = False,
    loaded_at: str | None = None,
    prune_missing: bool = False,
) -> dict[str, Any]:
    """Write the export to the store, then read the counts back.

    ``driver`` is a Neo4j driver or any object with ``session(database=...)`` that
    yields a session supporting ``run(cypher, params)``. Injected rather than
    fetched so a deployment chooses where the copy lives, and so this is testable
    without a server.
    """
    from datetime import datetime, timezone

    loaded_at = loaded_at or datetime.now(timezone.utc).isoformat()
    counts = validate_export(export)
    statements = plan(export, loaded_at=loaded_at, batch_size=batch_size)

    result: dict[str, Any] = {
        "schema": LOADER_SCHEMA,
        "projection_id": counts["projection_id"],
        "estate": counts["estate"],
        "loaded_at": loaded_at,
        "database": database,
        "dry_run": bool(dry_run),
        "expected": counts,
        "statements": len(statements),
        "written": {},
        "verified": None,
        "verification": "NOT_RUN",
        "pruned": None,
        "source_of_truth": (
            "the graph store is a projection of these evidence records. If the store and "
            "GET /estate/evidence/twin/graph disagree, the evidence wins and the store is rebuilt"
        ),
    }

    for statement in statements:
        key = statement.get("label") or statement.get("type") or statement["kind"]
        result["written"][key] = result["written"].get(key, 0) + int(statement.get("rows") or 0)

    if dry_run:
        result["verification"] = "DRY_RUN"
        result["note"] = (
            f"{len(statements)} statement(s) would run against {database or 'the default database'}. "
            "Nothing was written"
        )
        return result

    if driver is None:
        result.update(
            {
                "verification": "NOT_CONNECTED",
                "ok": False,
                "error": (
                    "no graph driver: the store is unreachable or not configured. Nothing was written, "
                    "and this is not 'the graph is up to date'"
                ),
            }
        )
        return result

    session_kwargs = {"database": database} if database else {}
    with driver.session(**session_kwargs) as session:
        for statement in statements:
            session.run(statement["cypher"], **statement["params"]).consume()

        if prune_missing:
            removed = 0
            for statement in prune(export):
                record = session.run(statement["cypher"], **statement["params"]).single()
                removed += int(record["removed"]) if record else 0
            result["pruned"] = removed

        record = session.run(
            "MATCH (n) WHERE n.estate = $estate RETURN count(n) AS nodes",
            estate=counts["estate"],
        ).single()
        stored_nodes = int(record["nodes"]) if record else 0
        record = session.run(
            "MATCH (n) WHERE n.estate = $estate WITH collect(n.id) AS ids "
            "MATCH (a)-[r]->(b) WHERE a.id IN ids "
            "RETURN count(DISTINCT r) AS relationships",
            estate=counts["estate"],
        ).single()
        stored_relationships = int(record["relationships"]) if record else 0

    expected_relationships = counts["relationships"] + counts["unresolved"]
    result["verified"] = {"nodes": stored_nodes, "relationships": stored_relationships}
    matches = stored_nodes >= counts["nodes"] and stored_relationships >= expected_relationships
    result["ok"] = bool(matches)
    result["verification"] = "VERIFIED" if matches else "MISMATCH"
    if not matches:
        result["error"] = (
            f"wrote {counts['nodes']} node(s) and {expected_relationships} relationship(s) but the store "
            f"reports {stored_nodes} and {stored_relationships}. A count mismatch means the copy is not a "
            "copy; treat the store as suspect rather than as updated"
        )
    return result


__all__ = [
    "EXPORT_SCHEMA",
    "LOADER_SCHEMA",
    "ExportRejected",
    "load",
    "node_statement",
    "plan",
    "prune",
    "relationship_statement",
    "validate_export",
]
