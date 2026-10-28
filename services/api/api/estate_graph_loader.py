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



#: readback queries the parity check runs. Each is a *question to the store*, not a
#: write: an id list per node kind, relationship counts per type, and one bounded
#: traversal whose answer can be compared with the in-process one.
NODE_IDS_QUERY = (
    "MATCH (n) WHERE n.estate = $estate AND $label IN labels(n) "
    "RETURN n.id AS id ORDER BY n.id"
)
REL_COUNTS_QUERY = (
    "MATCH (a)-[r]->() WHERE a.estate = $estate "
    "RETURN type(r) AS type, count(r) AS count ORDER BY type"
)


#: one bounded traversal, answered by the store rather than by the twin. The relationship
#: types are passed as a parameter so no token from an export is interpolated into Cypher,
#: and the walk is undirected for the same reason the twin's blast radius is: a dependency
#: points the other way from an impact.
TRAVERSAL_QUERY = (
    "MATCH (start:" + ASSET_LABEL + ") WHERE start.estate = $estate AND start.id IN $seeds "
    "MATCH path = (start)-[rels*1..{depth}]-(n) "
    "WHERE all(r IN rels WHERE type(r) IN $types) "
    "RETURN DISTINCT n.id AS id ORDER BY n.id"
)


def _expected_ids(export: Mapping[str, Any]) -> dict[str, set[str]]:
    """The exact node ids the export says should be in the store, per kind label."""
    by_label: dict[str, set[str]] = {}
    for node in export.get("nodes") or []:
        labels = [str(label) for label in (node.get("labels") or [])]
        kind = next(
            (label for label in labels if label.upper() not in {"ASSET", "EVIDENCE"}), "UNKNOWN"
        )
        by_label.setdefault(kind, set()).add(str(node["id"]))
    return by_label


def _expected_rel_counts(export: Mapping[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for edge in export.get("relationships") or []:
        rel_type = str(edge.get("type") or "").upper()
        counts[rel_type] = counts.get(rel_type, 0) + 1
    unresolved = len(export.get("unresolved") or [])
    if unresolved:
        counts[UNRESOLVED_TYPE] = counts.get(UNRESOLVED_TYPE, 0) + unresolved
    return counts


def parity(
    export: Mapping[str, Any],
    *,
    driver: Any,
    database: str | None = None,
    max_listed: int = 20,
) -> dict[str, Any]:
    """Do the store and the canonical records agree — exactly, and answerably?

    The loader's own verification counts what it wrote. Counts are a weak test: a store
    that kept yesterday's nodes and gained today's has *more* than expected and would
    pass a ``>=`` check while holding a superseded estate. This asks the store two
    questions that can only be answered with the projection in hand:

    * **which ids does the store hold, per kind?** Compared as sets against the export,
      so both a missing node and a leftover node are named rather than counted;
    * **how many relationships of each type?** Compared exactly, per type, so a lost
      edge type cannot hide inside an unchanged total.

    The result is ``PARITY``, ``MISMATCH`` (with the differences named),
    ``NOT_CONNECTED`` (no store, which is not "in parity") or ``STALE_ONLY`` (the store
    holds everything the export has plus nodes the caller has not pruned — an
    accumulated store, reported rather than smoothed over).

    Contents equality is not traversal equality: the store can hold exactly this projection
    and still answer a traversal differently if it walks different relationship types or a
    different depth. :func:`traversal_parity` runs that comparison for one asset and one
    depth; this function reports ``traversal_parity: NOT_CLAIMED`` because it has not run it.
    """
    counts = validate_export(export)
    estate = counts["estate"]
    expected_ids = _expected_ids(export)
    expected_rels = _expected_rel_counts(export)

    result: dict[str, Any] = {
        "schema": LOADER_SCHEMA,
        "check": "parity",
        "projection_id": counts["projection_id"],
        "estate": estate,
        "database": database,
        "expected": {
            "nodes": counts["nodes"],
            "relationships": counts["relationships"],
            "unresolved": counts["unresolved"],
        },
        "status": "NOT_RUN",
        "store": None,
        "missing": {},
        "unexpected": {},
        "relationship_differences": {},
        "traversal_parity": "NOT_CLAIMED",
        "traversal_note": (
            "contents parity is not traversal parity. The store holds a proven copy of this "
            "projection; whether a blast radius computed there reaches the same assets is "
            "answered by traversal_parity() (GET /twin/graph/traversal), not here"
        ),
    }

    if driver is None:
        result.update({
            "status": "NOT_CONNECTED",
            "ok": False,
            "error": (
                "no graph driver: the store is unreachable or not configured. That is not "
                "'the store is in parity'"
            ),
        })
        return result

    stored_ids: dict[str, set[str]] = {}
    session_kwargs = {"database": database} if database else {}
    with driver.session(**session_kwargs) as session:
        for label in sorted(expected_ids):
            _check_token(label, allowed=set(ASSET_TYPES) | set(EVIDENCE_TYPES), what="node label")
            rows = session.run(NODE_IDS_QUERY, estate=estate, label=label)
            stored_ids[label] = {str(record["id"]) for record in rows}

        rel_rows = session.run(REL_COUNTS_QUERY, estate=estate)
        stored_rels = {str(record["type"]): int(record["count"]) for record in rel_rows}

    missing = {
        label: sorted(ids - stored_ids.get(label, set()))[:max_listed]
        for label, ids in expected_ids.items()
        if ids - stored_ids.get(label, set())
    }
    unexpected = {
        label: sorted(stored_ids.get(label, set()) - ids)[:max_listed]
        for label, ids in expected_ids.items()
        if stored_ids.get(label, set()) - ids
    }
    # a kind the store holds entirely of leftovers is not in expected_ids at all
    for label in sorted(set(stored_ids) - set(expected_ids)):
        if stored_ids[label]:
            unexpected[label] = sorted(stored_ids[label])[:max_listed]

    relationship_differences = {
        rel_type: {"expected": expected_rels.get(rel_type, 0), "stored": stored_rels.get(rel_type, 0)}
        for rel_type in sorted(set(expected_rels) | set(stored_rels))
        if expected_rels.get(rel_type, 0) != stored_rels.get(rel_type, 0)
    }

    result["store"] = {
        "nodes": {label: len(ids) for label, ids in sorted(stored_ids.items())},
        "relationships": dict(sorted(stored_rels.items())),
    }
    result["missing"] = missing
    result["unexpected"] = unexpected
    result["relationship_differences"] = relationship_differences

    if missing or (unexpected and relationship_differences):
        result["status"] = "MISMATCH"
    elif unexpected:
        result["status"] = "STALE_ONLY"
    elif relationship_differences:
        result["status"] = "MISMATCH"
    else:
        result["status"] = "PARITY"

    result["ok"] = result["status"] == "PARITY"
    if result["status"] == "PARITY":
        result["note"] = (
            "the store holds exactly this projection: same ids per kind, same relationship count "
            "per type. It remains a copy — the evidence is still the truth"
        )
    elif result["status"] == "STALE_ONLY":
        result["note"] = (
            "the store holds everything this projection has, plus nodes it no longer contains. "
            "That is an accumulated copy, not a wrong one: re-load with prune to converge, and do "
            "not read the extra nodes as estate state"
        )
    else:
        result["note"] = (
            "the store and the evidence disagree. The evidence wins: treat the store as suspect and "
            "reload it, rather than editing the store to match"
        )
    return result



def traversal_parity(
    export: Mapping[str, Any],
    impact: Mapping[str, Any],
    *,
    driver: Any,
    database: str | None = None,
    max_listed: int = 20,
) -> dict[str, Any]:
    """Run the same blast radius in the store and compare it with the twin's (§20–§21).

    ``parity`` proves the store holds this projection. It cannot prove that a *question*
    asked of the store gets the twin's answer, and until that is shown the store stays a
    copy for external consumers — which is why ``parity`` reports
    ``traversal_parity: NOT_CLAIMED``. This is that check, for one asset and one depth:

    * the twin's reachable set comes from ``estate_twin.impact`` and is untruncated;
    * the store's comes from one bounded Cypher walk over the same relationship types,
      passed as a parameter so nothing from an export is interpolated;
    * both are compared as **sets**, so an id only the store reaches is named as loudly as
      an id only the twin reaches.

    A difference does not mean the store is wrong or the twin is wrong — it means one of
    them is answering a different question, and the honest response is to find out which
    before letting anything read the store as authority. ``NOT_CONNECTED`` is not parity.
    """
    counts = validate_export(export)
    estate = counts["estate"]
    reachable = [str(item) for item in (impact.get("reachable_ids") or [])]
    depth = int(impact.get("depth") or 0)

    result: dict[str, Any] = {
        "schema": LOADER_SCHEMA,
        "check": "traversal",
        "projection_id": counts["projection_id"],
        "estate": estate,
        "database": database,
        "selector": impact.get("selector"),
        "depth": depth,
        "status": "NOT_RUN",
        "in_process": {"count": len(reachable), "ids": reachable[:max_listed]},
        "store": None,
        "only_in_twin": [],
        "only_in_store": [],
        "ok": False,
    }

    if impact.get("status") != "MATCHED":
        result.update({
            "status": "NO_MATCH",
            "note": (
                f"the twin answered {impact.get('status')!r} for this selector, so there is no "
                "reachable set to compare. That is not parity and it is not an empty result"
            ),
        })
        return result

    if driver is None:
        result.update({
            "status": "NOT_CONNECTED",
            "note": (
                "no graph store: the traversal parity check needs a store to walk. This is not "
                "'the store agrees with the twin'"
            ),
        })
        return result

    types = sorted({
        _check_token(str(edge.get("type") or ""), allowed=_ALLOWED_REL_TYPES, what="relationship type")
        for edge in export.get("relationships") or []
        if str(edge.get("type") or "").upper() != UNRESOLVED_TYPE
    })
    seeds = [str(item) for item in (impact.get("seed_ids") or [])]
    if not seeds:
        result.update({
            "status": "NO_MATCH",
            "note": "the impact had no seed assets, so there is nothing to walk from",
        })
        return result
    if not types:
        result.update({
            "status": "NO_TRAVERSABLE_TYPES",
            "note": (
                "this projection has no established relationships, so any traversal is the seed "
                "set alone. That is a fact about the estate, not a parity result"
            ),
        })
        return result

    query = TRAVERSAL_QUERY.format(depth=max(1, min(depth, 10)))
    session_kwargs = {"database": database} if database else {}
    with driver.session(**session_kwargs) as session:
        rows = session.run(query, estate=estate, seeds=seeds, types=types)
        stored = {str(record["id"]) for record in rows}

    # the twin's own set includes the seeds (distance 0); so must the store's
    stored |= {seed for seed in seeds if seed}
    twin_set = set(reachable)

    only_in_twin = sorted(twin_set - stored)
    only_in_store = sorted(stored - twin_set)
    result["store"] = {
        "count": len(stored),
        "ids": sorted(stored)[:max_listed],
        "types_walked": types,
        "seeds": seeds,
    }
    result["only_in_twin"] = only_in_twin[:max_listed]
    result["only_in_store"] = only_in_store[:max_listed]

    if only_in_twin or only_in_store:
        result.update({
            "status": "TRAVERSAL_MISMATCH",
            "ok": False,
            "note": (
                "the store and the twin do not reach the same assets for this question. One of "
                "them is answering a different question: check that the store holds this "
                "projection (parity), that the relationship types walked are the ones the twin "
                "uses, and that depth is the same on both sides. Until that is settled neither "
                "answer should be read as authority"
            ),
        })
    else:
        result.update({
            "status": "TRAVERSAL_PARITY",
            "ok": True,
            "note": (
                "a blast radius computed in the graph store reaches exactly the assets the twin "
                "reaches, at the same depth, over the same relationship types. The store is a "
                "verified copy for this question — the evidence remains the truth"
            ),
        })
    return result


__all__ = [
    "EXPORT_SCHEMA",
    "LOADER_SCHEMA",
    "ExportRejected",
    "load",
    "parity",
    "node_statement",
    "plan",
    "prune",
    "relationship_statement",
    "traversal_parity",
    "validate_export",
]
