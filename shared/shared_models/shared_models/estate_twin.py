"""The CryptoScan Digital Twin (spec 94).

Design spec: ``docs/bank-environment/94-cryptoscan-digital-twin.md``.

The estate graph (spec 93) is the correlated model. This module is the *twin* on
top of it: the parts of spec 94 that turn a graph into something you can
investigate, size, and simulate.

Seven layers, and the rule each one keeps:

* **Estate placement** — where an asset belongs. An asset with no environment or
  location is reported as ``UNPLACED``; it is never attached to the estate root to
  make the tree look complete.
* **Assets** — canonical, stable ids (``estate_graph``).
* **Relationships** — every edge carries a basis and evidence; anything else is
  ``UNKNOWN`` (``estate_graph``).
* **Crypto** — capability, configuration, negotiation and observation kept apart
  (``estate_graph.crypto_artifacts``).
* **Evidence** — ``why()`` answers with the collector, source, timestamp and hash
  behind a fact, and refuses to answer for an edge that does not exist.
* **Time** — ``snapshot()`` is content-addressed by the projection id, so two
  snapshots are comparable exactly when nothing about the evidence changed.
* **Simulation** — ``simulate()`` runs on a *copy*: it rebuilds a graph from a
  snapshot payload and re-projects the six BOMs. It reports the live projection id
  before and after so "the production twin was not touched" is a checked fact, not
  a promise.

Two refusals worth stating out loud, because they are what make the twin
trustworthy:

* ``completeness()`` measures **how well the estate is described**, not how good
  its cryptography is. A twin at 100% completeness may be entirely classical.
* ``impact()`` / ``simulate()`` return ``NO_MATCH`` rather than an empty impact
  list when a scenario matched nothing — "nothing was affected" and "we could not
  find the thing you asked about" are different answers, and only one of them is
  usually true.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from shared_models.estate_graph import (
    ASSET_TYPES,
    BOM_KINDS,
    EstateGraph,
    build_graph,
)

TWIN_SCHEMA = "cryptoscan.estate-twin/1"
SNAPSHOT_SCHEMA = "cryptoscan.estate-twin-snapshot/1"
COMPLETENESS_SCHEMA = "cryptoscan.estate-twin-completeness/1"
INVESTIGATION_SCHEMA = "cryptoscan.estate-twin-asset/1"
WHY_SCHEMA = "cryptoscan.estate-twin-why/1"
SEARCH_SCHEMA = "cryptoscan.estate-twin-search/1"
IMPACT_SCHEMA = "cryptoscan.estate-twin-impact/1"
SIMULATION_SCHEMA = "cryptoscan.estate-twin-simulation/1"

#: §4 layer 1 — the placement levels the twin understands
ESTATE_LEVELS: tuple[str, ...] = (
    "BANK",
    "REGION",
    "DATA_CENTER",
    "CLOUD_ENVIRONMENT",
    "ENVIRONMENT",
    "BUSINESS_SYSTEM",
)

#: §15 — what a simulation is allowed to change
SIMULATION_KINDS: tuple[str, ...] = (
    "REPLACE_ALGORITHM",
    "RETIRE_ALGORITHM",
    "DISABLE_PROTOCOL",
    "UPGRADE_COMPONENT",
)

#: §12 — strongest evidence first. Used to answer "how well is this described".
STRENGTH_ORDER: tuple[str, ...] = (
    "RUNTIME_OBSERVED",
    "AUDIT_OBSERVED",
    "NETWORK_ACTIVE_OBSERVED",
    "CERTIFICATE_OBSERVED",
    "NETWORK_PASSIVE_OBSERVED",
    "STATIC_OBSERVED",
    "CONFIGURED",
    "IMPORTED",
    "VENDOR_DECLARED",
    "INFERRED",
    "UNKNOWN",
)

MAX_LISTED = 50

#: BOM projections are stable when these change nothing; used by the simulator
#: to tell a real projection difference from a re-render.
_VOLATILE_COMPONENT_KEYS = frozenset({"generated_at"})


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _percent(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(100.0 * numerator / denominator, 1)


def _strength(evidence_types: Iterable[str]) -> str:
    seen = {str(item) for item in evidence_types}
    for level in STRENGTH_ORDER:
        if level in seen:
            return level
    return "UNKNOWN"


def _record_hash(record: Mapping[str, Any]) -> str:
    """Content hash of one observation, so a "why" answer can be checked later.

    The evidence id is already content-addressed; this is the same idea stated in
    the auditor's terms — hash the fact, the source and the time, so a re-read
    either reproduces the hash or proves the record moved.
    """
    return "sha256:" + _canonical(
        {
            "evidence_type": record.get("evidence_type"),
            "target": record.get("target"),
            "layer": record.get("layer"),
            "source": record.get("source"),
            "collector": record.get("collector"),
            "observed_at": record.get("observed_at"),
            "facts": record.get("facts") or {},
        }
    )


def _asset_card(asset: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "asset_id": asset["asset_id"],
        "type": asset["type"],
        "name": asset["name"],
        "environment": asset.get("environment"),
        "owner": asset.get("owner"),
        "location": asset.get("location"),
        "status": asset.get("status") or asset.get("attributes", {}).get("status"),
        "identity": asset.get("identity") or {},
    }


def _matches_selector(facts: Mapping[str, Any], selector: Mapping[str, Any]) -> bool:
    """Does one evidence fact set match the selector?

    Every stated field must match; an unstated field never excludes. A selector
    that does not constrain anything is rejected by the caller, because "match
    everything" is how an impact report becomes a wall of numbers.
    """
    for field in ("algorithm", "protocol", "mode", "key_size", "curve", "version", "name"):
        wanted = selector.get(field)
        if wanted in (None, ""):
            continue
        value = facts.get(field)
        if value in (None, ""):
            return False
        if field == "key_size":
            if str(value).strip() != str(wanted).strip():
                return False
            continue
        if str(wanted).strip().lower() not in str(value).strip().lower():
            return False
    return True


def _selector_is_meaningful(selector: Mapping[str, Any]) -> bool:
    return any(
        selector.get(field) not in (None, "")
        for field in ("algorithm", "protocol", "mode", "key_size", "curve", "version", "name", "asset")
    )


def _resolve(graph: EstateGraph, ref: Any) -> str | None:
    """Resolve an asset_id, an exact name, or a unique name fragment (§24)."""
    text = _text(ref)
    if not text:
        return None
    if graph.asset(text) is not None:
        return text
    lowered = text.lower()
    for asset in graph.assets():
        if str(asset.get("name") or "").lower() == lowered:
            return asset["asset_id"]
    candidates = [
        asset["asset_id"]
        for asset in graph.assets()
        if lowered in str(asset.get("name") or "").lower()
    ]
    return candidates[0] if len(candidates) == 1 else None


def _adjacency(graph: EstateGraph) -> dict[str, list[dict[str, Any]]]:
    """Undirected view over *established* edges only.

    A refused edge is not in the topology. Traversing through an ``UNKNOWN``
    relationship would let the blast radius inherit an assumption.
    """
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in graph.relationships():
        adjacency.setdefault(edge["subject"], []).append(edge)
        adjacency.setdefault(edge["object"], []).append(edge)
    return adjacency


def _walk(
    graph: EstateGraph,
    seeds: Iterable[str],
    *,
    depth: int,
) -> tuple[dict[str, int], dict[str, str]]:
    """Breadth-first over established edges. Returns distance and parent maps."""
    adjacency = _adjacency(graph)
    distance: dict[str, int] = {}
    parent: dict[str, str] = {}
    frontier = [seed for seed in seeds if seed]
    for seed in frontier:
        distance[seed] = 0
    current = 0
    while frontier and current < depth:
        nxt: list[str] = []
        for node in frontier:
            for edge in adjacency.get(node, []):
                other = edge["object"] if edge["subject"] == node else edge["subject"]
                if other in distance:
                    continue
                distance[other] = current + 1
                parent[other] = node
                nxt.append(other)
        frontier = nxt
        current += 1
    return distance, parent


def _path_to(parent: Mapping[str, str], node: str, graph: EstateGraph) -> list[dict[str, Any]]:
    """Rebuild one hop-by-hop path, so an impact number can be read as a route."""
    hops: list[str] = [node]
    current = node
    while current in parent:
        current = parent[current]
        hops.append(current)
    hops.reverse()
    path: list[dict[str, Any]] = []
    for index, asset_id in enumerate(hops):
        asset = graph.asset(asset_id) or {}
        path.append(
            {
                "asset_id": asset_id,
                "name": asset.get("name"),
                "type": asset.get("type"),
                "via": None if index == 0 else path_edge(graph, hops[index - 1], asset_id),
            }
        )
    return path


def path_edge(graph: EstateGraph, source: str, target: str) -> dict[str, Any] | None:
    for edge in graph.relationships():
        if {edge["subject"], edge["object"]} == {source, target}:
            return {
                "predicate": edge["predicate"],
                "basis": edge.get("basis"),
                "confidence": edge.get("confidence"),
                "evidence_ids": edge.get("evidence_ids"),
            }
    return None


# --------------------------------------------------------------------------- #
# layer 6 — snapshots
# --------------------------------------------------------------------------- #


def snapshot(graph: EstateGraph, *, scope: str | None = None) -> dict[str, Any]:
    """A content-addressed twin snapshot (§14, §19).

    The id is the projection id, so two snapshots are comparable exactly when the
    evidence behind them is identical. ``created_at`` is bookkeeping and is
    deliberately *not* part of the id — otherwise every re-read would be a new
    snapshot and every diff would be full.
    """
    payload = {
        "estate": graph.estate,
        "scope": scope or graph.scope,
        "assets": [
            {
                "type": asset["type"],
                "name": asset["name"],
                "identity": asset.get("identity") or {},
                "environment": asset.get("environment"),
                "owner": asset.get("owner"),
                "location": asset.get("location"),
                "source": asset.get("source"),
                "attributes": asset.get("attributes") or {},
            }
            for asset in graph.assets()
        ],
        "evidence": [dict(record) for record in graph.evidence()],
        "relationships": [
            {
                "subject": edge["subject"],
                "predicate": edge["predicate"],
                "object": edge["object"],
                "basis": edge.get("basis"),
                "evidence_ids": list(edge.get("evidence_ids") or []),
                "confidence": edge.get("confidence"),
                "attributes": edge.get("attributes") or {},
            }
            for edge in graph.relationships()
        ],
        "collectors": [
            {
                "plane": collector.get("plane"),
                "status": collector.get("status"),
                "expected": collector.get("expected"),
                "collected": collector.get("collected"),
                "reason": collector.get("reason"),
                "impact": collector.get("impact"),
            }
            for collector in graph.coverage().get("collectors") or []
        ],
        "coverage": [dict(row) for row in graph.coverage_rows()],
    }
    projection_id = graph.fingerprint()
    return {
        "schema": SNAPSHOT_SCHEMA,
        "snapshot_id": f"twin:{projection_id}",
        "projection_id": projection_id,
        "created_at": _now(),
        "estate": graph.estate,
        "scope": payload["scope"],
        "counts": {
            "assets": len(payload["assets"]),
            "evidence": len(payload["evidence"]),
            "relationships": len(payload["relationships"]),
            "collectors": len(payload["collectors"]),
            "coverage_rows": len(payload["coverage"]),
        },
        "collector_versions": sorted(
            {str(record.get("collector")) for record in payload["evidence"] if record.get("collector")}
        ),
        "payload": payload,
        "note": (
            "the snapshot id is the projection id: two snapshots are comparable when the evidence "
            "behind them is identical, and created_at is bookkeeping rather than identity"
        ),
    }


def graph_from_snapshot(snapshot_doc: Mapping[str, Any]) -> EstateGraph:
    """Rebuild a graph from a snapshot — the only way a simulation gets a graph."""
    payload = snapshot_doc.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError("snapshot has no payload — a twin snapshot must carry its evidence")
    return build_graph(payload)


# --------------------------------------------------------------------------- #
# layer 1 — estate placement
# --------------------------------------------------------------------------- #


def placement_model(graph: EstateGraph) -> dict[str, Any]:
    """§4 — where everything belongs, with the unplaced called out.

    The twin refuses to invent a hierarchy: an asset with neither an environment
    nor a location lands in ``unplaced`` with a reason, because "we do not know
    where this runs" is a finding in its own right.
    """
    bank = graph.estate or "UNNAMED_ESTATE"
    environments: dict[str, dict[str, Any]] = {}
    unplaced: list[dict[str, Any]] = []
    systems: dict[str, list[dict[str, Any]]] = {}

    for asset in graph.assets():
        environment = _text(asset.get("environment"))
        location = _text(asset.get("location"))
        if not environment and not location:
            unplaced.append({**_asset_card(asset), "reason": "no environment and no location in any evidence"})
            continue
        key = environment or "UNSPECIFIED_ENVIRONMENT"
        bucket = environments.setdefault(
            key,
            {
                "name": key,
                "assets": 0,
                "by_type": {},
                "locations": {},
                "business_systems": [],
            },
        )
        bucket["assets"] += 1
        bucket["by_type"][asset["type"]] = bucket["by_type"].get(asset["type"], 0) + 1
        location_key = location or "UNSPECIFIED_LOCATION"
        bucket["locations"].setdefault(location_key, 0)
        bucket["locations"][location_key] += 1
        if asset["type"] in {"SYSTEM"}:
            bucket["business_systems"].append(asset.get("name"))
            systems.setdefault(key, []).append(asset.get("name"))

    tree = []
    for name in sorted(environments):
        bucket = environments[name]
        tree.append(
            {
                "name": bucket["name"],
                "assets": bucket["assets"],
                "by_type": bucket["by_type"],
                "business_systems": sorted(item for item in bucket["business_systems"] if item),
                "locations": [
                    {"name": location, "assets": count}
                    for location, count in sorted(bucket["locations"].items())
                ],
            }
        )

    return {
        "schema": TWIN_SCHEMA,
        "model": "cryptoscan.estate-placement/1",
        "levels": list(ESTATE_LEVELS),
        "bank": bank,
        "estate": bank,
        "environments": tree,
        "business_systems": sorted({name for names in systems.values() for name in names if name}),
        "unplaced": unplaced[:MAX_LISTED],
        "unplaced_count": len(unplaced),
        "placeable": len(graph.assets()) - len(unplaced),
        "note": (
            "placement is derived from evidence, never assumed: an asset without an environment or "
            "location is UNPLACED rather than attached to the estate root"
        ),
    }


# --------------------------------------------------------------------------- #
# §29 — twin completeness (description quality, not crypto posture)
# --------------------------------------------------------------------------- #


def _dimension(
    name: str,
    numerator: int,
    denominator: int,
    *,
    meaning: str,
    state: str | None = None,
) -> dict[str, Any]:
    percent = _percent(numerator, denominator)
    if state is None:
        state = "MEASURED" if percent is not None else "NOT_OBSERVED"
    return {
        "dimension": name,
        "numerator": numerator,
        "denominator": denominator,
        "percent": percent,
        "state": state,
        "meaning": meaning,
    }


def completeness(graph: EstateGraph) -> dict[str, Any]:
    """§29 — how completely the twin describes the estate.

    This is a **description** score. It says nothing about whether the crypto it
    describes is any good, and it is never called readiness. The unmeasured
    dimensions are listed rather than counted as 0% (which would look like a
    failure) or as 100% (which would look like a pass).
    """
    assets = graph.assets()
    evidence = graph.evidence()
    edges = graph.relationships()
    coverage = graph.coverage()

    described = {str(record["target"]) for record in evidence}
    asset_ids = {asset["asset_id"] for asset in assets}
    with_evidence = [edge for edge in edges if edge.get("evidence_ids")]

    dimensions: list[dict[str, Any]] = [
        _dimension(
            "ASSET_EVIDENCE",
            len(described & asset_ids),
            len(assets),
            meaning="assets with at least one evidence record behind them",
        ),
        _dimension(
            "RELATIONSHIP_EVIDENCE",
            len(with_evidence),
            len(edges),
            meaning="edges that carry the evidence they were established on",
        ),
    ]

    summary = coverage["summary"]
    dimensions.append(
        _dimension(
            "TARGET_COVERAGE",
            int(summary.get("collected") or 0),
            int(summary.get("expected") or 0),
            meaning="collector targets actually attempted versus expected",
            state=str(summary.get("coverage_state") or "NOT_OBSERVED"),
        )
    )

    visibility: list[dict[str, Any]] = []
    for row in coverage.get("targets") or []:
        entry = _dimension(
            str(row.get("target") or "UNKNOWN"),
            int(row.get("collected") or 0),
            int(row.get("expected") or 0),
            meaning=f"visibility into {row.get('target')}",
            state=str(row.get("status") or "UNKNOWN"),
        )
        entry["reason"] = row.get("reason")
        visibility.append(entry)

    measured = [item for item in dimensions + visibility if item["percent"] is not None]
    unmeasured = [
        {"dimension": item["dimension"], "state": item["state"], "reason": item.get("reason")}
        for item in dimensions + visibility
        if item["percent"] is None
    ]
    overall = round(sum(item["percent"] for item in measured) / len(measured), 1) if measured else None

    unknown = graph.unknown_inventory()
    conflicts = graph.conflicts()
    why_not_100: list[dict[str, Any]] = []
    if unknown["assets_without_evidence"]:
        why_not_100.append(
            {
                "reason": "assets with no evidence at all",
                "count": len(unknown["assets_without_evidence"]),
                "next_action": "run an approved collector against these targets, or declare them out of scope",
            }
        )
    if unknown["failed_collectors"]:
        why_not_100.append(
            {
                "reason": "collectors that failed — their estate is NOT_OBSERVED, not empty",
                "count": len(unknown["failed_collectors"]),
                "next_action": "restore collector access, then re-run; the plane stays UNKNOWN until then",
            }
        )
    if unknown["unresolved_relationships"]:
        why_not_100.append(
            {
                "reason": "relationships without a basis or evidence",
                "count": len(unknown["unresolved_relationships"]),
                "next_action": "supply the configuration/PKCS#11/runtime observation that would establish the edge",
            }
        )
    if conflicts:
        why_not_100.append(
            {
                "reason": "conflicting observations of the same fact",
                "count": len(conflicts),
                "next_action": "find out which source is describing which artefact — do not pick a winner",
            }
        )
    if unknown["capability_only"]:
        why_not_100.append(
            {
                "reason": "crypto artefacts known only as capability or configuration",
                "count": unknown["capability_only"],
                "next_action": "observe them at runtime or on the wire before calling them 'in use'",
            }
        )
    for row in visibility:
        if row["state"] in {"FAILED", "NOT_ATTEMPTED", "PARTIAL", "NOT_OBSERVED"}:
            why_not_100.append(
                {
                    "reason": f"{row['dimension']} is {row['state']}",
                    "count": row["denominator"] - row["numerator"] if row["denominator"] else 0,
                    "next_action": row.get("reason") or f"restore visibility into {row['dimension']}",
                }
            )

    return {
        "schema": COMPLETENESS_SCHEMA,
        "estate": graph.estate,
        "projection_id": graph.fingerprint(),
        "dimensions": dimensions,
        "visibility": visibility,
        "measured": len(measured),
        "unmeasured": unmeasured,
        "overall_percent": overall,
        "overall_state": "MEASURED" if overall is not None else "NOT_OBSERVED",
        "overall_label": "twin completeness",
        "is_posture_score": False,
        "meaning": (
            "this measures how completely the twin describes the estate. It is not crypto readiness: "
            "a fully described estate can be entirely classical, and a twin cannot be more complete "
            "than its collectors"
        ),
        "why_not_100": why_not_100[:MAX_LISTED],
    }


# --------------------------------------------------------------------------- #
# §25 — asset investigation
# --------------------------------------------------------------------------- #


def investigate(graph: EstateGraph, ref: Any, *, depth: int = 3) -> dict[str, Any] | None:
    """One asset, everything the twin knows, and the strength of each part."""
    asset_id = _resolve(graph, ref)
    if asset_id is None:
        return None
    asset = graph.asset(asset_id)
    if asset is None:
        return None

    records = [record for record in graph.evidence() if str(record["target"]) == asset_id]
    by_type: dict[str, int] = {}
    for record in records:
        key = str(record["evidence_type"])
        by_type[key] = by_type.get(key, 0) + 1

    artifacts = [item for item in graph.crypto_artifacts() if item["asset_id"] == asset_id]
    outgoing = [edge for edge in graph.relationships() if edge["subject"] == asset_id]
    incoming = [edge for edge in graph.relationships() if edge["object"] == asset_id]

    def _edges(items: Sequence[Mapping[str, Any]], *, inbound: bool) -> list[dict[str, Any]]:
        out = []
        for edge in items:
            other_id = edge["subject"] if inbound else edge["object"]
            other = graph.asset(other_id) or {}
            out.append(
                {
                    "predicate": edge["predicate"],
                    "direction": "in" if inbound else "out",
                    "asset_id": other_id,
                    "name": other.get("name"),
                    "type": other.get("type"),
                    "basis": edge.get("basis"),
                    "confidence": edge.get("confidence"),
                    "evidence_ids": edge.get("evidence_ids") or [],
                }
            )
        return out

    dependencies = [item for item in _edges(outgoing, inbound=False) if item["predicate"] in
                    {"depends_on", "uses", "runs_on", "hosted_on", "connects_to", "backs_with"}]

    distance, parent = _walk(graph, [asset_id], depth=depth)
    reached = [node for node in distance if node != asset_id]

    return {
        "schema": INVESTIGATION_SCHEMA,
        "model": "cryptoscan.estate-asset-view/1",
        "projection_id": graph.fingerprint(),
        "estate": graph.estate,
        "asset": _asset_card(asset),
        "attributes": asset.get("attributes") or {},
        "placement": {
            "environment": asset.get("environment"),
            "location": asset.get("location"),
            "owner": asset.get("owner"),
            "placed": bool(asset.get("environment") or asset.get("location")),
        },
        "crypto": {
            "artifacts": artifacts,
            "by_usage_state": {
                state: sum(1 for item in artifacts if item["usage_state"] == state)
                for state in ("SUPPORTED", "CONFIGURED", "NEGOTIATED", "OBSERVED")
            },
            "observed": [item for item in artifacts if item["usage_state"] == "OBSERVED"],
            "capability_only": [item for item in artifacts if item["usage_state"] in {"SUPPORTED", "CONFIGURED"}],
            "note": "capability is not use: SUPPORTED/CONFIGURED artefacts are not evidence of operation",
        },
        "relationships": {
            "outgoing": _edges(outgoing, inbound=False),
            "incoming": _edges(incoming, inbound=True),
            "dependencies": dependencies,
            "count": len(outgoing) + len(incoming),
        },
        "evidence": {
            "count": len(records),
            "by_type": by_type,
            "strongest": _strength(by_type),
            "records": [
                {**record, "hash": _record_hash(record)}
                for record in sorted(records, key=lambda item: str(item.get("observed_at") or ""))
            ],
        },
        "unknown": {
            "unresolved_relationships": [
                edge
                for edge in graph.unresolved_relationships()
                if asset_id in {edge.get("subject"), edge.get("object")}
            ],
            "conflicts": [item for item in graph.conflicts() if item.get("asset_id") == asset_id],
            "no_evidence": not records,
        },
        "neighbourhood": {
            "depth": depth,
            "reached": len(reached),
            "assets": [
                {
                    "asset_id": node,
                    "name": (graph.asset(node) or {}).get("name"),
                    "type": (graph.asset(node) or {}).get("type"),
                    "hops": distance[node],
                }
                for node in sorted(reached, key=lambda node: (distance[node], node))[:MAX_LISTED]
            ],
            "truncated": len(reached) > MAX_LISTED,
        },
    }


# --------------------------------------------------------------------------- #
# §28 — "why is this relationship present?"
# --------------------------------------------------------------------------- #


def why(
    graph: EstateGraph,
    *,
    subject: Any = None,
    predicate: str | None = None,
    obj: Any = None,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    """Answer with provenance — or refuse, naming what is missing.

    An edge that was refused is the more interesting answer: the twin explains
    *why* it is not a relationship rather than drawing it anyway.
    """
    if evidence_id:
        for record in graph.evidence():
            if str(record["evidence_id"]) == str(evidence_id):
                return {
                    "schema": WHY_SCHEMA,
                    "status": "EVIDENCE",
                    "evidence": record,
                    "collector": record.get("collector"),
                    "source": record.get("source"),
                    "observed_at": record.get("observed_at"),
                    "evidence_type": record.get("evidence_type"),
                    "confidence": record.get("confidence"),
                    "hash": _record_hash(record),
                }
        return {"schema": WHY_SCHEMA, "status": "NO_SUCH_EVIDENCE", "evidence_id": evidence_id}

    source = _resolve(graph, subject) if subject is not None else None
    target = _resolve(graph, obj) if obj is not None else None
    verb = _text(predicate).lower() or None

    if subject is not None and source is None:
        return {
            "schema": WHY_SCHEMA,
            "status": "UNKNOWN_ASSET",
            "detail": f"no asset matches {subject!r}; nothing can be established about it",
        }

    matches = [
        edge
        for edge in graph.relationships()
        if (source is None or edge["subject"] == source)
        and (target is None or edge["object"] == target)
        and (verb is None or edge["predicate"] == verb)
    ]

    if not matches:
        refused = [
            edge
            for edge in graph.unresolved_relationships()
            if (source is None or edge.get("subject") == source)
            and (target is None or edge.get("object") == target)
            and (verb is None or edge.get("predicate") == verb)
        ]
        if refused:
            return {
                "schema": WHY_SCHEMA,
                "status": "NOT_ESTABLISHED",
                "answer": (
                    "this relationship does not exist in the twin. It was refused, and the reason is "
                    "the answer to 'why'"
                ),
                "refused": refused[:MAX_LISTED],
                "note": "an UNKNOWN edge is not a weak relationship — it is the absence of one",
            }
        return {
            "schema": WHY_SCHEMA,
            "status": "NO_SUCH_RELATIONSHIP",
            "subject": source,
            "predicate": verb,
            "object": target,
            "answer": "no such relationship is recorded; the twin does not draw edges it cannot evidence",
        }

    explanations = []
    for edge in matches[:MAX_LISTED]:
        evidence = [record for record in graph.evidence() if str(record["evidence_id"]) in set(edge["evidence_ids"])]
        explanations.append(
            {
                "edge": {
                    "subject": edge["subject"],
                    "subject_name": (graph.asset(edge["subject"]) or {}).get("name"),
                    "predicate": edge["predicate"],
                    "object": edge["object"],
                    "object_name": (graph.asset(edge["object"]) or {}).get("name"),
                    "basis": edge.get("basis"),
                    "confidence": edge.get("confidence"),
                },
                "answer": (
                    f"{edge['predicate'].replace('_', ' ')} is established by {edge.get('basis')} evidence "
                    f"at {edge.get('confidence')} confidence"
                ),
                "evidence": [
                    {
                        "evidence_id": record["evidence_id"],
                        "evidence_type": record["evidence_type"],
                        "collector": record.get("collector"),
                        "source": record.get("source"),
                        "observed_at": record.get("observed_at"),
                        "confidence": record.get("confidence"),
                        "hash": _record_hash(record),
                        "facts": record.get("facts"),
                    }
                    for record in evidence
                ],
            }
        )

    return {
        "schema": WHY_SCHEMA,
        "status": "ESTABLISHED",
        "matches": explanations,
        "note": "every edge in the twin answers 'why' with a collector, a source, a timestamp and a hash",
    }


# --------------------------------------------------------------------------- #
# §26 — search
# --------------------------------------------------------------------------- #


def search(graph: EstateGraph, query: str, *, limit: int = MAX_LISTED) -> dict[str, Any]:
    """Search the twin by algorithm, key size, protocol, name, type or owner."""
    text = _text(query)
    if not text:
        return {
            "schema": SEARCH_SCHEMA,
            "query": text,
            "status": "EMPTY_QUERY",
            "assets": [],
            "artifacts": [],
            "by_asset_type": {},
            "counts": {"assets": 0, "artifacts": 0},
        }
    needle = text.lower()

    def _hit(*values: Any) -> bool:
        return any(needle in str(value).lower() for value in values if value not in (None, ""))

    matched_artifacts = [
        item
        for item in graph.crypto_artifacts()
        if _hit(item.get("algorithm"), item.get("protocol"), item.get("mode"), item.get("curve"), item.get("key_size"))
    ]
    artifact_assets = {item["asset_id"] for item in matched_artifacts}

    matched_assets = [
        asset
        for asset in graph.assets()
        if _hit(asset.get("name"), asset.get("type"), asset.get("environment"), asset.get("owner"))
        or asset["asset_id"] in artifact_assets
    ]

    by_type: dict[str, int] = {}
    for asset in matched_assets:
        by_type[asset["type"]] = by_type.get(asset["type"], 0) + 1

    by_artifact_type: dict[str, int] = {}
    for item in matched_artifacts:
        key = str(item.get("asset_type") or "UNKNOWN")
        by_artifact_type[key] = by_artifact_type.get(key, 0) + 1

    return {
        "schema": SEARCH_SCHEMA,
        "query": text,
        "status": "MATCHED" if matched_assets or matched_artifacts else "NO_MATCH",
        "assets": [ _asset_card(asset) for asset in matched_assets[:limit] ],
        "artifacts": matched_artifacts[:limit],
        "by_asset_type": by_type,
        "by_artifact_asset_type": by_artifact_type,
        "by_usage_state": {
            state: sum(1 for item in matched_artifacts if item["usage_state"] == state)
            for state in ("SUPPORTED", "CONFIGURED", "NEGOTIATED", "OBSERVED")
        },
        "counts": {"assets": len(matched_assets), "artifacts": len(matched_artifacts)},
        "truncated": len(matched_assets) > limit or len(matched_artifacts) > limit,
        "note": (
            "a match on a capability artefact is a match on what the estate *supports*; only "
            "OBSERVED/NEGOTIATED matches describe cryptography that ran"
        ),
    }


# --------------------------------------------------------------------------- #
# §27 — blast radius
# --------------------------------------------------------------------------- #


def impact(
    graph: EstateGraph,
    selector: Mapping[str, Any],
    *,
    depth: int = 3,
) -> dict[str, Any]:
    """Blast radius for an algorithm, protocol, component or asset.

    The traversal uses established edges only, and every report carries its
    unknowns: refused edges touching the reachable set, reachable assets with no
    evidence, and conflicts. A blast radius without its blind spots is a guess
    with a number attached.
    """
    selector = dict(selector or {})
    if not _selector_is_meaningful(selector):
        return {
            "schema": IMPACT_SCHEMA,
            "status": "EMPTY_SELECTOR",
            "detail": "a blast radius needs something to select: an algorithm, protocol, key size, version or asset",
        }

    asset_ref = selector.get("asset")
    seed_assets: set[str] = set()
    matching_artifacts: list[dict[str, Any]] = []

    if asset_ref:
        resolved = _resolve(graph, asset_ref)
        if resolved:
            seed_assets.add(resolved)
    else:
        matching_artifacts = [
            item for item in graph.crypto_artifacts() if _matches_selector(item, selector)
        ]
        seed_assets.update(item["asset_id"] for item in matching_artifacts)

    if not seed_assets:
        return {
            "schema": IMPACT_SCHEMA,
            "status": "NO_MATCH",
            "selector": selector,
            "seed_assets": [],
            "by_type": {},
            "direct": [],
            "transitive": [],
            "detail": (
                "nothing in the twin matches this selector. That is NOT 'no impact' — the estate may "
                "not have been collected, or the algorithm may only exist in sources that were not read"
            ),
            "coverage": graph.coverage()["summary"],
        }

    distance, parent = _walk(graph, seed_assets, depth=depth)
    reached = sorted(distance, key=lambda node: (distance[node], node))
    transitive = [node for node in reached if distance[node] > 0]
    direct = [node for node in reached if distance[node] == 1]

    def _cards(nodes: Iterable[str]) -> list[dict[str, Any]]:
        out = []
        for node in nodes:
            asset = graph.asset(node) or {}
            out.append({**_asset_card(asset), "hops": distance[node]})
        return out

    by_type: dict[str, int] = {}
    for node in reached:
        asset = graph.asset(node) or {}
        key = str(asset.get("type") or "UNKNOWN")
        by_type[key] = by_type.get(key, 0) + 1

    reachable_set = set(reached)
    reachable_artifacts = [
        item for item in graph.crypto_artifacts() if item["asset_id"] in reachable_set
    ]
    unknown_edges = [
        edge
        for edge in graph.unresolved_relationships()
        if {edge.get("subject"), edge.get("object")} & reachable_set
    ]
    no_evidence = [
        node for node in reached if not (graph.asset(node) or {}).get("evidence_refs")
    ]
    conflicts = [item for item in graph.conflicts() if item.get("asset_id") in reachable_set]

    paths = []
    for node in transitive[:10]:
        paths.append({"asset_id": node, "path": _path_to(parent, node, graph)})

    return {
        "schema": IMPACT_SCHEMA,
        "status": "MATCHED",
        "selector": selector,
        "projection_id": graph.fingerprint(),
        "seed_assets": _cards(sorted(seed_assets)),
        "matching_artifacts": matching_artifacts[:MAX_LISTED],
        "matching_artifacts_count": len(matching_artifacts),
        "depth": depth,
        "counts": {
            "seed": len(seed_assets),
            "direct": len(direct),
            "transitive": len(transitive),
            "total": len(reached),
            "business_systems": by_type.get("SYSTEM", 0),
        },
        "by_type": by_type,
        "direct": _cards(direct)[:MAX_LISTED],
        "transitive": _cards(transitive)[:MAX_LISTED],
        "truncated": len(transitive) > MAX_LISTED,
        "paths": paths,
        "crypto_in_radius": {
            "artifacts": len(reachable_artifacts),
            "by_usage_state": {
                state: sum(1 for item in reachable_artifacts if item["usage_state"] == state)
                for state in ("SUPPORTED", "CONFIGURED", "NEGOTIATED", "OBSERVED")
            },
        },
        "blockers": [
            {
                "kind": "UNRESOLVED_RELATIONSHIP",
                "detail": "an edge in this radius is UNKNOWN, so the radius may be larger than shown",
                "subject": edge.get("subject"),
                "predicate": edge.get("predicate"),
                "object": edge.get("object"),
                "reason": edge.get("reason"),
            }
            for edge in unknown_edges[:MAX_LISTED]
        ],
        "unknown": {
            "assets_without_evidence": no_evidence[:MAX_LISTED],
            "assets_without_evidence_count": len(no_evidence),
            "unresolved_relationships": len(unknown_edges),
            "conflicts": conflicts,
        },
        "note": (
            "the radius travels established edges only; refused edges and unevidenced assets are listed "
            "as blind spots instead of being assumed away"
        ),
    }


# --------------------------------------------------------------------------- #
# layer 7 — simulation (§15–§17)
# --------------------------------------------------------------------------- #


def _bom_diff(base: Mapping[str, Any], simulated: Mapping[str, Any]) -> dict[str, Any]:
    def _index(bom: Mapping[str, Any]) -> dict[str, str]:
        out: dict[str, str] = {}
        for component in bom.get("components") or []:
            ref = str(component.get("bom_ref") or component.get("asset_id") or component.get("name"))
            body = {key: value for key, value in component.items() if key not in _VOLATILE_COMPONENT_KEYS}
            out[ref] = _canonical(body)
        return out

    per_bom: dict[str, Any] = {}
    for kind in BOM_KINDS:
        before = _index(base.get(kind) or {})
        after = _index(simulated.get(kind) or {})
        added = sorted(set(after) - set(before))
        removed = sorted(set(before) - set(after))
        changed = sorted(ref for ref in set(before) & set(after) if before[ref] != after[ref])
        per_bom[kind] = {
            "added": added[:MAX_LISTED],
            "removed": removed[:MAX_LISTED],
            "changed": changed[:MAX_LISTED],
            "counts": {
                "added": len(added),
                "removed": len(removed),
                "changed": len(changed),
                "unchanged": len(set(before) & set(after)) - len(changed),
            },
        }
    return {
        "boms": per_bom,
        "any_change": any(
            entry["counts"]["added"] or entry["counts"]["removed"] or entry["counts"]["changed"]
            for entry in per_bom.values()
        ),
    }


def _capability_blockers(
    graph: EstateGraph,
    affected: Iterable[str],
    *,
    target: str | None,
) -> list[dict[str, Any]]:
    """Asserts a blocker only where the twin actually holds capability evidence."""
    if not target:
        return []
    wanted = target.strip().upper()
    blockers: list[dict[str, Any]] = []
    for asset_id in affected:
        for record in graph.evidence():
            if str(record["target"]) != asset_id:
                continue
            facts = record.get("facts") or {}
            declared = facts.get("supported_algorithms") or facts.get("capabilities")
            if not declared:
                continue
            if isinstance(declared, str):
                declared = [declared]
            supported = [str(item).upper() for item in declared]
            if any(wanted in item or item in wanted for item in supported):
                continue
            blockers.append(
                {
                    "kind": "CAPABILITY_NOT_EVIDENCED",
                    "asset_id": asset_id,
                    "asset_name": (graph.asset(asset_id) or {}).get("name"),
                    "detail": (
                        f"{record.get('source')} declares {', '.join(supported) or 'no algorithms'}; "
                        f"nothing in the evidence supports {target} here"
                    ),
                    "evidence_id": record.get("evidence_id"),
                }
            )
    return blockers


def simulate(graph: EstateGraph, scenario: Mapping[str, Any]) -> dict[str, Any]:
    """§15–§17 — ask "what if" on a copy of the twin.

    The live graph is only ever *read*. The scenario is applied to the snapshot
    payload, a new graph is built from it, and the six BOMs are re-projected from
    that graph. The live projection id is captured before and after, so
    "simulation changed nothing" is a checked assertion rather than a promise.
    """
    scenario = dict(scenario or {})
    kind = _text(scenario.get("kind")).upper()
    if kind not in SIMULATION_KINDS:
        return {
            "schema": SIMULATION_SCHEMA,
            "status": "INVALID_SCENARIO",
            "kind": kind or None,
            "detail": f"expected one of {', '.join(SIMULATION_KINDS)}",
        }

    live_projection_before = graph.fingerprint()
    base_snapshot = snapshot(graph)
    payload = copy.deepcopy(base_snapshot["payload"])

    source = _text(scenario.get("from"))
    target = _text(scenario.get("to"))
    target_refs = {_resolve(graph, ref) for ref in scenario.get("targets") or [] if _resolve(graph, ref)}
    if not source and kind in {"REPLACE_ALGORITHM", "RETIRE_ALGORITHM", "DISABLE_PROTOCOL", "UPGRADE_COMPONENT"}:
        return {
            "schema": SIMULATION_SCHEMA,
            "status": "INVALID_SCENARIO",
            "kind": kind,
            "detail": "scenario needs 'from' — a change with no before-state has no measurable effect",
        }
    if kind == "REPLACE_ALGORITHM" and not target:
        return {
            "schema": SIMULATION_SCHEMA,
            "status": "INVALID_SCENARIO",
            "kind": kind,
            "detail": "REPLACE_ALGORITHM needs 'to'",
        }

    matched = 0
    affected: set[str] = set()
    effects: list[dict[str, Any]] = []

    for record in payload["evidence"]:
        facts = record.get("facts") or {}
        if target_refs and str(record.get("target")) not in target_refs:
            continue
        hit = False
        if kind == "REPLACE_ALGORITHM":
            hit = _matches_selector(facts, {"algorithm": source}) or _matches_selector(facts, {"protocol": source})
            if hit:
                if facts.get("algorithm"):
                    facts["simulated_from_algorithm"] = facts["algorithm"]
                    facts["algorithm"] = target
                if facts.get("protocol"):
                    facts["simulated_from_protocol"] = facts["protocol"]
                    facts["protocol"] = target
                if scenario.get("key_size"):
                    facts["key_size"] = scenario["key_size"]
        elif kind == "RETIRE_ALGORITHM":
            hit = _matches_selector(facts, {"algorithm": source}) or _matches_selector(facts, {"protocol": source})
            if hit:
                facts["simulated_retired"] = {
                    "algorithm": facts.get("algorithm"),
                    "protocol": facts.get("protocol"),
                    "key_size": facts.get("key_size"),
                }
                facts["algorithm"] = None
                facts["protocol"] = None
        elif kind == "DISABLE_PROTOCOL":
            hit = _matches_selector(facts, {"protocol": source})
            if hit:
                facts["simulated_disabled_protocol"] = facts["protocol"]
                facts["protocol"] = None
        elif kind == "UPGRADE_COMPONENT":
            hit = False
            for field in ("version", "component", "name"):
                value = facts.get(field)
                if value and source.lower() in str(value).lower():
                    facts["simulated_from_version"] = value
                    facts[f"simulated_{field}"] = target or value
                    if field == "version":
                        facts["version"] = target or value
                    hit = True
        if hit:
            matched += 1
            affected.add(str(record.get("target")))
            effects.append(
                {
                    "evidence_id": record.get("evidence_id"),
                    "asset_id": record.get("target"),
                    "asset_name": (graph.asset(str(record.get("target"))) or {}).get("name"),
                    "layer": record.get("layer"),
                    "evidence_type": record.get("evidence_type"),
                    "before": record.get("facts") or {},
                    "after": facts,
                }
            )

    if matched == 0:
        return {
            "schema": SIMULATION_SCHEMA,
            "status": "NO_MATCH",
            "kind": kind,
            "scenario": scenario,
            "base_projection_id": live_projection_before,
            "live_state_modified": False,
            "detail": (
                "no evidence matched this scenario, so nothing can be said about its impact. This is "
                "not 'no impact': the estate may not describe the artefact, or it may live in a "
                "source that was never collected"
            ),
            "coverage": graph.coverage()["summary"],
        }

    simulated_graph = build_graph(payload)
    simulated_snapshot = snapshot(simulated_graph)

    base_boms = graph.project_all()
    simulated_boms = simulated_graph.project_all()
    diff = _bom_diff(base_boms["boms"], simulated_boms["boms"])

    simulated_impact = impact(simulated_graph, {"asset": None, "algorithm": target or source}, depth=3) \
        if (target or source) else {"status": "NO_MATCH"}
    if simulated_impact.get("status") != "MATCHED":
        # fall back to the affected assets themselves rather than an empty radius
        distance, parent = _walk(simulated_graph, affected, depth=3)
        simulated_impact = {
            "status": "MATCHED",
            "counts": {"total": len(distance), "seed": len(affected)},
            "by_type": {
                type_name: sum(
                    1 for node in distance
                    if (simulated_graph.asset(node) or {}).get("type") == type_name
                )
                for type_name in sorted({
                    (simulated_graph.asset(node) or {}).get("type") or "UNKNOWN" for node in distance
                })
            },
            "note": "radius computed from the changed assets themselves",
        }

    # a capability blocker is worth reporting anywhere in the radius, not only on
    # the asset that changed: a library three hops away that cannot do the new
    # algorithm is exactly the thing a migration plan needs to see
    radius, _parents = _walk(graph, affected, depth=3)
    blockers = list(_capability_blockers(graph, set(affected) | set(radius), target=target or None))
    for edge in graph.unresolved_relationships():
        if {edge.get("subject"), edge.get("object")} & affected:
            blockers.append(
                {
                    "kind": "UNRESOLVED_RELATIONSHIP",
                    "detail": "a refused edge touches a changed asset, so its true radius is unknown",
                    "subject": edge.get("subject"),
                    "predicate": edge.get("predicate"),
                    "object": edge.get("object"),
                    "reason": edge.get("reason"),
                }
            )

    live_projection_after = graph.fingerprint()

    return {
        "schema": SIMULATION_SCHEMA,
        "status": "SIMULATED",
        "simulation_id": f"sim:{_canonical({'projection': live_projection_before, 'scenario': scenario})[:24]}",
        "kind": kind,
        "scenario": scenario,
        "base_snapshot": base_snapshot["snapshot_id"],
        "base_projection_id": live_projection_before,
        "simulated_projection_id": simulated_snapshot["projection_id"],
        "live_state_modified": live_projection_before != live_projection_after,
        "live_projection_unchanged": live_projection_before == live_projection_after,
        "matched_evidence": matched,
        "affected_assets": [
            {"asset_id": asset_id, "name": (graph.asset(asset_id) or {}).get("name"),
             "type": (graph.asset(asset_id) or {}).get("type")}
            for asset_id in sorted(affected)
        ],
        "effects": effects[:MAX_LISTED],
        "impact": {
            "counts": simulated_impact.get("counts"),
            "by_type": simulated_impact.get("by_type"),
        },
        "bom_diff": diff["boms"],
        "bom_changes": diff["any_change"],
        "blockers": blockers[:MAX_LISTED],
        "unknown": {
            "unresolved_relationships_touching_affected": sum(
                1 for edge in graph.unresolved_relationships()
                if {edge.get("subject"), edge.get("object")} & affected
            ),
            "affected_assets_without_evidence": sum(
                1 for asset_id in affected if not (graph.asset(asset_id) or {}).get("evidence_refs")
            ),
            "affected_assets_without_evidence_note": (
                "these assets are in the blast radius but the twin holds no evidence for them, so "
                "their role in the change is unknown rather than absent"
            ),
        },
        "note": (
            "the scenario was applied to a copy of the twin; the six BOMs are projections of that copy, "
            "and the live projection id is identical before and after"
        ),
    }


def overview(graph: EstateGraph) -> dict[str, Any]:
    """§24 — the estate screen: what the twin holds, in one read."""
    placement = placement_model(graph)
    return {
        "schema": TWIN_SCHEMA,
        "model": "cryptoscan.estate-twin-overview/1",
        "estate": graph.estate,
        "projection_id": graph.fingerprint(),
        "levels": list(ESTATE_LEVELS),
        "asset_types": sorted(ASSET_TYPES),
        "summary": graph.summary(),
        "placement": {
            "environments": placement["environments"],
            "unplaced_count": placement["unplaced_count"],
            "business_systems": placement["business_systems"],
        },
        "completeness": completeness(graph),
        "note": (
            "the twin is one correlated model: the six BOMs, the coverage matrix and the completeness "
            "report are all views of this snapshot"
        ),
    }


__all__ = [
    "COMPLETENESS_SCHEMA",
    "ESTATE_LEVELS",
    "IMPACT_SCHEMA",
    "SIMULATION_KINDS",
    "SIMULATION_SCHEMA",
    "SNAPSHOT_SCHEMA",
    "STRENGTH_ORDER",
    "TWIN_SCHEMA",
    "completeness",
    "graph_from_snapshot",
    "impact",
    "investigate",
    "overview",
    "placement_model",
    "search",
    "simulate",
    "snapshot",
    "why",
]
