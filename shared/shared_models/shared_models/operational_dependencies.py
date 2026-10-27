"""Conditional review of declared dependency modes, never an availability model."""

from collections import Counter
from copy import deepcopy
import json
import math

from shared_models.dependency_semantics import edge_relation, propagates, system_id
from shared_models.relationship_lifecycle import current, utc

SCHEMA = "cryptoscan.operational-impact/1"
CONDITION_SCHEMA = "cryptoscan.operational-dependency/1"
MODES = ("UNKNOWN", "HARD", "OPTIONAL", "FAILOVER", "ASYNC_BUFFERED")
EDGE_LIMIT = 500
FIELDS = {
    "mode",
    "assumptions",
    "evidence_ref",
    "failover_system_ids",
    "buffer_capacity_messages",
    "buffer_retention_seconds",
}
OUTCOMES = {
    "UNKNOWN": "Operational consequence unknown; do not default to failure or safety.",
    "HARD": "If this provider becomes unavailable to the relevant function, the declared required dependency may block that function. This is not proof the entire consumer fails.",
    "OPTIONAL": "If this provider becomes unavailable, the declared optional function may degrade. Continued core service is not verified and exposure is not removed.",
    "FAILOVER": "If this provider becomes unavailable, continuity depends on routing, independent healthy alternatives, capacity and successful switchover. A declared alternative is not verified failover.",
    "ASYNC_BUFFERED": "If this provider becomes unavailable, buffering may defer consumer disruption. Outcome depends on usable headroom, arrival/drain rates, retention and recovery/replay; no safe delay is calculated.",
}


def validate_assertion(value):
    """Strict, bounded JSON contract shared by API and defensive readers."""
    if not isinstance(value, dict) or set(value) - FIELDS or value.get("mode") not in MODES:
        raise ValueError("operational dependency requires a supported mode and known fields only")
    mode = value["mode"]
    result = {"mode": mode}
    assumptions = value.get("assumptions", [])
    if not isinstance(assumptions, list) or len(assumptions) > 20:
        raise ValueError("at most 20 operational assumptions are allowed")
    if any(not isinstance(v, str) or not v.strip() or len(v) > 500 for v in assumptions):
        raise ValueError("assumptions must be nonempty strings of at most 500 characters")
    result["assumptions"] = [v.strip() for v in assumptions]
    ref = value.get("evidence_ref")
    if ref is not None:
        if not isinstance(ref, str) or not ref.strip() or len(ref) > 500:
            raise ValueError("operational evidence_ref must be a nonempty bounded string")
        result["evidence_ref"] = ref.strip()
    ids = value.get("failover_system_ids", [])
    if (
        not isinstance(ids, list)
        or len(ids) > 20
        or any(not isinstance(v, str) or not v or len(v) > 36 or v != v.strip() or ":" in v for v in ids)
    ):
        raise ValueError("failover alternatives require at most 20 exact raw system IDs")
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate failover system IDs")
    if ids and mode != "FAILOVER":
        raise ValueError("failover alternatives require FAILOVER mode")
    if mode == "FAILOVER":
        result["failover_system_ids"] = sorted(ids)
    for field in ("buffer_capacity_messages", "buffer_retention_seconds"):
        number = value.get(field)
        if number is None:
            continue
        valid = (
            (type(number) is int and 0 <= number <= 2**53 - 1)
            if field == "buffer_capacity_messages"
            else (type(number) in (float, int) and math.isfinite(number) and 0 < number <= 2**53 - 1)
        )
        if not valid or mode != "ASYNC_BUFFERED":
            raise ValueError(
                f"{field} requires a finite nonnegative capacity/positive retention in ASYNC_BUFFERED mode"
            )
        result[field] = number
    return result


def assertion_from_edge(row):
    if "operational_dependency" in row:
        return row["operational_dependency"]
    encoded = row.get("operational_dependency_json")
    if encoded is None:
        return None
    try:
        return json.loads(encoded)
    except (ValueError, TypeError):
        return {"mode": "INVALID"}  # corrupt native metadata stays unknown, never hard


def condition(value, *, known_systems=None, consumer=None, provider=None):
    status = "UNSPECIFIED" if value is None else "DECLARED"
    try:
        assertion = validate_assertion(value) if value is not None else {"mode": "UNKNOWN", "assumptions": []}
    except (ValueError, TypeError, OverflowError):
        status, assertion = "INVALID", {"mode": "UNKNOWN", "assumptions": []}
    mode = assertion["mode"]
    gaps = []
    if mode == "UNKNOWN":
        gaps.append("Mode is missing, explicitly unknown or invalid; operational coupling is not established.")
    if not assertion.get("evidence_ref"):
        gaps.append(
            "Operational-mode evidence reference missing; general relationship evidence does not verify this mode."
        )
    if not assertion.get("assumptions"):
        gaps.append("Operational assumptions are not recorded.")
    alternatives = assertion.get("failover_system_ids") or []
    loaded = [] if known_systems is None else sorted(set(alternatives) & set(known_systems))
    unresolved = [] if known_systems is None else sorted(set(alternatives) - set(known_systems))
    invalid_alternatives = sorted(set(alternatives) & {consumer, provider})
    if mode == "FAILOVER":
        if not alternatives:
            gaps.append("No exact alternative system IDs recorded.")
        if unresolved or known_systems is None or invalid_alternatives:
            gaps.append(
                "Alternative identity resolution is incomplete/invalid; unresolved references are not proof the systems do not exist."
            )
        gaps.append(
            "Alternative health, independence, capacity, routing and switchover behavior have not been verified by this evaluation."
        )
    if mode == "ASYNC_BUFFERED":
        for field in ("buffer_capacity_messages", "buffer_retention_seconds"):
            if field not in assertion:
                gaps.append(f"Declared {field} is missing.")
        gaps.append(
            "Current headroom, workload rates, durability and recovery/replay are not verified; no time-to-impact is inferred from declared capacity or retention."
        )
    return {
        "schema": CONDITION_SCHEMA,
        "mode": mode,
        "assertion_status": status,
        "assertion": assertion,
        "conditional_outcome": OUTCOMES[mode],
        "gaps": gaps,
        "failover_references": {
            "resolution": "not_loaded" if known_systems is None else "loaded_registry_only",
            "loaded_system_ids": loaded,
            "not_in_loaded_registry": unresolved,
            "invalid_self_or_provider_ids": invalid_alternatives,
        },
        "verified": False,
        "failure_probability": None,
        "safe_delay_seconds": None,
        "note": "Declared mode/assumptions, not observed availability or a guaranteed operational outcome. Alternatives do not create dependency edges.",
    }


def project_operational_dependencies(edges, classification, *, known_systems, now, source_coverage=None):
    """All loaded propagating edges WITHIN review scope, not a sampled BFS path.

    Mode never changes exposure membership. Detail bounds never change counts.
    No path-level hard/optional algebra or correlated-failover guarantee is made.
    """
    from shared_models.traversal_evidence import edge_evidence  # avoid metadata import cycle

    known = {system_id(s) for s in known_systems}
    review = set(classification.get("review_systems") or [])
    scopes = {
        sid: scope
        for scope in ("direct_exposure", "dependent_consumers", "supporting_context")
        for sid in (classification.get(scope) or {}).get("systems") or []
    }
    records, excluded = {}, set()
    for row in edges:
        src = system_id(row.get("from") or row.get("parent_id") or row.get("source"))
        dst = system_id(row.get("to") or row.get("child_id") or row.get("target"))
        if (
            src not in known
            or dst not in known
            or src not in review
            or dst not in review
            or not propagates(edge_relation(row))
        ):
            continue
        normalized = {**row, "from": src, "to": dst}
        if "target" in row and "from" not in row and "parent_id" not in row:
            # Twin `source` is the consumer endpoint, not provenance. Never
            # relabel a system ID as an evidence origin.
            normalized["source"] = row.get("relationship_source")
        identity = (src, dst, edge_relation(row), str(row.get("record_id") or row.get("id") or ""))
        signature = (*identity, json.dumps(normalized, sort_keys=True, default=str))
        if not current(row, now=now):
            excluded.add(signature)
            continue
        records[signature] = {
            "from": src,
            "to": dst,
            "relation": edge_relation(row),
            "record_id": identity[-1] or None,
            "consumer_scope": scopes.get(src),
            "provider_scope": scopes.get(dst),
            "condition": condition(assertion_from_edge(row), known_systems=known, consumer=src, provider=dst),
            "relationship_evidence": edge_evidence(normalized, now=now),
        }
    rows = [records[key] for key in sorted(records)]
    counts = Counter(row["condition"]["mode"] for row in rows)
    return {
        "schema": SCHEMA,
        "as_of": utc(now).isoformat(),
        "analysis_kind": "conditional_dependency_review",
        "provider_disruption_assumed": False,
        "mode_counts": {m: counts[m] for m in MODES},
        "edge_count": len(rows),
        "edges": rows[:EDGE_LIMIT],
        "edge_limit": EDGE_LIMIT,
        "edges_truncated": len(rows) > EDGE_LIMIT,
        "non_current_edge_count": len(excluded),
        "source_coverage": deepcopy(source_coverage),
        "scope": "loaded current propagating system edges with both endpoints in classified review scope; not all estate dependencies or all paths",
        "note": "Modes do not remove optional/failover/buffered dependencies from exposure. Mixed paths and multiple providers are not collapsed into a system failure verdict. No failure probability, guaranteed failover or safe buffering duration is computed.",
    }


def compare_operational_impacts(old, new):
    projections = [
        (r or {}).get("operational_impact") or (r or {}).get("impact", {}).get("operational_impact") or {}
        for r in (old, new)
    ]
    if any(p.get("schema") != SCHEMA or p.get("edges_truncated") is not False for p in projections):
        return {
            "comparable": False,
            "reason": "Operational projection schema unavailable or detail truncated; mode changes cannot be reconstructed from bounded listings.",
        }

    def index(projection):
        result = {}
        for row in projection.get("edges") or []:
            key = json.dumps([row["from"], row["to"], row["relation"], row.get("record_id")])
            value = row["condition"]
            result.setdefault(key, set()).add(
                json.dumps([value["assertion_status"], value["assertion"]], sort_keys=True)
            )
        return result

    before, after = [index(p) for p in projections]
    return {
        "comparable": True,
        "schema": SCHEMA,
        "added_edges": sorted(after.keys() - before.keys()),
        "removed_edges": sorted(before.keys() - after.keys()),
        "changed_edges": sorted(k for k in before.keys() & after.keys() if before[k] != after[k]),
        "note": "Changes to stored declarations, not measured availability changes. Requires comparable target/system policy in the caller.",
    }
