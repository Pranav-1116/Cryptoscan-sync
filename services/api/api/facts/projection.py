"""Pure fact projection over evidence rows (no ORM dependency).

Input rows are plain dicts in the EvidenceRecord column shape (the
``to_dict()`` / repository shape). Grouping is by the fact identity
below; every group keeps its evidence ids so the "WHERE EXACTLY / HOW"
question from advanced/48 is answered by reference, not by copy.
"""

from __future__ import annotations

import base64
import json
from collections import defaultdict
from typing import Any, Iterable, Mapping, Optional

#: maximum evidence ids carried inline per fact (the count stays honest)
MAX_EVIDENCE_REFS = 50


# fact identity lives in the database kernel (round 35): the fact store
# and this live projection share ONE definition of what a fact is
from db.fact_projection import fact_key  # noqa: F401 — re-exported truth


def _scanner_id(row: Mapping[str, Any]) -> str:
    finding = row.get("finding_data")
    if isinstance(finding, Mapping):
        return str(finding.get("scanner_id")
                   or (finding.get("metadata") or {}).get("scanner_id")
                   or "")
    return ""


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def project_facts(
    rows: Iterable[Mapping[str, Any]],
    *,
    max_evidence_refs: int = MAX_EVIDENCE_REFS,
) -> list[dict[str, Any]]:
    """Group evidence rows into facts (deterministic order)."""
    groups: dict[tuple, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows or ():
        groups[(row.get("tenant_id"), fact_key(row))].append(row)

    facts: list[dict[str, Any]] = []
    for tenant_id, key in sorted(groups, key=lambda k: (
            k[1][2], k[1][0], k[1][1], str(k[1][3]), k[1][4], str(k[0] or ""))):
        members = groups[(tenant_id, key)]
        algorithm, purpose, file_path, key_size, mode = key
        seen = sorted({_iso(m.get("created_at")) for m in members if m.get("created_at")})
        confidences = sorted({str(m.get("confidence") or "") for m in members if m.get("confidence")})
        scanners = sorted({s for s in (_scanner_id(m) for m in members) if s})
        evidence_ids = sorted(str(m.get("id")) for m in members)
        facts.append({
            "tenant_id": tenant_id,
            "fact": {
                "algorithm": algorithm,
                "purpose": purpose or None,
                "file_path": file_path or None,
                "key_size": key_size,
                "mode": mode or None,
            },
            "observation_count": len(members),
            "first_seen": seen[0] if seen else None,
            "last_seen": seen[-1] if seen else None,
            "scanners": scanners,
            "confidences": confidences,
            "hardcoded_key_observations": sum(
                1 for m in members if m.get("is_hardcoded_key")),
            "evidence_ids": evidence_ids[:max_evidence_refs],
            "evidence_count": len(evidence_ids),
            "evidence_truncated": len(evidence_ids) > max_evidence_refs,
        })
    return facts


def summarize_facts(facts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Estate-level rollup of a fact list."""
    facts = list(facts or ())
    algorithms: dict[str, int] = {}
    purposes: dict[str, int] = {}
    for item in facts:
        f = item.get("fact") or {}
        algorithms[f.get("algorithm") or "UNKNOWN"] = (
            algorithms.get(f.get("algorithm") or "UNKNOWN", 0) + 1)
        purposes[f.get("purpose") or "UNKNOWN"] = (
            purposes.get(f.get("purpose") or "UNKNOWN", 0) + 1)
    return {
        "facts_total": len(facts),
        "observations_total": sum(int(i.get("observation_count") or 0) for i in facts),
        "distinct_algorithms": len(algorithms),
        "facts_by_algorithm": dict(sorted(algorithms.items())),
        "facts_by_purpose": dict(sorted(purposes.items())),
        "facts_with_hardcoded_keys": sum(
            1 for i in facts if i.get("hardcoded_key_observations")),
    }


def _graph_identity(*parts: Any) -> str:
    """Unambiguous, stable node suffix for the complete tenant-local identity."""
    payload = json.dumps(parts, separators=(",", ":"), ensure_ascii=False)
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def code_graph_facts(facts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Code-level fact graph slice: file DEFINES fact OBSERVED_BY evidence.

    A bounded, honest slice of the code-level fact graph (advanced/48
    P1#11, advanced/58): file nodes link to the cryptographic facts their
    code defines/uses, and each fact cites its exact evidence records.
    ``CALLS`` edges need call-graph parsing the scanners do not produce
    today, so they are absent and stated as absent — not guessed from
    co-location. A live projection over the same evidence rows as
    ``GET /facts/crypto``; nothing persisted, no rearchitecture.
    """
    facts = list(facts or ())
    files: dict[tuple[str | None, str], dict[str, Any]] = {}
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for item in facts:
        fact = item.get("fact") or {}
        tenant_id = item.get("tenant_id")
        file_path = str(fact.get("file_path") or "") or "(unknown file)"
        file_key = (tenant_id, file_path)
        # Preserve the familiar platform file ID for ordinary paths. The
        # versioned encoding keeps tenant paths (and reserved platform paths)
        # disjoint even if a path itself contains delimiters.
        file_id = (f"file:v2:{_graph_identity(tenant_id, file_path)}"
                   if tenant_id is not None or file_path.startswith("v2:")
                   else f"file:{file_path}")
        if file_key not in files:
            files[file_key] = {"node_count": 0, "id": file_id}
        fact_id = (f"fact:{fact.get('algorithm')}:v2:"
                   f"{_graph_identity(tenant_id, fact.get('algorithm'), fact.get('purpose'), file_path, fact.get('key_size'), fact.get('mode'))}")
        files[file_key]["node_count"] += 1
        nodes.append({
            "id": fact_id,
            "type": "fact",
            "tenant_id": tenant_id,
            "algorithm": fact.get("algorithm"),
            "purpose": fact.get("purpose"),
            "file": file_path,
            "key_size": fact.get("key_size"),
            "mode": fact.get("mode"),
            "observation_count": item.get("observation_count"),
            "hardcoded_key_observations": item.get("hardcoded_key_observations"),
        })
        edges.append({
            "from": file_id,
            "to": fact_id,
            "relation": "DEFINES",
        })
        for evidence_id in item.get("evidence_ids") or []:
            edges.append({
                "from": fact_id,
                "to": f"evidence:{evidence_id}",
                "relation": "OBSERVED_BY",
            })

    for tenant_id, file_path in sorted(files, key=lambda k: (k[1], str(k[0] or ""))):
        file_info = files[(tenant_id, file_path)]
        nodes.append({
            "id": file_info["id"],
            "type": "file",
            "tenant_id": tenant_id,
            "file_path": file_path,
            "fact_count": file_info["node_count"],
        })

    return {
        "model": "code-fact-graph/read-projection-v1",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "file_count": len(files),
        "nodes": nodes,
        "edges": edges,
        "relations": ["DEFINES", "OBSERVED_BY"],
        "open_relations": {
            "CALLS": "needs call-graph parsing the scanners do not "
                     "produce; absent, not guessed from co-location",
        },
    }
