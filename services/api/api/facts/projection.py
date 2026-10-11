"""Pure fact projection over evidence rows (no ORM dependency).

Input rows are plain dicts in the EvidenceRecord column shape (the
``to_dict()`` / repository shape). Grouping is by the fact identity
below; every group keeps its evidence ids so the "WHERE EXACTLY / HOW"
question from advanced/48 is answered by reference, not by copy.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping, Optional

#: maximum evidence ids carried inline per fact (the count stays honest)
MAX_EVIDENCE_REFS = 50


def fact_key(row: Mapping[str, Any]) -> tuple:
    """Fact identity: what + why + where + parameters.

    Line number is deliberately NOT part of the identity: the same
    algorithm/purpose/parameters in the same file is one fact observed
    at several lines (lines stay on the evidence rows).
    """
    return (
        str(row.get("algorithm") or "UNKNOWN"),
        str(row.get("purpose") or ""),
        str(row.get("file_path") or ""),
        row.get("key_size"),
        str(row.get("mode") or ""),
    )


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
        groups[fact_key(row)].append(row)

    facts: list[dict[str, Any]] = []
    for key in sorted(groups, key=lambda k: (k[2], k[0], k[1], str(k[3]), k[4])):
        members = groups[key]
        algorithm, purpose, file_path, key_size, mode = key
        seen = sorted({_iso(m.get("created_at")) for m in members if m.get("created_at")})
        confidences = sorted({str(m.get("confidence") or "") for m in members if m.get("confidence")})
        scanners = sorted({s for s in (_scanner_id(m) for m in members) if s})
        evidence_ids = [str(m.get("id")) for m in members]
        facts.append({
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
