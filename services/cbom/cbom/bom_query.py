"""Unified BOM query layer (advanced/46, round 37).

Report 46's last ❌ row this repo can close: with round 36's canonical
identity + linking in place, ``query_boms`` answers cross-BOM questions
over any set of BOM documents — where does this identity appear (each
BOM's own ref), what does each BOM say about it, where do they disagree,
and which identities live in exactly one BOM (coverage gaps).

Pure: documents in, answer out. The API layer builds the documents from
the live inventory through the same helper as /cbom/cross-links, so the
two surfaces can never disagree about what they linked.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from cbom.cross_bom import _iter_components, canonical_identity, _comparable_values


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _compact(value: Any) -> str:
    """Algorithm comparison that survives 'RSA-2048' vs 'RSA 2048'."""
    return re.sub(r"[\s-]+", "", str(value or "").lower())


def _index(boms: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for bom_kind, document in boms.items():
        for component in _iter_components(document or {}):
            if not isinstance(component, Mapping):
                continue
            ident = canonical_identity(component)
            if ident is None:
                continue
            rows.append({
                "bom": bom_kind,
                "kind": ident["kind"],
                "identity": ident["identity"],
                "label": ident["label"],
                "ref": str(component.get("bom-ref") or "").strip() or None,
                "values": _comparable_values(component),
            })
    return rows


def query_boms(
    boms: Mapping[str, Mapping[str, Any]],
    *,
    identity: str | None = None,
    kind: str | None = None,
    bom: str | None = None,
    algorithm: str | None = None,
    linked_only: bool = False,
    unlinked_only: bool = False,
    conflicts_only: bool = False,
) -> dict[str, Any]:
    """Answer one cross-BOM question. Raises nothing; empty is an answer."""
    rows = _index(boms)

    # group once; every filter reads from this grouping
    by_identity: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_identity.setdefault(row["identity"], []).append(row)

    kind_filter = _norm(kind)
    bom_filter = _norm(bom)
    algorithm_filter = _norm(algorithm)
    identity_filter = (identity or "").strip()

    unknown_bom = bool(bom_filter) and bom_filter not in {
        _norm(k) for k in boms}

    matches: list[dict[str, Any]] = []
    for ident, members in sorted(by_identity.items()):
        boms_present = sorted({m["bom"] for m in members})
        linked = len(boms_present) >= 2

        if identity_filter and ident != identity_filter:
            continue
        if kind_filter and members[0]["kind"] != kind_filter:
            continue
        if algorithm_filter:
            if members[0]["kind"] != "crypto":
                continue
            wanted = _compact(algorithm_filter)
            label = _compact(members[0]["label"])
            if wanted not in label and label not in wanted:
                continue
        if bom_filter:
            if bom_filter not in boms_present:
                continue
        if linked_only and not linked:
            continue
        if unlinked_only and linked:
            continue

        # per-identity conflicts (same field, disagreeing non-empty values)
        fields: dict[str, dict[str, str]] = {}
        for member in members:
            for field, value in member["values"].items():
                fields.setdefault(field, {})[member["bom"]] = value
        conflicts = [
            {"field": field,
             "values": [{"bom": b, "value": v} for b, v in sorted(values.items())]}
            for field, values in sorted(fields.items())
            if len(set(values.values())) > 1
        ]

        if conflicts_only and not conflicts:
            continue

        matches.append({
            "identity": ident,
            "kind": members[0]["kind"],
            "label": members[0]["label"],
            "boms": boms_present,
            "bom_count": len(boms_present),
            "linked": linked,
            "present_in": [{"bom": m["bom"], "ref": m["ref"],
                            "values": m["values"]} for m in members],
            "conflicts": conflicts,
        })

    response: dict[str, Any] = {
        "model": "cross-bom/query-v1",
        "boms": sorted(boms.keys()),
        "query": {
            "identity": identity_filter or None,
            "kind": kind_filter or None,
            "bom": bom_filter or None,
            "algorithm": algorithm_filter or None,
            "linked_only": bool(linked_only),
            "unlinked_only": bool(unlinked_only),
            "conflicts_only": bool(conflicts_only),
        },
        "identities_total": len(by_identity),
        "identities_matching": len(matches),
        "matches": matches,
        "conflict_count": sum(len(m["conflicts"]) for m in matches),
        "note": "identities are the canonical ones from cross_bom (round "
                "36); unlinked identities exist in exactly one BOM — a "
                "coverage gap, not an error",
    }
    if unknown_bom:
        response["identities_matching"] = 0
        response["matches"] = []
        response["error"] = (f"unknown BOM {bom_filter!r}; available: "
                             f"{sorted(boms.keys())}")
    return response
