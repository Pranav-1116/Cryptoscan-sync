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

from cbom.cross_bom import compare_members, index_bom


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _compact(value: Any) -> str:
    """Algorithm comparison that survives 'RSA-2048' vs 'RSA 2048'."""
    return re.sub(r"[\s-]+", "", str(value or "").lower())


def _index(boms: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for bom_kind, document in boms.items():
        rows.extend(index_bom(bom_kind, document or {}))
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

    # Resolve every identity once (members, BOMs present, conflicts and
    # variations) before any filter is applied: the estate-wide summary below
    # and the filtered matches then read from the same comparison, so a
    # filtered page can never report different conflict totals than the
    # unfiltered estate it came from.
    groups: dict[str, dict[str, Any]] = {}
    for ident, members in sorted(by_identity.items()):
        boms_present = sorted({m["bom"] for m in members})
        conflicts, variations = compare_members(members)
        groups[ident] = {
            "members": members,
            "boms": boms_present,
            "linked": len(boms_present) >= 2,
            "conflicts": conflicts,
            "variations": [{"identity": ident, **entry} for entry in variations],
        }

    matches: list[dict[str, Any]] = []
    for ident, group in groups.items():
        members = group["members"]
        boms_present = group["boms"]
        linked = group["linked"]

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

        conflicts, variations = group["conflicts"], group["variations"]

        if conflicts_only and not conflicts:
            continue

        matches.append({
            "identity": ident,
            "kind": members[0]["kind"],
            "label": members[0]["label"],
            "boms": boms_present,
            "bom_count": len(boms_present),
            "linked": linked,
            "relationship": ("algorithm_association" if members[0]["kind"] == "crypto"
                             else "attribute_association"),
            "asset_identity_confirmed": False,
            "present_in": [{"bom": m["bom"], "ref": m["ref"],
                            "values": m["values"]} for m in members],
            "conflicts": conflicts,
            "variations": variations,
        })

    # Estate-wide arithmetic over EVERY identity, computed before/independently
    # of the filters above. The CBOM page's headline cards are these numbers,
    # so a searched or filtered table cannot present a subset total as the
    # estate's total.
    by_kind: dict[str, int] = {}
    by_bom: dict[str, int] = {}
    for group in groups.values():
        kind_key = group["members"][0]["kind"]
        by_kind[kind_key] = by_kind.get(kind_key, 0) + 1
        for bom_kind in group["boms"]:
            by_bom[bom_kind] = by_bom.get(bom_kind, 0) + 1
    linked_total = sum(1 for group in groups.values() if group["linked"])
    summary: dict[str, Any] = {
        "identities": len(groups),
        "linked": linked_total,
        "single_source": len(groups) - linked_total,
        "conflict_count": sum(len(group["conflicts"]) for group in groups.values()),
        "variation_count": sum(len(group["variations"]) for group in groups.values()),
        "by_kind": [{"kind": k, "identities": n}
                    for k, n in sorted(by_kind.items(), key=lambda kv: (-kv[1], kv[0]))],
        "by_bom": [{"bom": k, "identities": n}
                   for k, n in sorted(by_bom.items(), key=lambda kv: (-kv[1], kv[0]))],
        "scope": "estate-wide — counts every canonical identity, not the filtered result",
        "asset_identity_confirmed": False,
    }

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
        "summary": summary,
        "conflict_count": sum(len(m["conflicts"]) for m in matches),
        "variation_count": sum(len(m["variations"]) for m in matches),
        "note": "Canonical keys associate matching algorithms/names, not confirmed "
                "physical assets. Unlinked identities exist in exactly one BOM; "
                "mixed values within one BOM are variations, not conflicts.",
    }
    if unknown_bom:
        response["identities_matching"] = 0
        response["matches"] = []
        response["error"] = (f"unknown BOM {bom_filter!r}; available: "
                             f"{sorted(boms.keys())}")
    return response
