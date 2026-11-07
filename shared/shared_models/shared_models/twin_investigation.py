"""Digital Twin investigation journeys (gap analysis §F).

The review names one behaviour to validate:

    "Can an investigator start with a certificate, find every asset using it,
    see the evidence for each connection, and determine which business systems
    could be affected by its expiry?"

This module answers that question over evidence-backed rows and refuses to
paper over the gaps: a connection without evidence is listed as unevidenced,
an owner nobody recorded stays ``unknown``, and a business system reached only
through unevidenced edges is marked assumed, not affected.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

JOURNEY_SCHEMA = "cryptoscan.twin-investigation/1"


def _edge_proven(edge: Mapping[str, Any]) -> bool:
    return bool(edge.get("evidence_ids"))


def investigate_certificate(
        *, certificate_id: str,
        usage_edges: Iterable[Mapping[str, Any]],
        dependency_edges: Iterable[Mapping[str, Any]],
        ownership: Mapping[str, Any] | None = None,
        expiry: str | None = None) -> dict[str, Any]:
    """The certificate journey: users → evidence → dependent business systems.

    * ``usage_edges`` — (asset --uses--> certificate) rows, each with its
      evidence ids; edges without evidence are reported as ``unevidenced``
      and never counted as proven use;
    * ``dependency_edges`` — (system --depends_on--> asset) rows for impact
      traversal; a dependency chain with any unevidenced hop is an *assumed*
      path, reported as such and never as proven impact;
    * ``ownership`` — asset/system → owner; a missing owner is reported as
      "unknown", never filled in.
    """
    usage = [dict(e) for e in usage_edges]
    deps = [dict(e) for e in dependency_edges]
    owners = dict(ownership or {})

    proven_users, unevidenced_users = [], []
    for edge in usage:
        row = {
            "asset": edge.get("asset"),
            "relationship": edge.get("relationship", "uses"),
            "evidence_ids": list(edge.get("evidence_ids") or []),
            "owner": owners.get(edge.get("asset"), "unknown"),
        }
        (proven_users if _edge_proven(edge) else unevidenced_users).append(row)

    systems: dict[str, dict[str, Any]] = {}
    for edge in deps:
        system = str(edge.get("system") or edge.get("from"))
        via = str(edge.get("asset") or edge.get("to"))
        proven_path = _edge_proven(edge) and any(
            u["asset"] == via and u["evidence_ids"] for u in proven_users)
        entry = systems.setdefault(system, {
            "system": system,
            "owner": owners.get(system, "unknown"),
            "paths": [],
            "proven": False,
        })
        entry["paths"].append({
            "system": system, "via_asset": via,
            "evidence_ids": list(edge.get("evidence_ids") or []),
            "path_provenance": "PROVEN" if proven_path else "ASSUMED",
            "why": ("every hop carries evidence"
                    if proven_path else
                    "a hop without evidence is assumed, not proven impact"),
        })
        entry["proven"] = entry["proven"] or proven_path

    affected = sorted(s for s, e in systems.items() if e["proven"])
    assumed = sorted(s for s, e in systems.items() if not e["proven"])

    return {
        "schema": JOURNEY_SCHEMA,
        "certificate_id": str(certificate_id),
        "expiry": str(expiry) if expiry else None,
        "assets_using": sorted(
            [u["asset"] for u in proven_users if u["asset"]]),
        "connections": {
            "proven": proven_users,
            "unevidenced": unevidenced_users,
        },
        "business_systems": {
            "affected": [dict(systems[s], impact="PROVEN") for s in affected],
            "assumed": [dict(systems[s], impact="ASSUMED") for s in assumed],
        },
        "unknown_owners": sorted(
            {row["owner"] for row in proven_users if row["owner"] == "unknown"}
            | {e["owner"] for e in systems.values() if e["owner"] == "unknown"}),
        "blind_spots": [
            {"kind": "UNEVIDENCED_CONNECTION", "detail": u["asset"],
             "is_clean_result": False}
            for u in unevidenced_users
        ] + [
            {"kind": "ASSUMED_PATH", "detail": s,
             "is_clean_result": False}
            for s in assumed
        ],
        "answerable": bool(proven_users or assumed),
        "note": ("the journey is evidence-backed: a connection without "
                 "evidence is a blind spot, an owner nobody recorded stays "
                 "unknown, and a system reached through an unevidenced hop is "
                 "assumed affected — never proven"),
    }
