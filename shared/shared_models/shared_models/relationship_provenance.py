"""Relationship provenance, sighting windows and impact closure (roadmap item 1).

Every graph relationship must have evidence behind it — and a reader must be able
to see *what kind* of evidence: **proven** (direct observation of the running or
configured world), **inferred** (a declaration, an import, a derivation), or
**unknown** (no resolvable evidence at all). This module classifies edges that
way, derives first-seen/last-seen strictly from evidence timestamps (a missing
timestamp stays missing — it is never back-filled with "now"), and computes the
downstream impact closure when an asset changes.

The closure is labelled a projection everywhere it appears: it says who *would*
be affected along which dependency chain and with what provenance per hop. It is
never presented as a real production change (roadmap item 8's rule, applied from
the first tool that reasons about change).
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

PROVENANCE_SCHEMA = "cryptoscan.relationship-provenance/1"

#: how a relationship is established
PROVEN = "PROVEN"
INFERRED = "INFERRED"
UNKNOWN = "UNKNOWN"
PROVENANCE_CLASSES: tuple[str, ...] = (PROVEN, INFERRED, UNKNOWN)

#: evidence classes that directly observe the world. A relationship resting on any
#: of these is proven by something that was seen, not something that was said.
DIRECT_EVIDENCE: frozenset[str] = frozenset(
    {"RUNTIME_OBSERVED", "NETWORK_ACTIVE_OBSERVED", "NETWORK_PASSIVE_OBSERVED",
     "CERTIFICATE_OBSERVED", "AUDIT_OBSERVED", "CONFIGURED"})

#: classes that describe rather than observe
SECONDARY_EVIDENCE: frozenset[str] = frozenset(
    {"VENDOR_DECLARED", "IMPORTED", "INFERRED"})


def provenance_of(edge: Mapping[str, Any],
                  evidence_by_id: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Classify one edge. Unknown stays unknown: an unresolved evidence id counts
    as nothing, not as support.

    * ``PROVEN`` — at least one backing record is direct evidence;
    * ``INFERRED`` — backing records exist but every one is a declaration, an
      import or an inference;
    * ``UNKNOWN`` — no evidence ids, or none resolve to a record.
    """
    lookup = evidence_by_id or {}
    ids = [str(item) for item in (edge.get("evidence_ids") or [])]
    records = [lookup[i] for i in ids if i in lookup]
    unresolved = [i for i in ids if i not in lookup]
    kinds = {str(r.get("evidence_type") or "UNKNOWN").upper() for r in records}
    if kinds & DIRECT_EVIDENCE:
        klass, reason = PROVEN, ("direct evidence backs this relationship: it was "
                                 "observed, negotiated or configured")
    elif kinds:
        klass, reason = INFERRED, (
            "every backing record describes rather than observes: this relationship "
            "is inferred and must not be shown as proven")
    else:
        klass, reason = UNKNOWN, (
            "no resolvable evidence backs this relationship; it is unknown, which "
            "is never counted as proven")
    return {
        "schema": PROVENANCE_SCHEMA,
        "subject": edge.get("subject"), "predicate": edge.get("predicate"),
        "object": edge.get("object"), "basis": edge.get("basis"),
        "provenance": klass,
        "evidence_ids": ids,
        "unresolved_evidence_ids": unresolved,
        "evidence_types": sorted(kinds),
        "reason": reason,
    }


def sighting_window(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """First-seen / last-seen from evidence timestamps only.

    A record with no parsable ``observed_at`` extends neither bound: the window
    widens on evidence, never on convenience. If nothing is datable, both bounds
    are ``None`` — "I do not know when this was first seen", not "it appeared now".
    """
    stamps: list[str] = []
    for record in records:
        value = record.get("observed_at")
        if isinstance(value, str) and value.strip():
            stamps.append(value.strip())
    if not stamps:
        return {"first_seen": None, "last_seen": None, "sightings": 0,
                "reason": ("no datable evidence: first-seen and last-seen are "
                           "unknown, never back-filled")}
    return {"first_seen": min(stamps), "last_seen": max(stamps),
            "sightings": len(stamps), "reason": None}


def edge_sighting(edge: Mapping[str, Any],
                  evidence_by_id: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """The sighting window of one edge, across its resolvable evidence."""
    lookup = evidence_by_id or {}
    records = [lookup[i] for i in (edge.get("evidence_ids") or []) if i in lookup]
    return sighting_window(records)


def impact_closure(edges: Sequence[Mapping[str, Any]], changed: str, *,
                   evidence_by_id: Mapping[str, Mapping[str, Any]] | None = None,
                   predicates: Iterable[str] | None = None) -> dict[str, Any]:
    """Who depends on ``changed``, along which chain, with what provenance per hop.

    Edges run subject→object ("app uses service"); impact flows the other way: when
    the object changes, every subject that uses it is affected, and so on up the
    chain. Every hop carries its own provenance class, and a chain is only as
    strong as its weakest hop — a chain with an unknown hop is labelled ``UNKNOWN``,
    not "proven".

    The output is a **projection**: it names assets that *would* be affected. It
    is never a statement that anything has changed.
    """
    wanted = {str(p).lower() for p in predicates} if predicates is not None else None
    usable = [e for e in edges
              if wanted is None or str(e.get("predicate") or "").lower() in wanted]

    affected: dict[str, dict[str, Any]] = {changed: {
        "asset": changed, "hops": 0, "chain": [],
        "chain_provenance": PROVEN, "via": "the changed asset itself"}}
    frontier = [changed]
    weakest = {PROVEN: 0, INFERRED: 1, UNKNOWN: 2}

    while frontier:
        current = frontier.pop(0)
        depth = affected[current]["hops"]
        for edge in usable:
            if str(edge.get("object") or "") != current:
                continue
            subject = str(edge.get("subject") or "")
            if not subject or subject in affected:
                continue
            provenance = provenance_of(edge, evidence_by_id)
            chain = affected[current]["chain"] + [{
                "from": subject, "predicate": edge.get("predicate"),
                "to": current, "provenance": provenance["provenance"],
                "evidence_ids": provenance["evidence_ids"],
            }]
            weakest_class = max((affected[current]["chain_provenance"],
                                 provenance["provenance"]),
                                key=lambda c: weakest.get(c, 2))
            affected[subject] = {
                "asset": subject, "hops": depth + 1, "chain": chain,
                "chain_provenance": weakest_class,
                "via": f"depends on {current}",
            }
            frontier.append(subject)

    ordered = sorted(affected.values(), key=lambda row: (row["hops"], row["asset"]))
    return {
        "schema": PROVENANCE_SCHEMA,
        "result_kind": "IMPACT_PROJECTION",
        "changed": changed,
        "affected": ordered,
        "counts": {
            "affected": len(ordered) - 1,
            "proven_chains": sum(1 for row in ordered
                                 if row["chain_provenance"] == PROVEN and row["hops"]),
            "inferred_chains": sum(1 for row in ordered
                                   if row["chain_provenance"] == INFERRED),
            "unknown_chains": sum(1 for row in ordered
                                  if row["chain_provenance"] == UNKNOWN and row["hops"]),
        },
        "note": ("this is a hypothetical projection over recorded dependencies: it "
                 "is not a production change, and a chain is only as strong as its "
                 "weakest hop"),
    }
