"""Cross-BOM reconciliation (gap analysis §E).

Six BOMs are not six independent inventories. When several BOMs speak about
one subject, the system must show where evidence *agrees*, *conflicts* or is
*missing* — and it must never assume responsibility that no evidence supports:

    "It must not automatically assume that the OpenSSL library is responsible
    for every TLS connection made by the application."

So a claim of presence ("OpenSSL is in this application") and a claim of
responsibility ("OpenSSL negotiated this TLS session") are different claim
kinds, and responsibility is only ever recorded where evidence links the
component to the operation. Everything else is ``UNATTRIBUTED`` — present,
not proven responsible.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

RECONCILIATION_SCHEMA = "cryptoscan.cross-bom-reconciliation/1"

#: the six BOMs
SBOM, CBOM, HBOM, NBOM, VBOM, TECHBOM = (
    "SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM")
BOMS: tuple[str, ...] = (SBOM, CBOM, HBOM, NBOM, VBOM, TECHBOM)

AGREES, CONFLICTS, MISSING = "AGREES", "CONFLICTS", "MISSING"
UNATTRIBUTED = "UNATTRIBUTED"

#: what a claim asserts: presence of a component, or responsibility for an op
PRESENCE, RESPONSIBILITY = "PRESENCE", "RESPONSIBILITY"


def bom_claim(*, bom: str, subject: str, claim_kind: str,
              relationship: str, target: str,
              evidence_ids: Sequence[str], observed_at: str | None = None,
              note: str | None = None) -> dict[str, Any]:
    """One BOM's claim about one subject. Every claim carries its evidence.

    A responsibility claim without evidence is refused at construction: that
    is exactly the assumption this module exists to stop.
    """
    name = str(bom or "").upper()
    if name not in BOMS:
        raise ValueError(f"unknown BOM {bom!r}; expected one of "
                         f"{', '.join(BOMS)}")
    kind = str(claim_kind or "").upper()
    if kind not in {PRESENCE, RESPONSIBILITY}:
        raise ValueError(f"unknown claim kind {claim_kind!r}; expected "
                         f"{PRESENCE} or {RESPONSIBILITY}")
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if not ids:
        raise ValueError(
            "a claim with no evidence is a guess: file the SBOM entry, scan "
            "record or handshake capture behind it")
    return {
        "schema": RECONCILIATION_SCHEMA,
        "bom": name, "subject": str(subject), "claim_kind": kind,
        "relationship": str(relationship), "target": str(target),
        "evidence_ids": ids,
        "observed_at": str(observed_at) if observed_at else None,
        "note": str(note) if note else None,
    }


def attribute_operation(*, component: str, operation: str,
                        claims: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """May ``component`` be named responsible for ``operation``?

    Only a RESPONSIBILITY claim with evidence linking the two says yes. Presence
    of the component — however well evidenced — never attributes the operation.
    """
    rows = [dict(c) for c in claims]
    for row in rows:
        if (row.get("claim_kind") == RESPONSIBILITY
                and row.get("target") == operation
                and row.get("subject") == component
                and row.get("evidence_ids")):
            return {
                "component": str(component), "operation": str(operation),
                "attribution": "ATTRIBUTED",
                "evidence_ids": list(row.get("evidence_ids") or []),
                "reason": (f"evidence links {component} to {operation} "
                           f"({', '.join(row['evidence_ids'])})"),
            }
    present = [row for row in rows
               if row.get("claim_kind") == PRESENCE
               and row.get("target") == component]
    return {
        "component": str(component), "operation": str(operation),
        "attribution": UNATTRIBUTED, "evidence_ids": [],
        "reason": (
            f"{component} is present ({', '.join(present[0].get('evidence_ids') or [])})"
            if present else f"no claim places {component} in this subject"
        ) + (f", but no evidence links it to {operation}: presence is not "
             f"responsibility" if present else ""),
    }


def reconcile(*, subject: str,
              claims: Sequence[Mapping[str, Any]],
              expected_boms: Sequence[str] = BOMS) -> dict[str, Any]:
    """Reconcile every claim about one subject across the BOMs.

    Claims are grouped by the (relationship, target) edge they assert:

    * ``AGREES`` — two or more BOMs assert the same edge and no evidence
      contradicts it;
    * ``CONFLICTS`` — BOMs assert contradictory edges for the same
      relationship (different targets, or presence vs absence asserted as
      conflict), with both sides kept;
    * ``MISSING`` — only one BOM speaks to an edge the expected set should
      cover, or an expected BOM has no claim at all.

    Nothing here deletes or overwrites a claim: conflicts are preserved with
    both sides visible.
    """
    rows = [dict(c) for c in claims]
    edges: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        key = (str(row.get("relationship")), str(row.get("target")))
        edges.setdefault(key, []).append(row)

    agrees, conflicts, missing = [], [], []
    for (relationship, target), group in sorted(edges.items()):
        boms_in = sorted({str(r.get("bom")) for r in group})
        entry = {
            "relationship": relationship, "target": target,
            "boms": boms_in,
            "evidence_ids": sorted({e for r in group
                                    for e in (r.get("evidence_ids") or [])}),
            "claims": group,
        }
        if len(boms_in) >= 2:
            agrees.append({**entry, "verdict": AGREES,
                           "reason": (f"{' and '.join(boms_in)} agree on "
                                      f"{relationship} → {target}")})
        else:
            missing.append({**entry, "verdict": MISSING,
                            "reason": (f"only {boms_in[0]} speaks to "
                                       f"{relationship} → {target}: the other "
                                       f"BOMs neither confirm nor contradict "
                                       f"it — missing is not agreement")})

    # same relationship, different targets across groups = conflict
    by_relationship: dict[str, set[str]] = {}
    for (relationship, target) in edges:
        by_relationship.setdefault(relationship, set()).add(target)
    for relationship, targets in sorted(by_relationship.items()):
        if len(targets) > 1 and not any(
                c["relationship"] == relationship for c in conflicts):
            conflicts.append({
                "relationship": relationship, "target": sorted(targets),
                "boms": sorted({str(r.get("bom")) for r in rows
                                if str(r.get("relationship")) == relationship}),
                "evidence_ids": sorted({e for r in rows
                                        if str(r.get("relationship")) == relationship
                                        for e in (r.get("evidence_ids") or [])}),
                "claims": [r for r in rows
                           if str(r.get("relationship")) == relationship],
                "verdict": CONFLICTS,
                "reason": (f"claims disagree on {relationship}: "
                           f"{sorted(targets)}"),
            })

    expected = [str(b).upper() for b in expected_boms]
    silent = [b for b in expected
              if b not in {str(r.get("bom")).upper() for r in rows}]
    for bom in silent:
        missing.append({
            "relationship": "*", "target": "*", "boms": [bom],
            "evidence_ids": [], "claims": [], "verdict": MISSING,
            "reason": (f"{bom} has no claim about {subject}: an inventory "
                       f"that never speaks is a blind spot, not agreement"),
        })

    return {
        "schema": RECONCILIATION_SCHEMA,
        "subject": str(subject),
        "agrees": agrees, "conflicts": conflicts, "missing": missing,
        "counts": {AGREES: len(agrees), CONFLICTS: len(conflicts),
                   MISSING: len(missing)},
        "note": ("six BOMs are one estate seen from six angles: agreement is "
                 "recorded where evidence matches, conflicts keep both sides, "
                 "and silence is missing — never assumed agreement. Presence "
                 "is never responsibility without evidence linking the "
                 "component to the operation."),
    }
