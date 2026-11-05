"""The estate, measured against what the bank says should be there.

Spec 94 §4 draws a coverage matrix with a denominator: *Servers 118/120, HSMs 7/8*. Every
coverage number this platform could produce before this module answered a **different**
question — how many targets a collector attempted against how many it planned to attempt.
That is a fact about a collector run, not about the estate, and the two are routinely
confused: "NETWORK 12/12 COMPLETE" says nothing about whether the bank's 120 servers were
found, and "HSM 8/8" says nothing about whether those eight are the eight the bank owns.

The denominator cannot be computed. It can only be **declared** — by the bank. So this
module takes a declaration and reports the disagreement between it and the evidence, and
it is careful about which disagreements mean what:

* **population** — a declared count per asset class. Collected more than declared is not
  112% coverage: it is a disagreement, and either the declaration is stale or identity
  resolution over-merged two assets into one. Collected zero against a declared eight is
  eight assets nobody has described, not a clean start.
* **claims** — a named truth ("this host exists", "this API runs on this host", "this
  certificate uses RSA-2048", "this team owns the payment API"), checked against the
  estate. A claim the estate contradicts is a different finding from a claim the estate
  does not hold at all, and neither is the same as a claim this build cannot check.

What this module deliberately does **not** report is precision. Precision would need to
know whether the estate's *undeclared* findings are wrong, and the bank's silence about an
asset is not a statement that the asset does not exist — an estate finding something the
declaration never mentioned is usually the platform doing its job. Only recall over the
declared sample is computable, and that is what it computes, labelled as such.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from shared_models.estate_graph import SCHEMA as ESTATE_SCHEMA_VERSION
from shared_models.estate_graph import EstateGraph

#: ``cryptoscan.estate-ground-truth/1`` — the declaration, and the measurement of it.
GROUND_TRUTH_SCHEMA = "cryptoscan.estate-ground-truth/1"
GROUND_TRUTH_MEASUREMENT_SCHEMA = "cryptoscan.estate-ground-truth-measurement/1"

#: The claim types §11 asks to be measured separately. One metric per type, because an
#: average across them hides the only thing worth knowing: *which* kind of claim is wrong.
CLAIM_TYPES: tuple[str, ...] = (
    "ASSET_PRESENCE",
    "RELATIONSHIP",
    "ALGORITHM_USE",
    "KEY_SIZE",
    "CERTIFICATE",
    "OWNERSHIP",
)

VERDICTS: tuple[str, ...] = ("MATCHED", "CONTRADICTED", "MISSING_FROM_ESTATE", "NOT_CHECKABLE")

#: Population statuses. ``NOT_DECLARED`` is a first-class answer: a class with no
#: denominator has no percentage, and printing 0% or 100% there would invent one.
POPULATION_STATUSES: tuple[str, ...] = (
    "COMPLETE",
    "PARTIAL",
    "EMPTY",
    "OVER_DECLARED",
    "NOT_DECLARED",
)

MAX_CLAIMS = 5000


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _resolve(graph: EstateGraph, ref: Any) -> str | None:
    """Resolve an asset id, an exact name, or a unique name fragment.

    Deliberately the same resolution rule the twin uses: a declaration that names
    "Payment API" and an estate whose asset is named "payment-api" are talking about the
    same thing, and refusing it on case would report a spelling as a coverage gap.
    """
    text = _text(ref)
    if not text:
        return None
    if graph.asset(text) is not None:
        return text
    lowered = text.lower()
    exact = [a["asset_id"] for a in graph.assets() if _text(a.get("name")).lower() == lowered]
    if len(exact) == 1:
        return exact[0]
    candidates = [a["asset_id"] for a in graph.assets() if lowered in _text(a.get("name")).lower()]
    return candidates[0] if len(candidates) == 1 else None


def _evidence_for(graph: EstateGraph, asset_id: str) -> list[dict[str, Any]]:
    return [record for record in graph.evidence() if str(record.get("target")) == asset_id]


def _algorithms(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Every algorithm an evidence set names, with its key size and whether it was used.

    ``capability`` and ``use`` are kept apart: a library that *supports* RSA-2048 is not
    an application that used RSA-2048, and a claim about use must not be satisfied by a
    capability list (§8's state table, §16's OpenSSL example).
    """
    found: list[dict[str, Any]] = []
    for record in records:
        facts = record.get("facts") or {}
        algorithm = facts.get("algorithm")
        if algorithm:
            found.append(
                {
                    "algorithm": _text(algorithm).upper(),
                    "key_size": _int(facts.get("key_size")),
                    "evidence_type": record.get("evidence_type"),
                    "evidence_id": record.get("evidence_id"),
                    "capability": False,
                }
            )
        for supported in facts.get("supported_algorithms") or []:
            found.append(
                {
                    "algorithm": _text(supported).upper(),
                    "key_size": None,
                    "evidence_type": record.get("evidence_type"),
                    "evidence_id": record.get("evidence_id"),
                    "capability": True,
                }
            )
    return found


def _check_claim(graph: EstateGraph, claim: Mapping[str, Any]) -> dict[str, Any]:
    claim_type = _text(claim.get("type")).upper()
    base = {
        "claim_id": _text(claim.get("claim_id")) or None,
        "type": claim_type,
        "declared": {k: v for k, v in claim.items() if k not in {"claim_id", "type", "note"}},
        "note": _text(claim.get("note")) or None,
    }

    def result(verdict: str, reason: str, evidence: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        return {**base, "verdict": verdict, "reason": reason, "evidence": (evidence or [])[:10]}

    asset_id = _resolve(graph, claim.get("asset"))

    if claim_type == "ASSET_PRESENCE":
        if asset_id is None:
            return result(
                "MISSING_FROM_ESTATE",
                "the estate holds no asset by this id, name or unique name fragment — either a "
                "collection gap or a declaration that has moved on; this measurement cannot tell "
                "which, and does not guess",
            )
        asset = graph.asset(asset_id) or {}
        records = _evidence_for(graph, asset_id)
        return result(
            "MATCHED",
            f"present as {asset.get('type')} '{asset.get('name')}' with {len(records)} evidence record(s)",
            records,
        )

    if claim_type == "RELATIONSHIP":
        subject = _resolve(graph, claim.get("subject"))
        obj = _resolve(graph, claim.get("object"))
        predicate = _text(claim.get("predicate")).lower()
        if subject is None or obj is None:
            return result(
                "MISSING_FROM_ESTATE",
                f"one end of the claim is not in the estate (subject={claim.get('subject')!r}, "
                f"object={claim.get('object')!r}), so the relationship cannot be confirmed or denied",
            )
        edges = [
            edge
            for edge in graph.relationships()
            if edge.get("subject") == subject and edge.get("object") == obj
            and _text(edge.get("predicate")).lower() == predicate
        ]
        if edges:
            return result("MATCHED", f"{predicate} is established from evidence", edges)
        # the two ends exist but the edge does not: this is the interesting case, because
        # a twin that cannot draw an edge has a reason, and the reason is the finding
        # a refusal only contradicts *this* claim when it refused *this* predicate: the
        # graph refusing `uses` between two assets says nothing about `uses_hsm` between them
        refused = [
            entry
            for entry in graph.unresolved_relationships()
            if str(entry.get("subject")) == subject and str(entry.get("object")) == obj
            and _text(entry.get("predicate")).lower() == predicate
        ]
        if refused:
            return result(
                "CONTRADICTED",
                "both ends are present and this edge was refused — the refusal reason is the "
                "finding, not an absence of data",
                refused,
            )
        other = [
            entry
            for entry in graph.unresolved_relationships()
            if {str(entry.get("subject")), str(entry.get("object"))} == {subject, obj}
        ]
        return result(
            "MISSING_FROM_ESTATE",
            "both ends are present but no evidence establishes this relationship; that is a "
            "missing observation, never a statement that the two are unrelated"
            + (
                f" ({len(other)} other relationship between these two assets was refused for its "
                "own reason and is not a finding about this one)"
                if other else ""
            ),
        )

    if claim_type in {"ALGORITHM_USE", "KEY_SIZE"}:
        if asset_id is None:
            return result("MISSING_FROM_ESTATE", "the claimed asset is not in the estate")
        wanted = _text(claim.get("algorithm")).upper()
        if not wanted:
            return result("NOT_CHECKABLE", "the claim names no algorithm to check")
        found = _algorithms(_evidence_for(graph, asset_id))
        used = [item for item in found if item["algorithm"] == wanted and not item["capability"]]
        capable = [item for item in found if item["algorithm"] == wanted and item["capability"]]

        if claim_type == "KEY_SIZE":
            wanted_size = _int(claim.get("key_size"))
            if wanted_size is None:
                return result("NOT_CHECKABLE", "the claim names no key size to check")
            sized = [item for item in used if item["key_size"] is not None]
            if not sized:
                if used:
                    return result(
                        "NOT_CHECKABLE",
                        f"{wanted} is present on this asset but no evidence states a key size — "
                        "'no key size recorded' is not 'the declared key size is right'",
                        used,
                    )
                return result(
                    "MISSING_FROM_ESTATE",
                    f"no evidence establishes {wanted} on this asset at any key size",
                )
            if any(item["key_size"] == wanted_size for item in sized):
                return result(
                    "MATCHED", f"{wanted}-{wanted_size} is established by evidence",
                    [item for item in sized if item["key_size"] == wanted_size],
                )
            return result(
                "CONTRADICTED",
                f"evidence establishes {wanted} but at "
                f"{sorted({item['key_size'] for item in sized})}, not {wanted_size}",
                sized,
            )

        if used:
            return result("MATCHED", f"{wanted} is established as use, not capability", used)
        if capable:
            return result(
                "CONTRADICTED",
                f"{wanted} appears only as a capability the asset supports — §8's state table "
                "does not let a capability list satisfy a claim about use",
                capable,
            )
        return result("MISSING_FROM_ESTATE", f"no evidence names {wanted} on this asset")

    if claim_type == "CERTIFICATE":
        if asset_id is None:
            return result("MISSING_FROM_ESTATE", "the claimed certificate asset is not in the estate")
        records = _evidence_for(graph, asset_id)
        wanted_subject = _text(claim.get("subject_contains")).lower()
        wanted_algorithm = _text(claim.get("public_key_algorithm")).upper()
        wanted_size = _int(claim.get("public_key_size"))
        facts = [record.get("facts") or {} for record in records]
        if wanted_subject:
            subjects = [_text(item.get("subject")).lower() for item in facts]
            if not any(subjects):
                return result("NOT_CHECKABLE", "no certificate evidence states a subject", records)
            if not any(wanted_subject in subject for subject in subjects):
                return result(
                    "CONTRADICTED",
                    f"certificate evidence names {sorted(set(s for s in subjects if s))}, which "
                    f"does not contain {wanted_subject!r}",
                    records,
                )
        if wanted_algorithm or wanted_size is not None:
            pairs = [
                (_text(item.get("public_key_algorithm")).upper(), _int(item.get("public_key_size")))
                for item in facts
                if item.get("public_key_algorithm")
            ]
            if not pairs:
                return result("NOT_CHECKABLE", "no certificate evidence states a public key", records)
            if not any(
                (not wanted_algorithm or algorithm == wanted_algorithm)
                and (wanted_size is None or size == wanted_size)
                for algorithm, size in pairs
            ):
                return result(
                    "CONTRADICTED",
                    f"certificate evidence establishes {pairs}, not "
                    f"{wanted_algorithm or 'any algorithm'}"
                    f"{'' if wanted_size is None else '-' + str(wanted_size)}",
                    records,
                )
        return result("MATCHED", "the certificate evidence agrees with the claim", records)

    if claim_type == "OWNERSHIP":
        if asset_id is None:
            return result("MISSING_FROM_ESTATE", "the claimed asset is not in the estate")
        asset = graph.asset(asset_id) or {}
        owner = _text(asset.get("owner"))
        wanted_owner = _text(claim.get("owner"))
        if not wanted_owner:
            return result("NOT_CHECKABLE", "the claim names no owner to check")
        if not owner:
            return result(
                "NOT_CHECKABLE",
                "the asset is in the estate but no source states an owner — an unowned asset is "
                "a finding about ownership collection, not a failed claim",
            )
        if owner.lower() == wanted_owner.lower():
            return result("MATCHED", f"owner is '{owner}'", [{"owner": owner}])
        return result("CONTRADICTED", f"the estate states owner '{owner}', not '{wanted_owner}'")

    return result(
        "NOT_CHECKABLE",
        f"claim type {claim_type!r} is not one this build measures; expected one of "
        f"{', '.join(CLAIM_TYPES)} — a type it cannot check is reported, not skipped",
    )


def _population(graph: EstateGraph, declared: Mapping[str, Any]) -> list[dict[str, Any]]:
    evidence_counts: dict[str, int] = {}
    for record in graph.evidence():
        target = str(record.get("target"))
        evidence_counts[target] = evidence_counts.get(target, 0) + 1
    rows: list[dict[str, Any]] = []
    for asset_type, raw in declared.items():
        kind = _text(asset_type).upper()
        expected = _int(raw)
        present = graph.by_type(kind)
        collected = len(present)
        evidenced = sum(1 for asset in present if evidence_counts.get(asset["asset_id"]))
        if expected is None or expected < 0:
            status, note = "NOT_DECLARED", "the declared count is not a number, so there is no denominator"
        elif expected == 0 and collected == 0:
            status, note = "COMPLETE", "the bank declared this class empty and the estate holds none"
        elif expected == 0:
            status, note = "OVER_DECLARED", (
                f"the bank declared this class empty but the estate holds {collected}; either the "
                "declaration is stale or these are misidentified as " + kind
            )
        elif collected > expected:
            status, note = "OVER_DECLARED", (
                f"{collected} found against {expected} declared — not {round(100.0 * collected / expected, 1)}% "
                "coverage: either the declaration is stale, or identity resolution has split one "
                "asset into several"
            )
        elif collected == expected:
            status, note = "COMPLETE", "collected matches the declared population"
        elif collected == 0:
            status, note = "EMPTY", (
                f"none of the {expected} declared {kind} assets is in the estate — a collection gap, "
                "not an empty estate"
            )
        else:
            status, note = "PARTIAL", f"{expected} declared, {collected} collected"
        rows.append(
            {
                "asset_type": kind,
                "declared": expected,
                "collected": collected,
                "evidenced": evidenced,
                "unevidenced": max(0, collected - evidenced),
                "status": status,
                "note": note,
                # a percentage is only printed where there is a denominator to divide by
                # a percentage only where the denominator still means something: an
                # OVER_DECLARED class has exceeded its own denominator, and 100% beside
                # "you found more than you declared" would restate a disagreement as a pass
                "collected_percent": (
                    round(100.0 * collected / expected, 1)
                    if expected not in (None, 0) and status != "OVER_DECLARED" else None
                ),
            }
        )
    # an asset class the estate holds but the bank never declared has no denominator at all
    declared_types = {row["asset_type"] for row in rows}
    for asset_type in sorted({asset["type"] for asset in graph.assets()} - declared_types):
        present = graph.by_type(asset_type)
        evidenced = sum(1 for asset in present if evidence_counts.get(asset["asset_id"]))
        rows.append(
            {
                "asset_type": asset_type,
                "declared": None,
                "collected": len(present),
                "evidenced": evidenced,
                "unevidenced": max(0, len(present) - evidenced),
                "status": "NOT_DECLARED",
                "note": "the estate holds this class and the bank declared no count for it, so there "
                        "is no denominator and no percentage is printed",
                "collected_percent": None,
            }
        )
    return rows


def measure(graph: EstateGraph, declaration: Mapping[str, Any]) -> dict[str, Any]:
    """Check a bank's declaration against the evidence the estate holds.

    A declaration is required, because the whole point is that the denominator cannot be
    inferred from what was collected. An empty declaration is refused rather than answered
    with a clean-looking result.
    """
    declared_by = _text(declaration.get("declared_by"))
    population = declaration.get("asset_population") or {}
    claims = declaration.get("claims") or []
    if not isinstance(claims, list):
        return {
            "schema": GROUND_TRUTH_MEASUREMENT_SCHEMA,
            "status": "INVALID_DECLARATION",
            "detail": "claims must be a list",
            "live_state_modified": False,
        }
    if len(claims) > MAX_CLAIMS:
        return {
            "schema": GROUND_TRUTH_MEASUREMENT_SCHEMA,
            "status": "INVALID_DECLARATION",
            "detail": f"{len(claims)} claims exceeds the {MAX_CLAIMS} this measurement accepts",
            "live_state_modified": False,
        }
    if not declared_by:
        return {
            "schema": GROUND_TRUTH_MEASUREMENT_SCHEMA,
            "status": "INVALID_DECLARATION",
            "detail": (
                "a declaration must name who declared it (declared_by): a measurement against "
                "ground truth is only worth what its source is worth, and an unattributed "
                "denominator is an invented one"
            ),
            "live_state_modified": False,
        }

    rows = _population(graph, population if isinstance(population, Mapping) else {})
    results = [_check_claim(graph, claim) for claim in claims if isinstance(claim, Mapping)]

    by_type: dict[str, dict[str, Any]] = {}
    for claim_type in CLAIM_TYPES:
        typed = [item for item in results if item["type"] == claim_type]
        counts = {verdict: sum(1 for item in typed if item["verdict"] == verdict) for verdict in VERDICTS}
        checkable = counts["MATCHED"] + counts["CONTRADICTED"] + counts["MISSING_FROM_ESTATE"]
        by_type[claim_type] = {
            "declared": len(typed),
            **counts,
            # recall over *this declaration only*: of the claims this build could check,
            # how many the estate agreed with. It is not precision and must not be called so
            "agreement_rate": round(counts["MATCHED"] / checkable, 4) if checkable else None,
            "basis": "DECLARED_SAMPLE_ONLY",
        }
    untyped = [item for item in results if item["type"] not in CLAIM_TYPES]

    recognised_types = {asset_type for asset_type in population}
    with_denominator = [row for row in rows if row["declared"] not in (None, 0)]
    return {
        "schema": GROUND_TRUTH_MEASUREMENT_SCHEMA,
        "status": "MEASURED",
        "estate": graph.estate,
        "projection_id": graph.fingerprint(),
        "graph_schema": ESTATE_SCHEMA_VERSION,
        "declared_by": declared_by,
        "declared_at": _text(declaration.get("declared_at")) or None,
        "basis": _text(declaration.get("basis")) or "BANK_INVENTORY_DECLARATION",
        "population": {
            "rows": rows,
            "declared_classes": len(recognised_types),
            "classes_with_a_denominator": len(with_denominator),
            "classes_not_declared": len([row for row in rows if row["status"] == "NOT_DECLARED"]),
            "disagreements": [row for row in rows if row["status"] in {"OVER_DECLARED", "EMPTY"}],
            "meaning": (
                "declared counts are a bank's own denominator. Collected > declared is a "
                "disagreement to resolve, never a coverage of more than 100%; a class with no "
                "declared count prints no percentage at all"
            ),
        },
        "claims": {
            "results": results,
            "by_type": by_type,
            "unmeasurable_types": [item for item in untyped if item["verdict"] == "NOT_CHECKABLE"],
            "meaning": (
                "agreement rate is recall over the declared sample only. Precision is not reported: "
                "it would need to know whether the estate's *undeclared* findings are wrong, and a "
                "bank not having declared an asset is not evidence that the asset does not exist"
            ),
        },
        "counts": {
            **{verdict: sum(1 for item in results if item["verdict"] == verdict) for verdict in VERDICTS},
            "claims_declared": len(results),
            "claims_malformed": sum(1 for claim in claims if not isinstance(claim, Mapping)),
        },
        "live_state_modified": False,
        "limits": [
            "this measures the declaration, not the world: a bank that declares eight HSMs and "
            "owns nine will be told its estate found nine, and nothing here can tell which is right",
            "a claim the estate does not hold is reported as missing from the estate — that is "
            "either a collection gap or a stale declaration, and this measurement cannot choose",
            "populations are counted as collected assets of that type, so an asset this estate "
            "misidentifies is a wrong answer in both columns at once",
            "no score is computed across claim types: one number would hide which kind of claim "
            "the platform gets wrong",
        ],
    }


__all__ = [
    "CLAIM_TYPES",
    "GROUND_TRUTH_MEASUREMENT_SCHEMA",
    "GROUND_TRUTH_SCHEMA",
    "POPULATION_STATUSES",
    "VERDICTS",
    "measure",
]
