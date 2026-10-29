"""The Digital Twin's chain, link by link.

    Estate → Assets → Relationships → Crypto graph → Evidence graph →
    History → Impact analysis → Simulation

That order is not decoration: each link consumes what the previous ones produced.
Relationships cannot exist without assets; the crypto graph is drawn over the
relationships; impact is a traversal of the crypto graph; a simulation is an
impact calculation run against a hypothetical edit.

This module answers exactly one question per link — *what does the twin hold on
this link, for this estate, right now?* — so a screen can show **where the chain
stops** for a real estate instead of drawing eight boxes and letting the reader
assume the seven they cannot see are full.

Three rules are enforced here rather than trusted to the view:

* A store that could not be read is ``NOT_EVALUATED`` with its reason. It is
  never reported as ``EMPTY`` — "we did not look" and "we looked and there is
  nothing" are different facts, and only one of them is evidence.
* Impact analysis and simulation are ``AWAITING_INPUT`` when they are computable
  but nothing has been asked yet. They are never ``EMPTY``: an estate with assets
  always has a computable impact for *some* selector.
* The chain link counts are counts of records the twin holds, not a coverage or
  maturity score. ``claim`` says so, and nothing here is aggregated into a
  percentage.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

CHAIN_SCHEMA = "cryptoscan.estate-twin-chain/1"

POPULATED = "POPULATED"
EMPTY = "EMPTY"
NOT_EVALUATED = "NOT_EVALUATED"
AWAITING_INPUT = "AWAITING_INPUT"

STATUS_MEANING = {
    POPULATED: "the twin holds records on this link, measured now",
    EMPTY: "the twin was read for this link and holds nothing — a real, measured emptiness",
    NOT_EVALUATED: "the underlying store was not read in this call; nothing is claimed about it",
    AWAITING_INPUT: "computable on request, but nothing has been asked yet",
}

#: (id, label, the question the link answers, the endpoint that serves its full view)
STAGES: tuple[tuple[str, str, str, str], ...] = (
    (
        "ESTATE",
        "Estate",
        "which snapshot is the twin a projection of?",
        "/api/v1/estate/evidence/twin",
    ),
    (
        "ASSETS",
        "Assets",
        "what does the twin hold as an asset?",
        "/api/v1/estate/evidence/catalog/assets",
    ),
    (
        "RELATIONSHIPS",
        "Relationships",
        "how are those assets connected, and on what evidence?",
        "/api/v1/estate/evidence/catalog/relationships",
    ),
    (
        "CRYPTO_GRAPH",
        "Crypto graph",
        "which algorithms sit on which asset, on which plane?",
        "/api/v1/estate/evidence/twin/crypto-graph",
    ),
    (
        "EVIDENCE_GRAPH",
        "Evidence graph",
        "how many assets are actually backed by an evidence record?",
        "/api/v1/estate/evidence/evidence/records",
    ),
    (
        "HISTORY",
        "History",
        "does the twin remember earlier values, and does it dispute any?",
        "/api/v1/estate/evidence/history/summary",
    ),
    (
        "IMPACT",
        "Impact analysis",
        "what would a selector's failure reach?",
        "/api/v1/estate/evidence/twin/impact",
    ),
    (
        "SIMULATION",
        "Simulation",
        "what would a planned change do, and what was already considered?",
        "/api/v1/estate/evidence/twin/simulations",
    ),
)

STAGE_INDEX = {stage[0]: stage for stage in STAGES}


def _stage(
    identifier: str,
    status: str,
    *,
    detail: Mapping[str, Any] | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    if identifier not in STAGE_INDEX:
        raise ValueError(f"unknown chain stage {identifier!r}")
    if status not in STATUS_MEANING:
        raise ValueError(f"unknown chain status {status!r}")
    _, label, question, endpoint = STAGE_INDEX[identifier]
    return {
        "index": [stage[0] for stage in STAGES].index(identifier),
        "stage": identifier,
        "label": label,
        "question": question,
        "status": status,
        "status_meaning": STATUS_MEANING[status],
        "detail": dict(detail or {}),
        "reason": reason,
        "endpoint": endpoint,
    }


def _count(values: Iterable[Any]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for value in values:
        key = str(value or "UNKNOWN")
        totals[key] = totals.get(key, 0) + 1
    return dict(sorted(totals.items()))


def chain(
    graph: Any,
    *,
    history: Mapping[str, Any] | None = None,
    history_error: str | None = None,
    simulations: Iterable[Mapping[str, Any]] | None = None,
    simulations_error: str | None = None,
    simulation_limit: int = 100,
) -> dict[str, Any]:
    """Walk the chain over one graph, reporting what each link actually holds.

    ``history``/``simulations`` are passed in because they live in the database,
    not in the graph. Passing ``None`` means **not read** and produces
    ``NOT_EVALUATED``; it never means zero.
    """
    from shared_models import estate_twin as _twin

    assets = graph.assets()
    evidence = graph.evidence()
    relationships = graph.relationships()
    unresolved = graph.unresolved_relationships()

    described = {str(record.get("target")) for record in evidence}
    asset_ids = {str(asset.get("asset_id")) for asset in assets}
    backed = described & asset_ids

    stages: list[dict[str, Any]] = []

    stages.append(
        _stage(
            "ESTATE",
            POPULATED if graph.estate else NOT_EVALUATED,
            detail={
                "estate": graph.estate,
                "projection_id": graph.fingerprint(),
                "levels": list(getattr(_twin, "ESTATE_LEVELS", ()) or ()),
            },
            reason=None if graph.estate else "the graph carries no estate identifier",
        )
    )

    stages.append(
        _stage(
            "ASSETS",
            POPULATED if assets else EMPTY,
            detail={
                "assets": len(assets),
                "by_type": _count(asset.get("type") for asset in assets),
            },
            reason=None if assets else "no asset has been collected into this snapshot",
        )
    )

    with_evidence = [edge for edge in relationships if edge.get("evidence_ids")]
    stages.append(
        _stage(
            "RELATIONSHIPS",
            POPULATED if relationships else EMPTY,
            detail={
                "relationships": len(relationships),
                "with_evidence": len(with_evidence),
                "unresolved": len(unresolved),
                "by_predicate": _count(
                    edge.get("predicate") or edge.get("type") for edge in relationships
                ),
            },
            reason=(
                None
                if relationships
                else (
                    "no relationship has been established between this snapshot's assets; the twin "
                    "holds the assets but cannot yet say how they reach each other"
                )
            ),
        )
    )

    counts: dict[str, Any] = {}
    crypto_error: str | None = None
    try:
        counts = dict(_twin.crypto_graph(graph).get("counts") or {})
    except Exception as exc:  # pragma: no cover - defensive: the graph is ours
        crypto_error = f"crypto graph could not be built: {exc}"
    crypto_total = sum(int(value or 0) for value in counts.values())
    stages.append(
        _stage(
            "CRYPTO_GRAPH",
            NOT_EVALUATED if crypto_error else (POPULATED if crypto_total else EMPTY),
            detail=counts,
            reason=crypto_error or (
                None if crypto_total else "no algorithm is attached to any asset on any plane"
            ),
        )
    )

    stages.append(
        _stage(
            "EVIDENCE_GRAPH",
            POPULATED if evidence else EMPTY,
            detail={
                "evidence_records": len(evidence),
                "by_type": _count(record.get("evidence_type") for record in evidence),
                "assets_backed": len(backed),
                "assets_unbacked": len(asset_ids - backed),
            },
            reason=(
                None
                if evidence
                else (
                    "the snapshot holds no evidence record; every asset in it is an assertion "
                    "without a source"
                )
            ),
        )
    )

    if history is None:
        stages.append(
            _stage(
                "HISTORY",
                NOT_EVALUATED,
                reason=history_error or "the observation store was not read in this call",
            )
        )
    else:
        observations = dict(history.get("observations") or {})
        held = int(observations.get("total") or 0)
        stages.append(
            _stage(
                "HISTORY",
                POPULATED if held else EMPTY,
                detail={
                    "observations": held,
                    "current": int(observations.get("current") or 0),
                    "historical": int(observations.get("historical") or 0),
                    "assets": int(observations.get("assets") or 0),
                    "disputed_facts": int(observations.get("disputed_facts") or 0),
                },
                reason=(
                    None
                    if held
                    else (
                        "no fact has ever been recorded for these assets, so the twin has no "
                        "earlier value to compare against — history starts at the next run"
                    )
                ),
            )
        )

    reachable = bool(assets)
    stages.append(
        _stage(
            "IMPACT",
            AWAITING_INPUT if reachable else EMPTY,
            detail={"reachable_assets": len(assets), "relationships": len(relationships)},
            reason=(
                "impact is computed for a selector you supply; no selector has been asked for yet"
                if reachable
                else "there is no asset to compute an impact over"
            ),
        )
    )

    if simulations is None:
        stages.append(
            _stage(
                "SIMULATION",
                NOT_EVALUATED,
                reason=simulations_error or "stored simulations were not read in this call",
            )
        )
    else:
        stored = list(simulations)
        stages.append(
            _stage(
                "SIMULATION",
                AWAITING_INPUT if reachable else EMPTY,
                detail={
                    "stored": len(stored),
                    "limit": simulation_limit,
                    "at_limit": len(stored) >= simulation_limit,
                    "computable": reachable,
                },
                reason=(
                    "a simulation is computed on request against a copy; these are the stored ones, "
                    "and none of them is estate state"
                    if reachable
                    else "there is no asset to simulate an edit against"
                ),
            )
        )

    blocked = next((item for item in stages if item["status"] not in {POPULATED, AWAITING_INPUT}), None)
    return {
        "schema": CHAIN_SCHEMA,
        "estate": graph.estate,
        "projection_id": graph.fingerprint(),
        "stages": stages,
        "order": [item["stage"] for item in stages],
        "status_meaning": STATUS_MEANING,
        "first_incomplete_stage": (blocked or {}).get("stage"),
        "claim": (
            "this describes how far the twin's own chain is populated for this estate. It is not a "
            "crypto posture score, a coverage percentage or a statement that the estate is fully "
            "described: a POPULATED link only says the twin holds records on it"
        ),
        "note": (
            "links are ordered by dependency — impact traverses the crypto graph, a simulation is an "
            "impact calculation over a hypothetical edit. A link that is NOT_EVALUATED was not read "
            "here; it is not empty"
        ),
    }


__all__ = [
    "AWAITING_INPUT",
    "CHAIN_SCHEMA",
    "EMPTY",
    "NOT_EVALUATED",
    "POPULATED",
    "STAGES",
    "STAGE_INDEX",
    "STATUS_MEANING",
    "chain",
]
