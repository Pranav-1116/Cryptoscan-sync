"""Impact as of a stored evidence state, and the drift since (spec 94, history link).

The twin's live ``impact`` answers *what would this selector reach now*. The
question a migration plan actually asks is different: **what did it reach when
the plan was signed off, and what has moved since**. That cannot be answered
from the live graph — the past is not in it — so this reads a stored snapshot,
rebuilds its graph from the stored payload (never from the live run), and
compares the two blast radii.

Three refusals are enforced here rather than trusted to the view:

* Two radii are only comparable when **both** matched. ``NO_MATCH`` on either
  side is ``NOT_COMPARABLE`` with the reason attached: "nothing matched at
  version 3" may mean the estate was never collected then, and reporting that
  as "nothing was affected" would turn missing evidence into a clean bill of
  health.
* Identical projection ids mean the evidence did not change. That is
  ``IDENTICAL``, not a zero delta that reads like a measurement of stability.
* A radius travels established edges only, so the comparison reports the blind
  spots on both sides. A *shrinking* radius can be an artefact of evidence that
  was lost rather than a migration that did work: ``left`` and
  ``evidence_lost`` are different findings, and the payload distinguishes them.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from shared_models import estate_twin

DRIFT_SCHEMA = "cryptoscan.estate-twin-impact-drift/1"
SIMULATION_DRIFT_SCHEMA = "cryptoscan.estate-twin-simulation-drift/1"

IDENTICAL = "IDENTICAL"
DIVERGED = "DIVERGED"
NOT_COMPARABLE = "NOT_COMPARABLE"

STATUS_MEANING = {
    IDENTICAL: "both states are the same evidence state; there is nothing to compare",
    DIVERGED: "the reachable set differs between the stored state and now",
    NOT_COMPARABLE: "at least one side did not match the selector, so a delta would be fiction",
}

#: How many asset cards each side of the delta may list. Counts are never truncated.
MAX_LISTED = estate_twin.MAX_LISTED


def _reach(impact: Mapping[str, Any]) -> set[str]:
    return {str(asset_id) for asset_id in impact.get("reachable_ids") or []}


def _hops(impact: Mapping[str, Any]) -> dict[str, int]:
    hops: dict[str, int] = {}
    for card in list(impact.get("direct") or []) + list(impact.get("transitive") or []):
        asset_id = card.get("asset_id")
        if asset_id is not None:
            hops[str(asset_id)] = int(card.get("hops") or 0)
    for card in impact.get("seed_assets") or []:
        asset_id = card.get("asset_id")
        if asset_id is not None:
            hops.setdefault(str(asset_id), 0)
    return hops


def _card(graph: Any, asset_id: str, *, hops: int | None = None) -> dict[str, Any]:
    asset = graph.asset(asset_id) or {}
    card = {
        "asset_id": asset_id,
        "name": asset.get("name"),
        "type": asset.get("type"),
        "hops": hops,
        "has_evidence": bool(asset.get("evidence_refs")),
    }
    return card


def _side(impact: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    """The comparable half of one impact call — counts and status, not the cards."""
    return {
        "label": label,
        "status": impact.get("status"),
        "projection_id": impact.get("projection_id"),
        "counts": impact.get("counts") or {},
        "by_type": impact.get("by_type") or {},
        "unknown": {
            "assets_without_evidence_count": (impact.get("unknown") or {}).get(
                "assets_without_evidence_count", 0
            ),
            "unresolved_relationships": (impact.get("unknown") or {}).get(
                "unresolved_relationships", 0
            ),
        },
        "blockers": len(impact.get("blockers") or []),
    }


def _not_comparable(
    *,
    selector: Mapping[str, Any],
    depth: int,
    now: Mapping[str, Any],
    before: Mapping[str, Any],
    as_of: Mapping[str, Any] | None,
) -> dict[str, Any]:
    sides = {"current": now, "historical": before}
    unusable = {name: side.get("status") for name, side in sides.items() if side.get("status") != "MATCHED"}
    reasons = {
        name: side.get("detail")
        or f"status {side.get('status')!r}: {len(side.get('reachable_ids') or [])} assets reached"
        for name, side in sides.items()
        if name in unusable
    }
    return {
        "schema": DRIFT_SCHEMA,
        "status": NOT_COMPARABLE,
        "status_meaning": STATUS_MEANING[NOT_COMPARABLE],
        "selector": dict(selector),
        "depth": depth,
        "as_of": dict(as_of or {}),
        "unusable_sides": unusable,
        "reasons": reasons,
        "sides": {name: _side(side, label=name) for name, side in sides.items()},
        "detail": (
            "a blast-radius delta needs two matched radii. One side did not match, and calling that "
            "'no impact' would report uncollected evidence as a clean estate"
        ),
    }


def compare_impact(
    current_graph: Any,
    historical_graph: Any,
    selector: Mapping[str, Any],
    *,
    depth: int = 3,
    as_of: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Blast radius now versus the same selector at a stored evidence state."""
    selector = dict(selector or {})
    now = estate_twin.impact(current_graph, selector, depth=depth)
    before = estate_twin.impact(historical_graph, selector, depth=depth)
    if now.get("status") != "MATCHED" or before.get("status") != "MATCHED":
        return _not_comparable(selector=selector, depth=depth, now=now, before=before, as_of=as_of)

    now_ids, before_ids = _reach(now), _reach(before)
    entered, left = now_ids - before_ids, before_ids - now_ids
    persisting = now_ids & before_ids
    now_hops, before_hops = _hops(now), _hops(before)

    # Asset ids are type-qualified, so a reclassified asset (SERVICE → SYSTEM)
    # arrives as one id leaving and another entering. Reported as a delta it
    # reads like an estate gained and lost a host at the same moment; reported
    # as a reclassification it reads as what it is. Pair on the name, and only
    # when exactly one side leaves and one side enters under that name.
    left_by_name: dict[str, str] = {}
    for asset_id in left:
        name = str((historical_graph.asset(asset_id) or {}).get("name") or "")
        if name:
            left_by_name.setdefault(name, asset_id)
    entered_by_name: dict[str, str] = {}
    for asset_id in entered:
        name = str((current_graph.asset(asset_id) or {}).get("name") or "")
        if name:
            entered_by_name.setdefault(name, asset_id)
    reclassified: list[dict[str, Any]] = []
    for name in sorted(set(left_by_name) & set(entered_by_name)):
        gone, arrived = left_by_name[name], entered_by_name[name]
        type_before = (historical_graph.asset(gone) or {}).get("type")
        type_now = (current_graph.asset(arrived) or {}).get("type")
        if type_before == type_now:
            continue
        reclassified.append(
            {
                "name": name,
                "type_before": type_before,
                "type_now": type_now,
                "asset_id_before": gone,
                "asset_id_now": arrived,
                "hops_before": before_hops.get(gone),
                "hops_now": now_hops.get(arrived),
            }
        )
        left.discard(gone)
        entered.discard(arrived)

    identical = now.get("projection_id") == before.get("projection_id")
    status = IDENTICAL if identical else DIVERGED

    # Three different facts hide behind "no longer reached", and a bare id diff
    # reports all of them as one number: the asset was deleted from the estate,
    # the asset is still there but lost the evidence that placed it in the
    # radius, or the selector genuinely stopped reaching it. Only the last one
    # is the migration working.
    gone_from_estate = sorted(asset_id for asset_id in left if current_graph.asset(asset_id) is None)
    evidence_lost = sorted(
        asset_id
        for asset_id in left
        if (asset := current_graph.asset(asset_id)) is not None and not asset.get("evidence_refs")
    )

    payload = {
        "schema": DRIFT_SCHEMA,
        "status": status,
        "status_meaning": STATUS_MEANING[status],
        "selector": selector,
        "depth": depth,
        "as_of": dict(as_of or {}),
        "identical_evidence": identical,
        "sides": {
            "current": _side(now, label="current"),
            "historical": _side(before, label="historical"),
        },
        "drift": {
            "counts": {
                "current_total": len(now_ids),
                "historical_total": len(before_ids),
                "entered": len(entered),
                "left": len(left),
                "persisting": len(persisting),
                "reclassified": len(reclassified),
            },
            "entered": [
                _card(current_graph, asset_id, hops=now_hops.get(asset_id))
                for asset_id in sorted(entered)[:MAX_LISTED]
            ],
            "left": [
                _card(historical_graph, asset_id, hops=before_hops.get(asset_id))
                for asset_id in sorted(left)[:MAX_LISTED]
            ],
            "reclassified": reclassified[:MAX_LISTED],
            "truncated": (len(entered) > MAX_LISTED or len(left) > MAX_LISTED),
            "evidence_lost": evidence_lost[:MAX_LISTED],
            "evidence_lost_count": len(evidence_lost),
            "gone_from_estate": gone_from_estate[:MAX_LISTED],
            "gone_from_estate_count": len(gone_from_estate),
        },
        "note": (
            "a radius travels established edges only. 'left' means the asset is no longer reached at "
            "this selector and depth; it is not by itself proof that the migration worked — split it "
            "by 'gone_from_estate' (deleted), 'evidence_lost' (still present, no evidence) and the "
            "remainder, and compare both sides' unknown counts before drawing that conclusion"
        ),
    }
    if identical:
        payload["reason"] = (
            "the stored state and the current state share one projection id, so the evidence is "
            "unchanged and there is no drift to measure"
        )
    if (as_of or {}).get("policy_version") in (None, ""):
        payload["caveat"] = (
            "this snapshot predates policy_version, so which rules read its evidence is not recorded"
        )
    return payload


def _affected(result: Mapping[str, Any]) -> set[str]:
    return {
        str(card.get("asset_id"))
        for card in result.get("affected_assets") or []
        if card.get("asset_id") is not None
    }


def compare_simulation(
    current_graph: Any,
    historical_graph: Any,
    scenario: Mapping[str, Any],
    *,
    as_of: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one scenario against the stored state and against now, then diff.

    A plan reviewed six weeks ago was reviewed against six-week-old evidence.
    Re-running it against the same *scenario* answers whether it still matches
    anything, whether it still reaches the same assets, and whether the BOM
    change it promised still happens.
    """
    scenario = dict(scenario or {})
    now = estate_twin.simulate(current_graph, scenario)
    before = estate_twin.simulate(historical_graph, scenario)
    sides = {"current": now, "historical": before}
    if any(side.get("status") != "SIMULATED" for side in sides.values()):
        unusable = {
            name: side.get("status")
            for name, side in sides.items()
            if side.get("status") != "SIMULATED"
        }
        return {
            "schema": SIMULATION_DRIFT_SCHEMA,
            "status": NOT_COMPARABLE,
            "status_meaning": STATUS_MEANING[NOT_COMPARABLE],
            "scenario": scenario,
            "as_of": dict(as_of or {}),
            "unusable_sides": unusable,
            "reasons": {
                name: side.get("detail") or f"status {side.get('status')!r}"
                for name, side in sides.items()
                if name in unusable
            },
            "sides": {
                name: {
                    "status": side.get("status"),
                    "matched_evidence": side.get("matched_evidence", 0),
                    "base_projection_id": side.get("base_projection_id"),
                }
                for name, side in sides.items()
            },
            "detail": (
                "the scenario must match evidence on both states to be comparable; a scenario that "
                "matched nothing at the stored state was never a plan for that state"
            ),
        }

    now_ids, before_ids = _affected(now), _affected(before)
    identical = now.get("base_projection_id") == before.get("base_projection_id")
    payload = {
        "schema": SIMULATION_DRIFT_SCHEMA,
        "status": IDENTICAL if identical else DIVERGED,
        "status_meaning": STATUS_MEANING[IDENTICAL if identical else DIVERGED],
        "scenario": scenario,
        "as_of": dict(as_of or {}),
        "identical_evidence": identical,
        "sides": {
            name: {
                "status": side.get("status"),
                "base_projection_id": side.get("base_projection_id"),
                "simulated_projection_id": side.get("simulated_projection_id"),
                "matched_evidence": side.get("matched_evidence"),
                "affected_count": len(_affected(side)),
                "bom_changes": side.get("bom_changes"),
                "live_projection_unchanged": side.get("live_projection_unchanged"),
            }
            for name, side in sides.items()
        },
        "drift": {
            "counts": {
                "current_affected": len(now_ids),
                "historical_affected": len(before_ids),
                "entered": len(now_ids - before_ids),
                "left": len(before_ids - now_ids),
                "persisting": len(now_ids & before_ids),
            },
            "entered": [
                _card(current_graph, asset_id)
                for asset_id in sorted(now_ids - before_ids)[:MAX_LISTED]
            ],
            "left": [
                _card(historical_graph, asset_id)
                for asset_id in sorted(before_ids - now_ids)[:MAX_LISTED]
            ],
        },
        "note": (
            "each side was run against its own copy of its own evidence; neither run modified live "
            "state, and both sides report that check independently"
        ),
    }
    if identical:
        payload["reason"] = (
            "both runs started from the same projection id, so this is a re-run of the same plan "
            "against the same evidence"
        )
    return payload


def target_assets(snapshot_row: Any) -> Iterable[str]:
    """Asset ids the stored snapshot holds — used to sanity-check a resolved version."""
    graph = estate_twin.graph_from_snapshot({"payload": snapshot_row.payload or {}})
    return sorted(asset["asset_id"] for asset in graph.assets())


__all__ = [
    "DIVERGED",
    "DRIFT_SCHEMA",
    "IDENTICAL",
    "NOT_COMPARABLE",
    "SIMULATION_DRIFT_SCHEMA",
    "compare_impact",
    "compare_simulation",
    "target_assets",
]
