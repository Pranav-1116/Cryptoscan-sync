"""Drift between two estate snapshots (spec 93 §18: "drift baseline").

Drift is only meaningful between *comparable* snapshots, so this module compares
two stored discovery runs by the things that are content-addressed:

* the six BOM projections, component by component (``bom_ref`` identity, content
  digest for a change), so a renamed artefact is an add+remove and a changed
  cipher is a change;
* the coverage matrix per plane, because "the estate changed" and "we looked at
  less of the estate" are different facts and must never be read as one;
* the collector outcomes, so a plane that stopped running shows up as coverage
  debt rather than as the estate losing all of its hardware.

Refusals that keep the report honest:

* one run is ``NO_BASELINE``, not "no drift";
* a plane that was not collected in either run cannot be reported as unchanged —
  it is ``NOT_COMPARABLE`` with a reason;
* nothing is summarised as "the estate is safe" — a drift report says what moved.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

MODEL = "cryptoscan.estate-drift/1"
MAX_LISTED = 40


def _canonical(component: Mapping[str, Any]) -> str:
    """Content digest of one component, ignoring render/observation timestamps.

    Timestamps say *when* a projection was rendered; hashing them would report
    drift on every re-read of the same snapshot.
    """
    import hashlib
    import json

    from api.security.estate_bom_anchor import stable_view

    body = json.dumps(stable_view(component), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _ref(component: Mapping[str, Any]) -> str:
    for key in ("bom-ref", "bom_ref", "ref"):
        value = component.get(key)
        if value:
            return str(value)
    name = str(component.get("name") or component.get("asset_id") or "component")
    return f"{component.get('type') or 'UNKNOWN'}:{name}"


def _components(bom: Mapping[str, Any]) -> dict[str, str]:
    return {_ref(component): _canonical(component) for component in (bom.get("components") or [])
            if isinstance(component, Mapping)}


def snapshot_from_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a discovery report (``/estate/evidence/scan`` or ``discover``) to a snapshot."""
    boms = report.get("boms") or {}
    coverage = (report.get("coverage") or {}).get("targets") or []
    collectors = {str(item.get("plane") or "UNKNOWN"): str(item.get("status") or "UNKNOWN")
                  for item in report.get("collectors") or []}
    return {
        "projection_id": report.get("projection_id"),
        "run_id": report.get("run_id"),
        "estate": report.get("estate"),
        "scope": report.get("scope"),
        "summary": report.get("summary") or {},
        "boms": {str(kind).upper(): _components(bom) for kind, bom in boms.items()},
        "coverage": {
            str(row.get("target") or "UNKNOWN"): {
                "expected": int(row.get("expected") or 0),
                "collected": int(row.get("collected") or 0),
                "status": str(row.get("status") or "UNKNOWN"),
            }
            for row in coverage
        },
        "collectors": collectors,
    }


def _diff_set(previous: Mapping[str, str], current: Mapping[str, str]) -> dict[str, Any]:
    added = sorted(set(current) - set(previous))
    removed = sorted(set(previous) - set(current))
    changed = sorted(ref for ref in set(previous) & set(current) if previous[ref] != current[ref])
    return {
        "added": added[:MAX_LISTED],
        "removed": removed[:MAX_LISTED],
        "changed": changed[:MAX_LISTED],
        "counts": {"added": len(added), "removed": len(removed), "changed": len(changed)},
        "truncated": any(len(items) > MAX_LISTED for items in (added, removed, changed)),
    }


def compare(previous: Mapping[str, Any] | None, current: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two snapshots produced by :func:`snapshot_from_report`."""
    if previous is None:
        return {
            "model": MODEL,
            "verdict": "NO_BASELINE",
            "current_projection_id": current.get("projection_id"),
            "reason": "this is the first stored discovery — it becomes the baseline; drift needs two snapshots",
            "note": "NO_BASELINE is not 'no drift': nothing has been compared yet",
        }

    kinds = sorted(set(previous.get("boms") or {}) | set(current.get("boms") or {}))
    boms: dict[str, Any] = {}
    for kind in kinds:
        before = (previous.get("boms") or {}).get(kind)
        after = (current.get("boms") or {}).get(kind)
        if before is None or after is None:
            boms[kind] = {
                "status": "NOT_COMPARABLE",
                "reason": f"{kind} is present in only one of the two snapshots, so its content cannot be diffed",
                "counts": {"added": len(after or {}), "removed": len(before or {}), "changed": 0},
                "added": sorted(set(after or {}))[:MAX_LISTED],
                "removed": sorted(set(before or {}))[:MAX_LISTED],
                "changed": [],
                "truncated": False,
            }
            continue
        diff = _diff_set(before, after)
        degraded = not (before or after)
        boms[kind] = {
            "status": "NOT_COMPARABLE" if degraded else (
                "CHANGED" if any(diff["counts"].values()) else "UNCHANGED"),
            "reason": (
                "both snapshots have an empty projection — that is not evidence of no change in the estate"
                if degraded else None
            ),
            **diff,
        }

    coverage_rows: dict[str, Any] = {}
    for plane in sorted(set(previous.get("coverage") or {}) | set(current.get("coverage") or {})):
        before = (previous.get("coverage") or {}).get(plane)
        after = (current.get("coverage") or {}).get(plane)
        if before is None or after is None:
            coverage_rows[plane] = {
                "status": "NOT_COMPARABLE",
                "reason": "this plane was not reported by both snapshots",
            }
            continue
        delta_expected = after["expected"] - before["expected"]
        delta_collected = after["collected"] - before["collected"]
        moved = delta_expected or delta_collected or before["status"] != after["status"]
        coverage_rows[plane] = {
            "status": "CHANGED" if moved else "UNCHANGED",
            "before": before,
            "after": after,
            "delta_expected": delta_expected,
            "delta_collected": delta_collected,
            "note": (
                "coverage debt grew: fewer targets were read, so part of this plane is NOT_OBSERVED now"
                if delta_collected < 0 else None
            ),
        }

    collector_rows: dict[str, Any] = {}
    for plane in sorted(set(previous.get("collectors") or {}) | set(current.get("collectors") or {})):
        before = (previous.get("collectors") or {}).get(plane)
        after = (current.get("collectors") or {}).get(plane)
        if before != after:
            collector_rows[plane] = {"before": before, "after": after}

    degraded_planes = sorted(
        plane for plane, row in collector_rows.items()
        if row.get("after") in {"FAILED", "NOT_ATTEMPTED"}
    )
    asset_delta = {
        "assets_before": int((previous.get("summary") or {}).get("assets") or 0),
        "assets_after": int((current.get("summary") or {}).get("assets") or 0),
        "relationships_before": int((previous.get("summary") or {}).get("relationships") or 0),
        "relationships_after": int((current.get("summary") or {}).get("relationships") or 0),
    }
    changed_boms = sorted(kind for kind, row in boms.items() if row["status"] == "CHANGED")
    changed_coverage = sorted(plane for plane, row in coverage_rows.items() if row["status"] == "CHANGED")
    drift = bool(changed_boms or changed_coverage or collector_rows
                 or asset_delta["assets_before"] != asset_delta["assets_after"]
                 or asset_delta["relationships_before"] != asset_delta["relationships_after"])

    return {
        "model": MODEL,
        "verdict": "DRIFT" if drift else "NO_DRIFT",
        "baseline_projection_id": previous.get("projection_id"),
        "current_projection_id": current.get("projection_id"),
        "same_snapshot": previous.get("projection_id") == current.get("projection_id"),
        "boms": boms,
        "coverage": coverage_rows,
        "collectors": collector_rows,
        "asset_delta": asset_delta,
        "changed_boms": changed_boms,
        "changed_coverage": changed_coverage,
        "degraded_planes": degraded_planes,
        "summary": (
            f"{len(changed_boms)} BOM(s) and {len(changed_coverage)} coverage row(s) changed; "
            f"{len(degraded_planes)} plane(s) stopped collecting"
        ),
        "meaning": (
            "drift reports what moved between two snapshots. A changed coverage row is not an estate change, "
            "and a plane that stopped running is UNKNOWN, not absent"
        ),
        "limitations": [
            "only stored discovery snapshots are compared; nothing is re-collected",
            "a BOM that is empty in both snapshots is NOT_COMPARABLE, not unchanged",
            "NO_DRIFT means the two snapshots match — it is never a statement that the estate is safe",
        ],
    }


def compare_latest(runs: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Compare the two newest stored discovery snapshots (newest first)."""
    ordered = [run for run in runs if isinstance(run, Mapping)]
    if not ordered:
        return {
            "model": MODEL,
            "verdict": "NO_BASELINE",
            "reason": "no estate discovery has been stored yet",
            "note": "run /estate/evidence/scan to create the baseline",
        }
    current = snapshot_from_report(ordered[0])
    previous = snapshot_from_report(ordered[1]) if len(ordered) > 1 else None
    report = compare(previous, current)
    report["runs_compared"] = [previous.get("run_id") if previous else None, current.get("run_id")]
    return report
