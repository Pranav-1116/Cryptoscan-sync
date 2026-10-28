"""Continuous change detection for the estate loop (spec 93 §13/§18).

Drift as an endpoint you call is a report. Drift as a *consequence of every run*
is monitoring — and that is what a 24/7 product has to do: the moment a plane
stops answering, a certificate disappears or a new unknown asset appears, someone
should learn about it without opening a console.

So every run compares itself with the run before it and answers three questions
in one object:

* **did the estate change?** components added/removed/changed per BOM;
* **did coverage change?** a plane that collected less, or stopped collecting at
  all — which is not an estate change, and must never be reported as one;
* **what should someone do?** every severity carries a next action, because
  "WARNING: drift detected" without a next step is noise that gets muted.

Severity, in the only order that matters:

* ``CRITICAL`` — coverage was lost (a plane that used to answer now does not).
  Nothing downstream can be trusted: an unobserved plane is UNKNOWN, and the
  BOMs that depended on it now under-report.
* ``WARNING`` — the estate changed (components appeared or disappeared), or
  unknown/open-work grew. Real, but the scan still covered what it claims.
* ``INFO`` — a change with no coverage or inventory consequence (e.g. only the
  projection id moved).
* ``NONE`` — the two snapshots match. That is not a statement of safety.
* ``NO_BASELINE`` — first run; nothing to compare, and it is *not* "no change".
"""

from __future__ import annotations

from typing import Any, Mapping

from api import estate_drift

MODEL = "cryptoscan.estate-change/1"

SEVERITY_ORDER = {"NONE": 0, "INFO": 1, "WARNING": 2, "CRITICAL": 3}

NEXT_ACTIONS = {
    "COVERAGE_LOST": (
        "a plane that answered before did not answer now: check its credentials, network path and the daemon "
        "log; until it is restored, the BOMs that depend on it are incomplete and its estate is UNKNOWN"
    ),
    "COVERAGE_REDUCED": (
        "a plane returned fewer targets than the previous run: confirm the target set did not shrink silently "
        "(a smaller read is not a smaller estate)"
    ),
    "ESTATE_CHANGED": (
        "components appeared or disappeared since the previous run: review the affected BOM, and confirm the "
        "removal was a decommission rather than a failed read"
    ),
    "OPEN_WORK_GREW": (
        "the unknown/open-work queue grew: assign the new items, or record why they cannot be resolved"
    ),
    "NONE": None,
    "NO_BASELINE": "run again on the same schedule; the second run becomes the comparison baseline",
}


def _coverage(snapshot: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return dict((snapshot or {}).get("coverage") or {})


def _bom_counts(snapshot: Mapping[str, Any]) -> dict[str, int]:
    return {
        str(kind).upper(): len(components or {})
        for kind, components in ((snapshot or {}).get("boms") or {}).items()
    }


def classify(previous: Mapping[str, Any] | None, current: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two ``estate_drift.snapshot_from_report`` snapshots into a verdict."""
    drift = estate_drift.compare(previous, current)
    if drift.get("verdict") == "NO_BASELINE":
        return {
            "model": MODEL,
            "severity": "NO_BASELINE",
            "changed": None,
            "headline": "first stored snapshot: it becomes the baseline",
            "findings": [],
            "next_action": NEXT_ACTIONS["NO_BASELINE"],
            "drift": drift,
            "meaning": "NO_BASELINE is not 'no change': nothing has been compared yet",
        }

    findings: list[dict[str, Any]] = []
    severity = "NONE"

    def raise_to(level: str) -> None:
        nonlocal severity
        if SEVERITY_ORDER[level] > SEVERITY_ORDER[severity]:
            severity = level

    # 1. coverage lost or reduced — never reported as an estate change
    for plane, row in (drift.get("coverage") or {}).items():
        before = row.get("before") or {}
        after = row.get("after") or {}
        if not before or not after:  # NOT_COMPARABLE: the plane is missing from one side
            continue
        status_before, status_after = before.get("status"), after.get("status")
        collected_before = int(before.get("collected") or 0)
        collected_after = int(after.get("collected") or 0)
        if status_after in {"FAILED", "NOT_ATTEMPTED", "NOT_OBSERVED"} and status_before not in {
            "FAILED", "NOT_ATTEMPTED", "NOT_OBSERVED"
        }:
            findings.append({
                "kind": "COVERAGE_LOST",
                "plane": plane,
                "before": before,
                "after": after,
                "detail": f"{plane} went {status_before} → {status_after}",
            })
            raise_to("CRITICAL")
        elif collected_after < collected_before:
            findings.append({
                "kind": "COVERAGE_REDUCED",
                "plane": plane,
                "before": before,
                "after": after,
                "detail": f"{plane} collected {collected_after} of {after.get('expected')} "
                          f"(was {collected_before})",
            })
            raise_to("CRITICAL")

    # 2. the estate itself moved
    for kind, bom in (drift.get("boms") or {}).items():
        counts = bom.get("counts") or {}
        if bom.get("status") == "NOT_COMPARABLE":
            if not any(int(counts.get(key) or 0) for key in ("added", "removed", "changed")):
                # empty in both snapshots: drift already refuses to call that
                # "unchanged", and it is certainly not a change worth alarming on
                continue
            findings.append({
                "kind": "ESTATE_CHANGED",
                "bom": kind,
                "detail": f"{kind} exists in only one of the two snapshots",
                "counts": counts,
            })
            raise_to("WARNING")
            continue
        if any(int(counts.get(key) or 0) for key in ("added", "removed", "changed")):
            findings.append({
                "kind": "ESTATE_CHANGED",
                "bom": kind,
                "counts": counts,
                "added": (bom.get("added") or [])[:10],
                "removed": (bom.get("removed") or [])[:10],
                "changed": (bom.get("changed") or [])[:10],
            })
            raise_to("WARNING")

    # 3. open work (unknown inventory) grew
    before_summary = dict((previous or {}).get("summary") or {})
    after_summary = dict(current.get("summary") or {})
    before_assets = int(before_summary.get("assets") or 0)
    after_assets = int(after_summary.get("assets") or 0)
    if after_assets > before_assets and not findings:
        findings.append({
            "kind": "OPEN_WORK_GREW",
            "detail": f"{after_assets - before_assets} asset(s) appeared without a corresponding BOM change",
        })
        raise_to("INFO")

    if drift.get("verdict") == "DRIFT" and severity == "NONE":
        # something moved that the three specific rules above do not name — say
        # so at INFO rather than pretending nothing happened
        findings.append({
            "kind": "ESTATE_CHANGED",
            "detail": drift.get("summary"),
            "changed_boms": drift.get("changed_boms") or [],
        })
        raise_to("INFO")

    primary = next((item["kind"] for item in findings if item["kind"] in NEXT_ACTIONS), "NONE")
    headline = (
        "no change between the two snapshots"
        if severity == "NONE"
        else "; ".join(sorted({item["kind"] for item in findings}))
    )
    return {
        "model": MODEL,
        "severity": severity,
        "changed": severity != "NONE",
        "headline": headline,
        "findings": findings,
        "next_action": NEXT_ACTIONS.get(primary),
        "bom_counts_before": _bom_counts(previous or {}),
        "bom_counts_after": _bom_counts(current),
        "coverage_before": {key: value.get("status") for key, value in _coverage(previous or {}).items()},
        "coverage_after": {key: value.get("status") for key, value in _coverage(current).items()},
        "baseline_projection_id": (previous or {}).get("projection_id"),
        "current_projection_id": current.get("projection_id"),
        "drift": drift,
        "meaning": (
            "every run is compared to the run before it; a lost plane is CRITICAL because it is UNKNOWN, not "
            "absent, and NONE is not a safety statement"
        ),
    }


def compare_reports(previous: Mapping[str, Any] | None,
                    current: Mapping[str, Any]) -> dict[str, Any]:
    """Convenience wrapper: two discovery reports, not two snapshots."""
    return classify(
        estate_drift.snapshot_from_report(previous) if previous else None,
        estate_drift.snapshot_from_report(current),
    )
