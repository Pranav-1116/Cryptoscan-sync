"""Estate Coverage Intelligence (roadmap item 6).

A coverage report exists to stop the most dangerous lie in security tooling: a
missing asset silently becoming a clean result. This module assembles the
dimensions item 6 names — authorized targets vs discovered, collectors needing
attention, partial observations, unknown assets, stale evidence, unsupported
device types, access-denied targets, unverified relationships and collection
freshness — and refuses to print completeness the data cannot support:

* a failed read never prints a zero: its plane is ``NOT_OBSERVED``, and the
  impact text carries why;
* a percentage over an unknown denominator is refused, not estimated;
* any gap forces the verdict away from ``CLEAN`` — missing is never clean.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

COVERAGE_SCHEMA = "cryptoscan.estate-coverage-intelligence/1"

VERDICT_COMPLETE = "COVERAGE_COMPLETE"
VERDICT_ATTENTION = "COVERAGE_ATTENTION"
VERDICT_INCOMPLETE = "COVERAGE_INCOMPLETE"


def _gap(kind: str, count: int, detail: str) -> dict[str, Any]:
    return {"kind": kind, "count": int(count), "detail": detail,
            "is_clean_result": False}


def coverage_intelligence(
    *,
    authorized_targets: int,
    discovered_assets: int,
    collector_outcomes: Iterable[Mapping[str, Any]],
    unknown_assets: int = 0,
    stale_evidence: int = 0,
    unverified_relationships: int = 0,
    access_denied_targets: int = 0,
    unsupported_types: Iterable[str] = (),
    freshness: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One coverage-intelligence record over one collection run.

    ``collector_outcomes`` are :func:`shared_models.estate_graph.collector_outcome`
    rows (or equivalent dicts): each names its plane, status, expected and
    collected counts, and its impact text. The verdict ladder:

    * ``COVERAGE_INCOMPLETE`` — any collection gap: a failed or not-attempted
      plane, a partial row, an access-denied target, or an unknown asset;
    * ``COVERAGE_ATTENTION`` — collection is complete but stale evidence,
      unverified relationships or unsupported types still need eyes;
    * ``COVERAGE_COMPLETE`` — none of the above. This verdict is deliberately
      hard to reach: a missing asset must never silently become a clean result.
    """
    authorized = max(0, int(authorized_targets))
    discovered = max(0, int(discovered_assets))
    unknown = max(0, int(unknown_assets))
    stale = max(0, int(stale_evidence))
    unverified = max(0, int(unverified_relationships))
    denied = max(0, int(access_denied_targets))
    unsupported = sorted({str(item) for item in unsupported_types if str(item).strip()})

    rows: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    attention: list[dict[str, Any]] = []
    expected_total = 0
    collected_total = 0
    unknown_denominator = False

    for raw in collector_outcomes:
        plane = str(raw.get("plane") or "UNKNOWN")
        status = str(raw.get("status") or "UNKNOWN").upper()
        if status == "NO_TARGET":
            status = "FAILED"
        expected = max(0, int(raw.get("expected") or 0))
        collected = max(0, int(raw.get("collected") or 0))
        is_failure = status in {"FAILED", "NOT_ATTEMPTED"} or bool(raw.get("is_failure"))
        if status not in {"COMPLETE", "PARTIAL", "FAILED", "NOT_ATTEMPTED", "UNKNOWN"}:
            status = "UNKNOWN"
            is_failure = True
        expected_total += expected
        collected_total += collected
        if expected == 0 and status != "COMPLETE":
            unknown_denominator = True
        rows.append({
            "plane": plane, "status": status, "expected": expected,
            "collected": collected,
            "reason": raw.get("reason"),
            "impact": raw.get("impact") or (
                "this plane's inventory is UNKNOWN — a failed read is a coverage "
                "fact, not an empty estate"),
            "is_failure": is_failure,
        })
        if is_failure:
            gaps.append(_gap(
                "COLLECTOR_FAILED", 1,
                f"plane {plane} is NOT_OBSERVED ({status}): its inventory is "
                f"unknown, never empty and never clean"))
        elif status == "PARTIAL" or (expected and collected < expected):
            gaps.append(_gap(
                "PARTIAL_OBSERVATION", max(0, expected - collected) or 1,
                f"plane {plane} collected {collected} of {expected}: the "
                f"remainder is NOT_OBSERVED, not absent"))

    if unknown:
        gaps.append(_gap(
            "UNKNOWN_ASSET", unknown,
            "assets whose presence or absence is unknown: a missing asset must "
            "never silently become a clean security result"))
    if discovered < authorized:
        gaps.append(_gap(
            "UNDISCOVERED_TARGET", authorized - discovered,
            "authorized targets that produced no discovery record: they are "
            "NOT_OBSERVED, not free of findings"))
    if denied:
        gaps.append(_gap(
            "ACCESS_DENIED", denied,
            "targets that refused or lacked access: a denied read is never an "
            "empty-risk result"))

    if stale:
        attention.append(_gap(
            "STALE_EVIDENCE", stale,
            "evidence past its freshness policy: still part of the history, "
            "no longer a current statement"))
    if unverified:
        attention.append(_gap(
            "UNVERIFIED_RELATIONSHIP", unverified,
            "relationships without proven evidence behind them"))
    if unsupported:
        attention.append(_gap(
            "UNSUPPORTED_TYPE", len(unsupported),
            f"device or asset types with no working collector: "
            f"{', '.join(unsupported)}"))

    if gaps:
        verdict = VERDICT_INCOMPLETE
        reason = ("collection has gaps: every gap above is NOT_OBSERVED or a "
                  "failure, and none of them is a clean security result")
    elif attention:
        verdict = VERDICT_ATTENTION
        reason = ("collection is complete but parts of the evidence need "
                  "attention before anyone calls this estate covered")
    else:
        verdict = VERDICT_COMPLETE
        reason = ("every authorized target was discovered, every collector "
                  "completed, and no gap or attention item stands")

    if expected_total > 0 and not unknown_denominator:
        coverage_percent: float | None = round(100.0 * collected_total / expected_total, 2)
        percent_note = None
    else:
        coverage_percent = None
        percent_note = ("the denominator includes planes that were never read or "
                        "targets with no expected count: a percentage over unknown "
                        "targets is refused, not estimated")

    return {
        "schema": COVERAGE_SCHEMA,
        "verdict": verdict,
        "reason": reason,
        "authorized_targets": authorized,
        "discovered_assets": discovered,
        "collectors": rows,
        "collectors_needing_attention": [
            row for row in rows
            if row["is_failure"] or row["status"] == "PARTIAL"
            or (row["expected"] and row["collected"] < row["expected"])],
        "unknown_assets": unknown,
        "stale_evidence": stale,
        "unsupported_types": unsupported,
        "access_denied_targets": denied,
        "unverified_relationships": unverified,
        "freshness": dict(freshness) if freshness else None,
        "gaps": gaps,
        "attention_items": attention,
        "coverage_percent": coverage_percent,
        "percent_note": percent_note,
        "note": ("a failed read never prints a zero, a percentage over an unknown "
                 "denominator is refused, and a missing asset is never a clean "
                 "result"),
    }
