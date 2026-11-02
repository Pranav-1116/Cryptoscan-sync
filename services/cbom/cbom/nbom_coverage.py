"""NBOM coverage: an observed endpoint is not the network.

Review item 4 is the blunt one:

    Suppose a bank has 10,000 network endpoints, but CryptoScan successfully
    observes 6,500. The NBOM must not imply: **this is the bank's complete
    network.**

The NBOM already refuses to read a timeout as plaintext. It did not yet refuse to
read *6,500 observed* as *the estate*. That is the same mistake one level up: a
probe that never ran is as silent as a probe that never negotiated, and a document
that lists 6,500 listeners is a **floor** on the network, never a total.

This module is the coverage model, in two pieces:

* **the matrix** (item 5) — one row per target group with `expected`, `attempted`,
  `observed`, `failed`, `unauthorized`, `excluded`, and the derived `unattempted`,
  `coverage_pct` and `status`. The row is where the arithmetic is checked: an
  observation count above the target count is refused, because that means the
  target list is stale, not that the estate grew;
* **the claim** — `attach` writes the block into the NBOM's `metadata.properties` and
  `claim` says what may be quoted. `TOTAL` only when every group is `COMPLETE`;
  otherwise `FLOOR`, with the unmeasured, unauthorized and failed counts named in
  the statement.

Five statuses, because "not complete" is too coarse to act on:

============  ===========================================================
``COMPLETE``  every expected endpoint was observed
``PARTIAL``   some were, and the rest are named
``FAILED``    probes ran and none negotiated: the scan failed, the network did not
``UNAUTHORIZED``  nothing was attempted: an authorization gap, not a network fact
``UNMEASURED``  no target list, so coverage is unknown and 100% would be a lie
============  ===========================================================
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

SCHEMA = "cryptoscan.nbom-coverage/1"

#: Row and estate statuses.
STATUSES: tuple[str, ...] = ("COMPLETE", "PARTIAL", "FAILED", "UNAUTHORIZED", "UNMEASURED")

#: Why a row is not complete. A row can carry several.
REASONS: tuple[str, ...] = (
    "NO_TARGETS",        # expected == 0: nothing to be complete against
    "NOT_ATTEMPTED",     # expected but no probe was issued
    "FAILED_PROBES",     # probes ran and did not negotiate
    "UNAUTHORIZED",       # probes were not issued for authorization reasons
    "EXCLUDED",           # deliberately out of scope
    "NOT_OBSERVED",       # attempted, neither success nor recorded failure
)

#: What a stored probe row's status means to coverage. Unlisted statuses are
#: refused rather than bucketed, so a new scanner outcome cannot silently become
#: "observed".
OBSERVED_STATUSES = frozenset({"OK", "TLS_OK", "OBSERVED"})
FAILED_STATUSES = frozenset({"TIMEOUT", "REFUSED", "ERROR", "FAILED",
                             "HANDSHAKE_FAILED", "UNREACHABLE", "RESET"})
UNAUTHORIZED_STATUSES = frozenset({"UNAUTHORIZED", "NOT_AUTHORIZED", "OUT_OF_SCOPE",
                                   "SKIPPED_UNAUTHORIZED", "DENIED"})

COUNT_FIELDS: tuple[str, ...] = ("expected", "attempted", "observed", "failed",
                                 "unauthorized", "excluded")

PROPERTY_BLOCK = "cryptoscan:network_coverage"
PROPERTY_PCT = "cryptoscan:network_coverage_pct"
PROPERTY_STATUS = "cryptoscan:network_coverage_status"
PROPERTY_EXPECTED = "cryptoscan:network_expected"
PROPERTY_OBSERVED = "cryptoscan:network_observed"
PROPERTY_UNMEASURED = "cryptoscan:network_unmeasured"
PROPERTY_TOTAL = "cryptoscan:network_may_report_total"


def _count(row: Mapping[str, Any], field: str) -> int:
    value = row.get(field)
    if value in (None, ""):
        return 0
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a count, not a boolean")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a count, got {value!r}") from exc
    if number < 0:
        raise ValueError(f"{field} cannot be negative ({number})")
    return number


def _pct(observed: int, expected: int) -> float | None:
    if expected <= 0:
        return None
    return round(100.0 * observed / expected, 1)


def group(row: Mapping[str, Any]) -> dict[str, Any]:
    """One matrix row: the counts, the derived gap, the status and why.

    Refusals are arithmetic, not policy: `observed > expected` says the target list
    is stale, `attempted > expected` says the scan targeted something nobody
    inventoried, and neither may be silently clamped to a plausible percentage.
    """
    if not isinstance(row, Mapping):
        raise ValueError("a coverage row must be an object")
    target = str(row.get("target") or row.get("name") or "").strip()
    if not target:
        raise ValueError("a coverage row needs a target (which group is being measured)")
    expected = _count(row, "expected")
    attempted = _count(row, "attempted")
    observed = _count(row, "observed")
    failed = _count(row, "failed")
    unauthorized = _count(row, "unauthorized")
    excluded = _count(row, "excluded")
    if observed > expected:
        raise ValueError(
            f"{target}: {observed} observed against {expected} expected — the target "
            "list is stale, and clamping the percentage would hide that")
    if attempted > expected:
        raise ValueError(
            f"{target}: {attempted} attempted against {expected} expected — the scan "
            "targeted endpoints nobody inventoried")
    if observed > attempted:
        raise ValueError(
            f"{target}: {observed} observed against {attempted} attempted — an "
            "observation needs a probe")
    if failed + unauthorized > attempted + unauthorized:
        raise ValueError(
            f"{target}: {failed} failed and {unauthorized} unauthorized outcomes exceed "
            "the endpoints the scan touched")
    unattempted = max(0, expected - attempted - unauthorized - excluded)
    reasons: list[str] = []
    if expected == 0:
        status = "UNMEASURED"
        reasons.append("NO_TARGETS")
    elif attempted == 0 and unauthorized > 0:
        status = "UNAUTHORIZED"
        reasons.append("UNAUTHORIZED")
    elif attempted == 0:
        status = "PARTIAL"
        reasons.append("NOT_ATTEMPTED")
    elif observed == 0 and failed >= attempted:
        status = "FAILED"
        reasons.append("FAILED_PROBES")
    elif observed == expected:
        status = "COMPLETE"
    else:
        status = "PARTIAL"
    if status != "COMPLETE":
        if failed and "FAILED_PROBES" not in reasons:
            reasons.append("FAILED_PROBES")
        if unauthorized and "UNAUTHORIZED" not in reasons:
            reasons.append("UNAUTHORIZED")
        if unattempted and "NOT_ATTEMPTED" not in reasons:
            reasons.append("NOT_ATTEMPTED")
        if excluded and "EXCLUDED" not in reasons:
            reasons.append("EXCLUDED")
        if not reasons:
            reasons.append("NOT_OBSERVED")
    return {
        "target": target,
        "unit": str(row.get("unit") or "endpoint"),
        "expected": expected,
        "attempted": attempted,
        "observed": observed,
        "failed": failed,
        "unauthorized": unauthorized,
        "excluded": excluded,
        "unattempted": unattempted,
        "coverage_pct": _pct(observed, expected),
        "status": status,
        "reasons": reasons,
        "statement": _row_statement(target, expected, attempted, observed, failed,
                                    unauthorized, unattempted, status),
    }


def _row_statement(target: str, expected: int, attempted: int, observed: int,
                   failed: int, unauthorized: int, unattempted: int,
                   status: str) -> str:
    if status == "UNMEASURED":
        return (f"{target}: no target list, so coverage is unknown — 0% and 100% are "
                "both wrong")
    pct = _pct(observed, expected)
    text = f"{target}: {observed} of {expected} observed ({pct}%)"
    if status == "COMPLETE":
        return text + "; every expected endpoint was observed"
    gaps = []
    if unattempted:
        gaps.append(f"{unattempted} never attempted")
    if unauthorized:
        gaps.append(f"{unauthorized} unauthorized")
    if failed:
        gaps.append(f"{failed} failed")
    if status == "FAILED":
        return (text + "; probes ran and none negotiated — that is a scan failure, not "
                "an empty network")
    if status == "UNAUTHORIZED":
        return (text + "; nothing was attempted because the collector was not "
                "authorized for this group")
    return text + ("; " + ", ".join(gaps) if gaps else "")


def matrix(rows: Iterable[Mapping[str, Any]], *, as_of: str | None = None,
           unit: str = "endpoint") -> dict[str, Any]:
    """The estate network coverage matrix, and the one claim it supports."""
    groups = [group(row) for row in rows or ()]
    seen: set[str] = set()
    for row in groups:
        key = row["target"].lower()
        if key in seen:
            raise ValueError(f"{row['target']} appears twice in one matrix")
        seen.add(key)
    totals = {field: sum(row[field] for row in groups) for field in COUNT_FIELDS}
    totals["unattempted"] = sum(row["unattempted"] for row in groups)
    estate_status = _estate_status(groups, totals)
    unmeasured = [row["target"] for row in groups if row["status"] == "UNMEASURED"]
    incomplete = [row["target"] for row in groups if row["status"] != "COMPLETE"]
    complete = [row["target"] for row in groups if row["status"] == "COMPLETE"]
    reasons: dict[str, int] = {reason: 0 for reason in REASONS}
    for row in groups:
        for reason in row["reasons"]:
            reasons[reason] = reasons.get(reason, 0) + 1
    block = {
        "schema": SCHEMA,
        "as_of": as_of or datetime.now(timezone.utc).isoformat(),
        "unit": unit,
        "groups": groups,
        "totals": totals,
        "coverage_pct": _pct(totals["observed"], totals["expected"]),
        "status": estate_status,
        "complete_groups": complete,
        "incomplete_groups": incomplete,
        "unmeasured_groups": unmeasured,
        "reason_counts": {key: value for key, value in reasons.items() if value},
        "statement": "",
    }
    block["claim"] = claim(block)
    block["statement"] = _matrix_statement(block)
    return block


def _estate_status(groups: list[dict[str, Any]], totals: Mapping[str, int]) -> str:
    if not groups or totals["expected"] == 0:
        return "UNMEASURED"
    if all(row["status"] == "COMPLETE" for row in groups):
        return "COMPLETE"
    measured = [row for row in groups if row["status"] != "UNMEASURED"]
    if measured and all(row["status"] == "FAILED" for row in measured):
        return "FAILED"
    if measured and all(row["status"] in {"FAILED", "UNAUTHORIZED"} for row in measured):
        if any(row["status"] == "UNAUTHORIZED" for row in measured):
            return "UNAUTHORIZED"
        return "FAILED"
    return "PARTIAL"


def _matrix_statement(block: Mapping[str, Any]) -> str:
    totals = block["totals"]
    pct = block["coverage_pct"]
    groups = block["groups"]
    if block["status"] == "UNMEASURED":
        return ("no target list, so network coverage is unknown and no count describes "
                "the estate")
    head = (f"{totals['observed']} of {totals['expected']} expected "
            f"{block['unit']}(s) observed across {len(groups)} target group(s) "
            f"({pct}%)")
    parts = [f"{len(block['complete_groups'])} group(s) complete"]
    if totals["unattempted"]:
        parts.append(f"{totals['unattempted']} never attempted")
    if totals["unauthorized"]:
        parts.append(f"{totals['unauthorized']} unauthorized")
    if totals["failed"]:
        parts.append(f"{totals['failed']} failed")
    if block["unmeasured_groups"]:
        parts.append(f"{len(block['unmeasured_groups'])} group(s) with no target list")
    tail = ("; any total is a floor on the network, not the network"
            if block["status"] != "COMPLETE"
            else "; every expected endpoint was observed")
    return f"{head} — {block['status'].lower()}: " + ", ".join(parts) + tail


def claim(block: Mapping[str, Any]) -> dict[str, Any]:
    """What a reader may do with the numbers above.

    ``TOTAL`` needs every group complete *and* a non-zero target, because an estate
    with no target list is not a measured zero.
    """
    totals = block.get("totals") or {}
    complete = block.get("status") == "COMPLETE" and int(totals.get("expected") or 0) > 0
    observed = int(totals.get("observed") or 0)
    if block.get("status") == "UNMEASURED" or int(totals.get("expected") or 0) == 0:
        return {
            "may_report_total": False,
            "basis": "UNKNOWN",
            "observed": observed,
            "expected": int(totals.get("expected") or 0),
            "coverage_pct": None,
            "statement": ("no target list, so the NBOM supports no total and no floor: "
                          "coverage of the network is unknown"),
        }
    return {
        "may_report_total": complete,
        "basis": "TOTAL" if complete else "FLOOR",
        "observed": observed,
        "expected": int(totals.get("expected") or 0),
        "coverage_pct": block.get("coverage_pct"),
        "statement": (
            f"{observed} endpoint(s) observed, and every expected endpoint was observed"
            if complete else
            f"{observed} endpoint(s) observed is a floor: the matrix does not cover the "
            "whole estate, so the NBOM describes what was observed, not what exists"),
    }


def from_probes(name: str, probes: Iterable[Mapping[str, Any]], *,
                declared: Iterable[str] = (), unit: str = "endpoint") -> dict[str, Any]:
    """A matrix row from stored probe rows, with unknown statuses refused.

    ``declared`` is the target list for this group. The expected count is the union
    of what the estate declared and what a probe touched, so an endpoint in the
    target list that no probe reached is `unattempted` — exactly the gap a bare
    probe count hides — and an endpoint probed but never declared widens the target
    list rather than being dropped.
    """
    observed = failed = unauthorized = 0
    touched: set[str] = set()
    refused: list[dict[str, Any]] = []
    for index, probe in enumerate(probes or (), start=1):
        if not isinstance(probe, Mapping):
            refused.append({"row": index, "reason": "a probe must be an object"})
            continue
        endpoint = str(probe.get("endpoint") or probe.get("host") or "").strip()
        status = str(probe.get("status") or "").strip().upper()
        if not endpoint:
            refused.append({"row": index, "reason": "a probe with no endpoint cannot be "
                                                    "counted"})
            continue
        if status in OBSERVED_STATUSES:
            observed += 1
        elif status in FAILED_STATUSES:
            failed += 1
        elif status in UNAUTHORIZED_STATUSES:
            unauthorized += 1
        else:
            refused.append({"row": index, "endpoint": endpoint, "status": status,
                            "reason": (f"status {status or '(empty)'} is not a documented "
                                       "probe outcome, so it is not counted as observed "
                                       "or failed")})
            continue
        touched.add(endpoint.lower())
    targets = [str(value).strip() for value in declared or () if str(value).strip()]
    declared_set = {value.lower() for value in targets}
    never_probed = sorted({value for value in targets if value.lower() not in touched})
    expected = len(declared_set | touched)
    row = group({
        "target": name,
        "unit": unit,
        "expected": expected,
        "attempted": observed + failed,
        "observed": observed,
        "failed": failed,
        "unauthorized": unauthorized,
    })
    row["declared"] = len(targets)
    row["declared_not_probed"] = never_probed
    if never_probed:
        row["statement"] = (row["statement"] + f"; {len(never_probed)} declared "
                            "endpoint(s) were never probed")
    return {"row": row, "refused": refused,
            "statement": row["statement"]
                        + (f"; {len(refused)} probe row(s) refused" if refused else "")}


def attach(document: Mapping[str, Any], block: Mapping[str, Any]) -> dict[str, Any]:
    """Write the coverage block into an NBOM's ``metadata.properties``.

    CycloneDX has nowhere to say "this document covers 65% of the estate", so the
    claim travels as namespaced properties next to the components it qualifies.
    """
    if not isinstance(document, Mapping):
        raise ValueError("a document must be an object")
    result = dict(document)
    metadata = dict(result.get("metadata") or {})
    existing = [dict(row) for row in metadata.get("properties") or []
                if isinstance(row, Mapping)
                and str(row.get("name")) not in
                {PROPERTY_BLOCK, PROPERTY_PCT, PROPERTY_STATUS, PROPERTY_EXPECTED,
                 PROPERTY_OBSERVED, PROPERTY_UNMEASURED, PROPERTY_TOTAL}]
    block_claim = block.get("claim") or claim(block)
    compact = {key: block.get(key) for key in ("status", "coverage_pct", "unit",
                                               "complete_groups", "unmeasured_groups")}
    compact["totals"] = block.get("totals")
    existing += [
        {"name": PROPERTY_BLOCK, "value": json.dumps(compact, sort_keys=True)},
        {"name": PROPERTY_PCT, "value": str(block.get("coverage_pct"))},
        {"name": PROPERTY_STATUS, "value": str(block.get("status"))},
        {"name": PROPERTY_EXPECTED, "value": str((block.get("totals") or {}).get("expected"))},
        {"name": PROPERTY_OBSERVED, "value": str((block.get("totals") or {}).get("observed"))},
        {"name": PROPERTY_UNMEASURED, "value": json.dumps(block.get("unmeasured_groups") or [])},
        {"name": PROPERTY_TOTAL, "value": "true" if block_claim["may_report_total"] else "false"},
    ]
    metadata["properties"] = existing
    result["metadata"] = metadata
    return result


def qualify(document: Mapping[str, Any]) -> dict[str, Any]:
    """Does this NBOM say how much of the network it covers?

    An NBOM that lists components and carries no coverage block invites exactly the
    reading item 4 forbids, so it is reported as ``UNQUALIFIED`` rather than assumed
    complete.
    """
    properties = {str(row.get("name")): row.get("value")
                  for row in ((document or {}).get("metadata") or {}).get("properties") or []
                  if isinstance(row, Mapping)}
    components = len((document or {}).get("components") or [])
    if PROPERTY_STATUS not in properties:
        return {
            "ok": components == 0,
            "state": "UNQUALIFIED" if components else "EMPTY",
            "components": components,
            "statement": (
                f"{components} component(s) and no coverage block: the document does not "
                "say how much of the network it describes" if components else
                "no components and no coverage block, so nothing is claimed"),
        }
    status = properties[PROPERTY_STATUS]
    return {
        "ok": True,
        "state": status,
        "components": components,
        "coverage_pct": properties.get(PROPERTY_PCT),
        "may_report_total": properties.get(PROPERTY_TOTAL) == "true",
        "statement": (f"coverage {status} at {properties.get(PROPERTY_PCT)}%; a total "
                      + ("may" if properties.get(PROPERTY_TOTAL) == "true" else "may not")
                      + " be quoted"),
    }


def summary(block: Mapping[str, Any]) -> dict[str, Any]:
    """The one-screen answer: the matrix, the gaps, and what may be quoted."""
    totals = block.get("totals") or {}
    return {
        "schema": SCHEMA,
        "status": block.get("status"),
        "coverage_pct": block.get("coverage_pct"),
        "expected": totals.get("expected"),
        "observed": totals.get("observed"),
        "gaps": {key: totals.get(key) for key in
                 ("attempted", "failed", "unauthorized", "unattempted", "excluded")},
        "complete_groups": block.get("complete_groups"),
        "incomplete_groups": block.get("incomplete_groups"),
        "unmeasured_groups": block.get("unmeasured_groups"),
        "may_report_total": (block.get("claim") or claim(block))["may_report_total"],
        "statement": block.get("statement"),
    }
