"""Coverage and empty CBOMs, rendered into the document itself.

The review's items 18 and 19:

**18 — a CBOM needs coverage.** 12 RSA assets over 62 of 100 applications is not
"the bank has 12 RSA assets". It is "12 discovered, 62/100 inspected, 62%", with
completeness ``PARTIAL``. The platform already refuses to say the first; this
module makes the second travel *in the document* as metadata properties, so a
downstream reader cannot quote a floor as a total.

**19 — an empty CBOM is not an absence of cryptography.** It can be no crypto
detected, no inventory ingested, unsupported or excluded paths, a failed scan, or
an incomplete estate. Those are five different statements and the document has to
say which ones apply instead of leaving a reader to assume the reassuring one.

Both are pure functions over facts the platform already has: the system coverage
rollup, the asset count, the collector's file counters and the scan's errors.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from cbom import coverage as scan_coverage
from cbom import usage_evidence as ue

SCHEMA = "cryptoscan.cbom-coverage/1"

#: Why a CBOM can be empty. Ordered from "we looked and found nothing" (the only
#: one that is a statement about cryptography) to "we could not look".
EMPTY_REASONS: tuple[str, ...] = (
    "NO_CRYPTO_DETECTED",
    "NO_INVENTORY_INGESTED",
    "PATHS_UNSUPPORTED_OR_EXCLUDED",
    "SCAN_FAILED",
    "COVERAGE_INCOMPLETE",
)

_REASON_TEXT = {
    "NO_CRYPTO_DETECTED": "the detectors ran and found no cryptographic material in the paths "
                          "that were inspected",
    "NO_INVENTORY_INGESTED": "no scan or inventory reached this system, so nothing was ever "
                             "looked for",
    "PATHS_UNSUPPORTED_OR_EXCLUDED": "part of the tree was skipped (unsupported file types, "
                                     "exclusions or unreadable paths)",
    "SCAN_FAILED": "the scan reported errors; an empty result over a failed scan says nothing",
    "COVERAGE_INCOMPLETE": "the estate was only partly inspected, so an empty result here says "
                           "nothing about the rest",
}

#: The properties written onto a CBOM. ``cryptoscan:inventory_completeness`` is
#: already used by the retained-history path with a different vocabulary, so this
#: module deliberately uses its own key rather than overloading that one.
PROPERTY_COVERAGE = "cryptoscan:coverage"
PROPERTY_PCT = "cryptoscan:coverage_pct"
PROPERTY_COMPLETENESS = "cryptoscan:coverage_completeness"
PROPERTY_ASSETS = "cryptoscan:assets_discovered"
PROPERTY_EMPTY = "cryptoscan:empty_bom"
PROPERTY_EMPTY_REASONS = "cryptoscan:empty_bom_reasons"
PROPERTY_EMPTY_STATEMENT = "cryptoscan:empty_bom_statement"


def inventory_coverage(rollup: Mapping[str, Any] | None = None, *,
                       assets: int = 0, unit: str = "application",
                       as_of: str | None = None, systems_inspected: int | None = None,
                       failed_jobs: int = 0, partial_systems: int = 0) -> dict[str, Any]:
    """The coverage block: what was inspected, what was found, and what may be quoted.

    ``rollup`` is the estate scan rollup (``coverage.rollup``): systems by status.
    An asset count over a partial estate is a **floor**; only ``COMPLETE`` lets it
    be read as a total, which is what ``may_report_total`` says.

    ``systems_inspected`` overrides the rollup's stored-status count with one
    derived from collection facts (a stored ``CURRENT`` is not an inspection).
    A failed job or a partially inspected system makes the block ``PARTIAL``:
    an estate with a failed collection is never ``COMPLETE``.
    """
    counts = dict((rollup or {}).get("counts") or {})
    total = int((rollup or {}).get("systems") or 0)
    inspected = int((rollup or {}).get("with_cbom") or 0) if systems_inspected is None else int(systems_inspected)
    block = ue.coverage(total, inspected, assets, unit=unit)
    if block["completeness"] == "COMPLETE" and (failed_jobs or partial_systems):
        block["completeness"] = "PARTIAL"
        block["quotable_as_total"] = False
        block["statement"] = (f"{assets} crypto asset(s) discovered; {inspected}/{total} {unit}(s) inspected, but "
                              f"{failed_jobs} collection job(s) failed and {partial_systems} {unit}(s) are only "
                              "partially inspected; the count is what was discovered, not what exists")
    never_scanned = int(counts.get("NEVER_SCANNED") or 0)
    failed = int(counts.get("FAILED") or 0)
    stale = int(counts.get("STALE") or 0)
    no_target = int(counts.get("NO_TARGET") or 0)
    caveats = [
        "an asset count is what the collectors found, not what the estate contains",
    ]
    if never_scanned:
        caveats.append(f"{never_scanned} {unit}(s) were never scanned; their cryptography is "
                       "unknown, not absent")
    if failed:
        caveats.append(f"{failed} {unit}(s) failed their scan; a failure is not an empty result")
    if stale:
        caveats.append(f"{stale} {unit}(s) are covered by a scan older than "
                       f"{scan_coverage.STALE_DAYS} days")
    if no_target:
        caveats.append(f"{no_target} {unit}(s) have no scan target configured")
    if failed_jobs:
        caveats.append(f"{failed_jobs} collection job(s) failed; their targets' current cryptography is unknown")
    if partial_systems:
        caveats.append(f"{partial_systems} {unit}(s) were only partially inspected")
    return {
        "schema": SCHEMA,
        "as_of": as_of or datetime.now(timezone.utc).isoformat(),
        "unit": unit,
        "systems_total": block["systems_total"],
        "systems_inspected": block["systems_inspected"],
        "coverage_pct": block["coverage_pct"],
        "completeness": block["completeness"],
        "may_report_total": bool(block["quotable_as_total"]),
        "assets_discovered": block["assets_discovered"],
        "status_counts": {key: int(counts.get(key) or 0) for key in scan_coverage.STATUSES},
        "never_scanned": never_scanned,
        "failed": failed,
        "stale": stale,
        "no_target": no_target,
        "failed_jobs": int(failed_jobs),
        "partial_systems": int(partial_systems),
        "caveats": caveats,
        "statement": (block["statement"]
                      + f"; {never_scanned} never scanned, {failed} failed, {stale} stale"),
    }


def document_properties(block: Mapping[str, Any]) -> list[dict[str, str]]:
    """Coverage as CycloneDX metadata properties.

    The compact JSON block is the machine-readable form; the scalar properties
    exist so a reader that does not parse the block still sees the percentage and
    the completeness instead of only the asset count.
    """
    compact = {
        "unit": block.get("unit"),
        "systems_total": block.get("systems_total"),
        "systems_inspected": block.get("systems_inspected"),
        "coverage_pct": block.get("coverage_pct"),
        "completeness": block.get("completeness"),
        "may_report_total": block.get("may_report_total"),
        "assets_discovered": block.get("assets_discovered"),
        "status_counts": block.get("status_counts"),
        "failed_jobs": block.get("failed_jobs", 0),
        "partial_systems": block.get("partial_systems", 0),
        "as_of": block.get("as_of"),
    }
    return [
        {"name": PROPERTY_COVERAGE, "value": json.dumps(compact, sort_keys=True)},
        {"name": PROPERTY_PCT, "value": str(block.get("coverage_pct"))},
        {"name": PROPERTY_COMPLETENESS, "value": str(block.get("completeness"))},
        {"name": PROPERTY_ASSETS, "value": str(block.get("assets_discovered"))},
    ]


def empty_reasons(*, components: int, errors: Any = None, files_scanned: int = 0,
                  files_skipped: int = 0, detectors_ran: int = 0,
                  imported: bool = False,
                  coverage_block: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Why this document has no components — several answers, never one.

    ``NO_CRYPTO_DETECTED`` is the only reason that is a statement about
    cryptography, and it is only available when the detectors actually ran, over
    files that were actually read, without errors, on a complete estate.
    """
    if components:
        return {"empty": False, "reasons": [], "statements": {},
                "statement": f"{components} component(s) present; the document is not empty",
                "may_conclude_no_crypto": False}
    # A scan that read files is a scan whose detectors ran; the counter is not
    # always recorded, and inventing "nothing was ingested" would be as wrong as
    # inventing "no crypto exists".
    ran = bool(detectors_ran) or files_scanned > 0
    reasons: list[str] = []
    if errors:
        reasons.append("SCAN_FAILED")
    if imported and not ran:
        reasons.append("NO_INVENTORY_INGESTED")
    elif ran and not files_scanned:
        reasons.append("PATHS_UNSUPPORTED_OR_EXCLUDED")
    if files_skipped:
        reasons.append("PATHS_UNSUPPORTED_OR_EXCLUDED")
    if coverage_block is not None and coverage_block.get("completeness") != "COMPLETE":
        reasons.append("COVERAGE_INCOMPLETE")
    # "We looked and saw nothing" is available only when the look was clean: the
    # detectors ran, files were read, nothing errored and nothing was skipped. An
    # incomplete estate does not withdraw it — it is added as a caveat beside it.
    if ran and files_scanned and not errors and not files_skipped:
        reasons.append("NO_CRYPTO_DETECTED")
    if not reasons:
        # Nothing ran and nothing failed: the honest answer is that the question was
        # never asked, which is *not* "no crypto detected".
        reasons.append("NO_INVENTORY_INGESTED")
    ordered = [reason for reason in EMPTY_REASONS if reason in reasons]
    statements = {reason: _REASON_TEXT[reason] for reason in ordered}
    may_conclude = ordered == ["NO_CRYPTO_DETECTED"]
    return {
        "empty": True,
        "reasons": ordered,
        "statements": statements,
        "may_conclude_no_crypto": may_conclude,
        "statement": (
            "the document has no components: " + "; ".join(statements[reason]
                                                           for reason in ordered)
            + ("; this is a statement about the inspected paths, not about the estate"
               if may_conclude else
               "; it is not evidence that no cryptography exists")),
    }


def render_empty(bom: Mapping[str, Any], **kwargs: Any) -> dict[str, Any]:
    """Attach the empty-BOM explanation to a document, without rewriting it."""
    kwargs.pop("components", None)
    explanation = empty_reasons(components=len((bom or {}).get("components") or []), **kwargs)
    if not explanation["empty"]:
        return dict(bom)
    rendered = copy.deepcopy(dict(bom))
    metadata = rendered.setdefault("metadata", {})
    properties = list(metadata.get("properties") or [])
    properties += [
        {"name": PROPERTY_EMPTY, "value": "true"},
        {"name": PROPERTY_EMPTY_REASONS, "value": json.dumps(explanation["reasons"])},
        {"name": PROPERTY_EMPTY_STATEMENT, "value": explanation["statement"]},
    ]
    metadata["properties"] = properties
    return rendered


def render_coverage(bom: Mapping[str, Any], block: Mapping[str, Any]) -> dict[str, Any]:
    """Attach the coverage block to a document (idempotent)."""
    rendered = copy.deepcopy(dict(bom))
    metadata = rendered.setdefault("metadata", {})
    names = {PROPERTY_COVERAGE, PROPERTY_PCT, PROPERTY_COMPLETENESS, PROPERTY_ASSETS}
    properties = [row for row in (metadata.get("properties") or [])
                  if not (isinstance(row, Mapping) and row.get("name") in names)]
    properties += document_properties(block)
    metadata["properties"] = properties
    return rendered


def quotable_counts(block: Mapping[str, Any]) -> dict[str, Any]:
    """How a report may phrase the asset count, given the coverage block."""
    assets = int(block.get("assets_discovered") or 0)
    if block.get("may_report_total") or block.get("quotable_as_total"):
        return {"phrasing": "TOTAL",
                "text": f"{assets} crypto asset(s) across the estate",
                "caveat": None}
    return {"phrasing": "FLOOR",
            "text": (f"{assets} crypto asset(s) discovered over "
                     f"{block.get('systems_inspected')}/{block.get('systems_total')} "
                     f"{block.get('unit')}(s) ({block.get('coverage_pct')}%)"),
            "caveat": "a floor, not a total: the uninspected remainder is unknown"}
