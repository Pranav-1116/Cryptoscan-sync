#!/usr/bin/env python3
"""Guide 145 — coverage in the CBOM, and what an empty CBOM actually says.

The review's items 18 and 19, made load-bearing:

* 12 RSA assets over 62 of 100 applications is **not** "the bank has 12 RSA
  assets". ``cbom.coverage_render`` turns the estate rollup into a coverage block,
  writes it into the document as metadata properties, and answers the only
  question a report may ask: is this count a total or a floor?
* an empty CBOM has five possible causes and the document now names them. Only
  "detectors ran, files were read, nothing errored, nothing was skipped, and the
  whole estate was inspected" can support "no crypto detected" — and even then
  the statement says it is a statement about the inspected paths.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = "cryptoscan.cbom-coverage-render-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

ROLLUP_PARTIAL = {"systems": 100, "with_cbom": 62,
           "counts": {"NO_TARGET": 5, "NEVER_SCANNED": 25, "CURRENT": 50, "STALE": 12,
                      "FAILED": 8}}
ROLLUP_COMPLETE = {"systems": 10, "with_cbom": 10,
            "counts": {"NO_TARGET": 0, "NEVER_SCANNED": 0, "CURRENT": 10, "STALE": 0,
                       "FAILED": 0}}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(SERVICES / "devsecops"),
                  str(SERVICES / "governance"), str(SERVICES / "quantum"),
                  str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import coverage_render  # noqa: PLC0415

    return {"cr": coverage_render}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def row_the_floor(modules: dict[str, Any]) -> dict[str, Any]:
    cr = modules["cr"]
    partial = cr.inventory_coverage(ROLLUP_PARTIAL, assets=480)
    complete = cr.inventory_coverage(ROLLUP_COMPLETE, assets=40)
    unknown = cr.inventory_coverage({}, assets=3)
    probes = [
        _probe("a-partial-estate-cannot-quote-a-total",
               partial["completeness"] == "PARTIAL" and partial["may_report_total"] is False,
               f"{partial['systems_inspected']}/{partial['systems_total']} inspected, "
               f"{partial['coverage_pct']}%"),
        _probe("the-statement-says-what-was-discovered-not-what-exists",
               partial["statement"].startswith("480 crypto asset(s) discovered")
               and "not what exists" in partial["statement"],
               partial["statement"]),
        _probe("the-unscanned-and-the-failed-are-named",
               "25 never scanned" in partial["statement"]
               and "8 failed" in partial["statement"]
               and any("failure is not an empty result" in caveat
                       for caveat in partial["caveats"]),
               "; ".join(partial["caveats"][1:3])),
        _probe("a-complete-estate-may-quote-a-total",
               complete["completeness"] == "COMPLETE"
               and cr.quotable_counts(complete)["phrasing"] == "TOTAL",
               cr.quotable_counts(complete)["text"]),
        _probe("an-unmeasured-estate-makes-no-claim",
               unknown["completeness"] == "UNKNOWN" and unknown["may_report_total"] is False,
               cr.quotable_counts(unknown)["text"]),
        _probe("coverage-never-exceeds-the-estate",
               cr.inventory_coverage({"systems": 5, "with_cbom": 9,
                                      "counts": {"CURRENT": 9}}, assets=1)["systems_inspected"]
               == 5,
               "inspected is clamped to total rather than reporting 180%"),
    ]
    return {"id": "the_floor",
            "question": "can an asset count be quoted without the coverage that qualifies it?",
            "phase": "review 18", "probes": probes}


def row_document_statement(modules: dict[str, Any]) -> dict[str, Any]:
    cr = modules["cr"]
    block = cr.inventory_coverage(ROLLUP_PARTIAL, assets=480)
    properties = {row["name"]: row["value"] for row in cr.document_properties(block)}
    bom = {"bomFormat": "CycloneDX", "metadata": {}, "components": []}
    once = cr.render_coverage(bom, block)
    router = (SERVICES / "api" / "api" / "routers" / "cbom.py").read_text(encoding="utf-8")
    probes = [
        _probe("the-coverage-block-travels-as-one-property",
               json.loads(properties[cr.PROPERTY_COVERAGE])["may_report_total"] is False,
               properties[cr.PROPERTY_COMPLETENESS] + " / "
               + properties[cr.PROPERTY_PCT] + "%"),
        _probe("the-scalars-exist-for-readers-that-do-not-parse-it",
               properties[cr.PROPERTY_ASSETS] == "480"
               and properties[cr.PROPERTY_COMPLETENESS] == "PARTIAL",
               "assets + completeness + pct beside the block"),
        _probe("the-estate-document-carries-the-coverage",
               "document_properties(coverage_block)" in router,
               "POST-export portfolio BOM states 62/100 rather than 'the bank has'"),
        _probe("the-coverage-endpoint-answers-the-quotable-question",
               "inventory_coverage(summary, assets=assets)" in router
               and '"quotable": quotable_counts(block)' in router,
               "GET /cbom/coverage returns the block and its phrasing"),
        _probe("attaching-coverage-is-idempotent-and-non-mutating",
               len([row for row in cr.render_coverage(once, block)["metadata"]["properties"]
                    if row["name"] == cr.PROPERTY_COVERAGE]) == 1
               and bom["metadata"] == {},
               "re-rendering replaces instead of duplicating"),
    ]
    return {"id": "document_statement",
            "question": "does the document itself carry the coverage, not only the API?",
            "phase": "review 18", "probes": probes}


def row_empty_reasons(modules: dict[str, Any]) -> dict[str, Any]:
    cr = modules["cr"]
    clean = cr.empty_reasons(components=0, files_scanned=900, detectors_ran=5,
                             coverage_block={"completeness": "COMPLETE"})
    unscanned = cr.empty_reasons(components=0)
    failed = cr.empty_reasons(components=0, errors=["scanner crashed"], files_scanned=3)
    skipped = cr.empty_reasons(components=0, files_scanned=10, files_skipped=4,
                               coverage_block={"completeness": "COMPLETE"})
    partial = cr.empty_reasons(components=0, files_scanned=900, detectors_ran=2,
                               coverage_block={"completeness": "PARTIAL"})
    probes = [
        _probe("five-different-statements-not-one",
               set(cr.EMPTY_REASONS) == {"NO_CRYPTO_DETECTED", "NO_INVENTORY_INGESTED",
                                         "PATHS_UNSUPPORTED_OR_EXCLUDED", "SCAN_FAILED",
                                         "COVERAGE_INCOMPLETE"},
               ", ".join(cr.EMPTY_REASONS)),
        _probe("no-crypto-detected-requires-a-clean-inspected-scan",
               clean["reasons"] == ["NO_CRYPTO_DETECTED"]
               and clean["may_conclude_no_crypto"] is True,
               clean["statement"]),
        _probe("an-empty-document-nobody-filled-in-says-exactly-that",
               unscanned["reasons"] == ["NO_INVENTORY_INGESTED"]
               and unscanned["may_conclude_no_crypto"] is False
               and "not evidence that no cryptography exists" in unscanned["statement"],
               unscanned["statement"]),
        _probe("a-failed-scan-is-never-an-empty-result",
               failed["reasons"] == ["SCAN_FAILED"], failed["statement"]),
        _probe("skipped-paths-are-named",
               skipped["reasons"] == ["PATHS_UNSUPPORTED_OR_EXCLUDED"], skipped["statement"]),
        _probe("partial-coverage-is-a-caveat-beside-the-finding",
               partial["reasons"] == ["NO_CRYPTO_DETECTED", "COVERAGE_INCOMPLETE"]
               and partial["may_conclude_no_crypto"] is False,
               partial["statement"]),
    ]
    return {"id": "empty_reasons",
            "question": "does an empty CBOM say which of the five things happened?",
            "phase": "review 19", "probes": probes}


def row_document_empty(modules: dict[str, Any]) -> dict[str, Any]:
    cr = modules["cr"]
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "metadata": {"timestamp": "2026-11-02T00:00:00Z"}, "components": []}
    rendered = cr.render_empty(bom, errors=["boom"], files_scanned=0)
    properties = {row["name"]: row["value"] for row in rendered["metadata"]["properties"]}
    exporter = (SERVICES / "api" / "api" / "routers" / "export.py").read_text(encoding="utf-8")
    probes = [
        _probe("the-document-carries-the-reason",
               properties[cr.PROPERTY_EMPTY] == "true"
               and "SCAN_FAILED" in properties[cr.PROPERTY_EMPTY_REASONS],
               properties[cr.PROPERTY_EMPTY_STATEMENT]),
        _probe("the-document-says-it-is-not-an-absence",
               "not evidence that no cryptography exists"
               in properties[cr.PROPERTY_EMPTY_STATEMENT],
               "an empty document is not a clean bill of health"),
        _probe("rendering-does-not-rewrite-the-document",
               rendered["specVersion"] == "1.5" and rendered["metadata"]["timestamp"]
               == "2026-11-02T00:00:00Z" and bom["metadata"] == {"timestamp":
                                                                "2026-11-02T00:00:00Z"},
               "only the explanation properties are added"),
        _probe("a-non-empty-document-is-left-alone",
               cr.render_empty({"metadata": {}, "components": [{"name": "AES-256-GCM"}]},
                               components=1) == {"metadata": {},
                                                "components": [{"name": "AES-256-GCM"}]},
               "no explanation is attached where none is needed"),
        _probe("the-export-path-renders-it",
               "from cbom.coverage_render import render_empty" in exporter
               and "render_empty(" in exporter,
               "a scan CBOM with no components says why"),
    ]
    return {"id": "document_empty",
            "question": "is the explanation in the artefact a reader receives?",
            "phase": "review 19", "probes": probes}


def row_api_exposure(modules: dict[str, Any]) -> dict[str, Any]:
    router = (SERVICES / "api" / "api" / "routers" / "cbom.py").read_text(encoding="utf-8")
    probes = [
        _probe("the-coverage-route-keeps-its-original-fields",
               "**summary" in router,
               "the estate rollup is still the top level of the response"),
        _probe("no-new-operation-was-added",
               router.count('@router.get("/coverage")') == 1,
               "the surface grew by payload, not by endpoint"),
    ]
    return {"id": "api_exposure",
            "question": "did the coverage land without widening the API surface?",
            "phase": "review 18", "probes": probes}


ROWS = (row_the_floor, row_document_statement, row_empty_reasons, row_document_empty,
        row_api_exposure)


def measure() -> dict[str, Any]:
    modules = _load()
    rows = []
    for builder in ROWS:
        row = builder(modules)
        failed = [probe for probe in row["probes"] if not probe["ok"]]
        if not failed:
            verdict = PASS
        elif len(failed) * 3 <= len(row["probes"]):
            verdict = PARTIAL
        else:
            verdict = FAIL
        row["verdict"] = verdict
        row["failed"] = [probe["probe"] for probe in failed]
        rows.append(row)
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "rows": rows,
        "limits": [
            "coverage is about systems that exist in the register. A business application nobody "
            "registered is invisible to the denominator, so a 100% figure means 'everything we "
            "know about was scanned', not 'everything that exists was scanned'",
            "inspected means a scan produced current or stale evidence. A scan that ran and "
            "found nothing counts as inspected, which is right for coverage and easy to misread "
            "as completeness of the CBOM",
            "the empty-BOM reasons are inferred from counters the collectors report. A collector "
            "that does not report files_scanned or files_skipped will produce a weaker "
            "explanation, never a stronger one",
            "an incomplete estate keeps NO_CRYPTO_DETECTED as a reason and adds "
            "COVERAGE_INCOMPLETE; a reader who stops at the first reason still over-reads it, so "
            "the statement is the field to quote",
            "the property block is JSON in a string, because CycloneDX properties are "
            "name/value pairs. Consumers must parse it to see per-status counts",
            "the export path explains an empty scan CBOM; the portfolio document states "
            "coverage. Other document builders (vendor, host, mainframe) still do not, and this "
            "guide does not claim they do",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Coverage in the CBOM, and what an empty CBOM actually says",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail** · "
        f"{report['probes']} probes",
        "",
        "The review's items 18 and 19:",
        "",
        "> 12 RSA assets discovered, 62/100 applications inspected, coverage 62%, "
        "completeness PARTIAL",
        "",
        "and an empty CBOM is not \"no cryptography exists\" — it may be *no crypto "
        "detected*, *no inventory ingested*, *paths unsupported or excluded*, *scan "
        "failed* or *coverage incomplete*. `cbom.coverage_render` writes both into the "
        "document:",
        "",
        "1. **The floor travels with the count.** `cryptoscan:coverage` (a JSON block), "
        "`cryptoscan:coverage_pct`, `cryptoscan:coverage_completeness` and "
        "`cryptoscan:assets_discovered` are metadata properties, so a downstream reader "
        "cannot quote the asset count without them.",
        "2. **`quotable_counts` answers the only question a report may ask:** is this a "
        "total or a floor? Only a fully inspected estate gets `TOTAL`.",
        "3. **An empty document names its reasons**, in a stable order, with a statement "
        "that says it is not evidence that no cryptography exists.",
        "4. **`NO_CRYPTO_DETECTED` is the only reason that is a statement about "
        "cryptography**, and it requires detectors that ran, files that were read, no "
        "errors and no skipped paths — an incomplete estate is an *additional* caveat, "
        "never a substitute.",
        "",
        "| Row | Question | Verdict | Probes |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* ({row['phase']})", ""]
        for probe in row["probes"]:
            mark = "**PASS**" if probe["ok"] else "**FAIL**"
            lines.append(f"- {mark} `{probe['probe']}` — {probe['observed']}")
    lines += ["", "## What this does not prove", ""]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    if args.md:
        args.md.write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    counts = report["counts"]
    print(f"{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail",
          file=sys.stderr)
    if not args.check:
        return 0
    if counts[FAIL]:
        return 2
    if counts[PARTIAL]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
