#!/usr/bin/env python3
"""Guide 153 — NBOM coverage: an observed endpoint is not the network.

Review item 4 states the failure mode in one sentence: 10,000 endpoints exist, 6,500
are observed, and the NBOM must not imply it is the bank's complete network. The
collection path already refuses to read a *timeout* as plaintext; this guide adds
the same refusal one level up, where the input is an *assessment* rather than a
probe.

What the matrix answers, per target group and for the estate:

    expected · attempted · observed · failed · unauthorized · excluded
             → unattempted, coverage_pct, status, and why

and what it lets a reader say: `TOTAL` only when every group is `COMPLETE`,
otherwise `FLOOR` with the gaps named. An estate with no target list is `UNMEASURED`
— 0% and 100% are both wrong there — and probes that all failed are a scan failure,
not an empty network.
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
SCHEMA = "cryptoscan.nbom-coverage-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

MATRIX: list[dict[str, Any]] = [
    {"target": "External endpoints", "expected": 120, "attempted": 120, "observed": 118},
    {"target": "Internal LB", "expected": 25, "attempted": 25, "observed": 25},
    {"target": "API gateways", "expected": 40, "attempted": 40, "observed": 37},
    {"target": "DB endpoints", "expected": 80, "attempted": 60, "observed": 54},
    {"target": "HSM network interfaces", "expected": 8, "attempted": 8, "observed": 8},
    {"target": "VPN gateways", "expected": 12, "attempted": 10, "observed": 9},
]

ESTATE = {"target": "all endpoints", "expected": 10000, "attempted": 8000,
          "observed": 6500, "failed": 1000, "unauthorized": 500}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import nbom_coverage  # noqa: PLC0415

    return {"nc": nbom_coverage}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _bom() -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"type": "network-endpoint", "bom-ref": "endpoint:1",
                            "name": "payments.bank.example:443"}],
            "metadata": {"properties": [{"name": "cryptoscan:estate", "value": "bank"}]}}


# --------------------------------------------------------------------------- #


def row_observed_is_not_the_network(modules: dict[str, Any]) -> dict[str, Any]:
    nc = modules["nc"]
    block = nc.matrix([ESTATE])
    row = block["groups"][0]
    complete = nc.matrix([{"target": "Internal LB", "expected": 25, "attempted": 25,
                           "observed": 25}])
    probes = [
        _probe("the-review-s-numbers-produce-65-percent",
               block["coverage_pct"] == 65.0 and block["totals"]["observed"] == 6500
               and block["totals"]["expected"] == 10000,
               f"{block['totals']['observed']} of {block['totals']['expected']} "
               f"({block['coverage_pct']}%)"),
        _probe("the-status-is-partial-not-complete",
               block["status"] == "PARTIAL", block["status"]),
        _probe("the-unattempted-endpoints-are-counted",
               row["unattempted"] == 1500,
               f"{row['unattempted']} never attempted = 10,000 − 8,000 − 500"),
        _probe("a-partial-estate-yields-a-floor-never-a-total",
               block["claim"]["basis"] == "FLOOR"
               and block["claim"]["may_report_total"] is False,
               block["claim"]["statement"]),
        _probe("only-a-fully-observed-estate-supports-a-total",
               complete["claim"]["basis"] == "TOTAL"
               and complete["claim"]["may_report_total"] is True,
               complete["claim"]["statement"]),
        _probe("the-gaps-are-named-in-words-not-only-in-numbers",
               all(fragment in block["statement"] for fragment in
                   ("1500 never attempted", "500 unauthorized", "1000 failed")),
               block["statement"]),
    ]
    return {"id": "observed_is_not_the_network",
            "question": "does 6,500 observed endpoints read as a 10,000-endpoint estate?",
            "phase": "review 4", "probes": probes}


def row_five_statuses(modules: dict[str, Any]) -> dict[str, Any]:
    nc = modules["nc"]
    cases = {
        "COMPLETE": {"target": "Internal LB", "expected": 25, "attempted": 25,
                     "observed": 25},
        "PARTIAL": {"target": "API gateways", "expected": 40, "attempted": 40,
                    "observed": 37},
        "FAILED": {"target": "DMZ", "expected": 10, "attempted": 10, "observed": 0,
                   "failed": 10},
        "UNAUTHORIZED": {"target": "Partner VPN", "expected": 12, "attempted": 0,
                         "observed": 0, "unauthorized": 12},
        "UNMEASURED": {"target": "Partner network", "expected": 0},
    }
    statuses = {name: nc.matrix([row])["groups"][0]["status"]
                for name, row in cases.items()}
    unmeasured = nc.matrix([cases["UNMEASURED"]])
    probes = [
        _probe("all-five-statuses-are-reachable-and-distinct",
               statuses == {name: name for name in cases},
               json.dumps(statuses, sort_keys=True)),
        _probe("an-unmeasured-group-is-neither-0-nor-100-percent",
               unmeasured["coverage_pct"] is None
               and "0% and 100% are both wrong"
               in unmeasured["groups"][0]["statement"],
               unmeasured["groups"][0]["statement"]),
        _probe("probes-that-all-failed-are-a-scan-failure-not-an-empty-network",
               "scan failure, not an empty network"
               in nc.matrix([cases["FAILED"]])["groups"][0]["statement"],
               nc.matrix([cases["FAILED"]])["groups"][0]["statement"]),
        _probe("an-unauthorized-group-is-called-an-authorization-gap",
               "not authorized" in nc.matrix([cases["UNAUTHORIZED"]])["groups"][0]["statement"],
               nc.matrix([cases["UNAUTHORIZED"]])["groups"][0]["statement"]),
        _probe("a-complete-group-says-so-without-a-caveat",
               nc.matrix([cases["COMPLETE"]])["groups"][0]["reasons"] == [],
               "no reasons, because there is no gap"),
    ]
    return {"id": "five_statuses",
            "question": "is 'not complete' fine-grained enough to act on?",
            "phase": "review 5", "probes": probes}


def row_arithmetic_checked(modules: dict[str, Any]) -> dict[str, Any]:
    nc = modules["nc"]
    refusals: dict[str, str] = {}

    def refuse(name: str, row: dict[str, Any]) -> None:
        try:
            nc.matrix([row])
        except ValueError as exc:
            refusals[name] = str(exc)

    refuse("observed_above_expected",
           {"target": "x", "expected": 5, "attempted": 5, "observed": 6})
    refuse("attempted_above_expected",
           {"target": "x", "expected": 5, "attempted": 6, "observed": 1})
    refuse("observed_above_attempted",
           {"target": "x", "expected": 5, "attempted": 1, "observed": 2})
    refuse("negative", {"target": "x", "expected": -1})
    refuse("boolean", {"target": "x", "expected": True})
    refuse("no_target", {"expected": 5})
    refuse("duplicate", {"target": "dmz", "expected": 1})
    try:
        nc.matrix([{"target": "DMZ", "expected": 1}, {"target": "dmz", "expected": 1}])
    except ValueError as exc:
        refusals["duplicate"] = str(exc)
    probes = [
        _probe("an-observation-above-the-target-list-is-refused",
               "target list is stale" in refusals.get("observed_above_expected", ""),
               refusals.get("observed_above_expected", "accepted")),
        _probe("a-probe-against-an-uninventoried-endpoint-is-refused",
               "nobody inventoried" in refusals.get("attempted_above_expected", ""),
               refusals.get("attempted_above_expected", "accepted")),
        _probe("an-observation-without-a-probe-is-refused",
               "an observation needs a probe" in refusals.get("observed_above_attempted", ""),
               refusals.get("observed_above_attempted", "accepted")),
        _probe("a-negative-or-boolean-count-is-refused",
               "cannot be negative" in refusals.get("negative", "")
               and "not a boolean" in refusals.get("boolean", ""),
               refusals.get("boolean", "accepted")),
        _probe("a-row-with-no-target-is-refused",
               "needs a target" in refusals.get("no_target", ""),
               refusals.get("no_target", "accepted")),
        _probe("the-same-group-twice-is-refused-rather-than-summed",
               "appears twice" in refusals.get("duplicate", ""),
               refusals.get("duplicate", "accepted")),
    ]
    return {"id": "arithmetic_checked",
            "question": "can a stale target list produce a plausible percentage?",
            "phase": "review 4", "probes": probes}


def row_from_probes(modules: dict[str, Any]) -> dict[str, Any]:
    nc = modules["nc"]
    body = nc.from_probes("External endpoints", [
        {"endpoint": "a.bank.example:443", "status": "OK"},
        {"endpoint": "b.bank.example:443", "status": "OK"},
        {"endpoint": "c.bank.example:443", "status": "TIMEOUT"},
        {"endpoint": "d.bank.example:443", "status": "UNAUTHORIZED"},
        {"endpoint": "e.bank.example:443", "status": "MAYBE"},
    ], declared=["a.bank.example:443", "b.bank.example:443", "c.bank.example:443",
                 "d.bank.example:443", "f.bank.example:443"])
    row = body["row"]
    probes = [
        _probe("a-successful-handshake-is-observed",
               row["observed"] == 2, f"{row['observed']} observed"),
        _probe("a-timeout-is-a-failure-and-never-an-observation",
               row["failed"] == 1 and row["observed"] == 2,
               f"failed={row['failed']}, observed={row['observed']}"),
        _probe("an-unauthorized-probe-is-not-counted-as-attempted",
               row["unauthorized"] == 1 and row["attempted"] == 3,
               f"unauthorized={row['unauthorized']}, attempted={row['attempted']}"),
        _probe("an-undocumented-status-is-refused-not-bucketed",
               len(body["refused"]) == 1
               and "not a documented probe outcome" in body["refused"][0]["reason"],
               body["refused"][0]["reason"]),
        _probe("a-declared-endpoint-nobody-probed-is-the-gap",
               row["declared_not_probed"] == ["f.bank.example:443"]
               and row["unattempted"] == 1,
               f"{row['unattempted']} unattempted: {row['declared_not_probed']}"),
        _probe("the-row-is-partial-because-a-declared-endpoint-was-never-probed",
               row["status"] == "PARTIAL"
               and "never probed" in body["statement"],
               body["statement"]),
    ]
    return {"id": "from_probes",
            "question": "does a stored probe ledger produce an honest coverage row?",
            "phase": "review 4 / 3", "probes": probes}


def row_document_carries_the_claim(modules: dict[str, Any]) -> dict[str, Any]:
    nc = modules["nc"]
    block = nc.matrix(MATRIX)
    document = nc.attach(_bom(), block)
    properties = {row["name"]: row["value"] for row in document["metadata"]["properties"]}
    unqualified = nc.qualify(_bom())
    empty = nc.qualify({"components": [], "metadata": {}})
    complete = nc.attach(_bom(), nc.matrix([
        {"target": "Internal LB", "expected": 25, "attempted": 25, "observed": 25}]))
    probes = [
        _probe("the-block-travels-with-the-document",
               properties[nc.PROPERTY_STATUS] == block["status"]
               and properties[nc.PROPERTY_PCT] == str(block["coverage_pct"]),
               f"{properties[nc.PROPERTY_STATUS]} at "
               f"{properties[nc.PROPERTY_PCT]}% of "
               f"{properties[nc.PROPERTY_EXPECTED]}"),
        _probe("the-total-claim-is-a-property-a-reader-cannot-miss",
               properties[nc.PROPERTY_TOTAL] == "false",
               f"{nc.PROPERTY_TOTAL} = {properties[nc.PROPERTY_TOTAL]}"),
        _probe("existing-document-properties-survive",
               "cryptoscan:estate" in properties,
               "the estate property is still there"),
        _probe("an-nbom-with-components-and-no-coverage-is-unqualified",
               unqualified["state"] == "UNQUALIFIED" and unqualified["ok"] is False,
               unqualified["statement"]),
        _probe("an-empty-nbom-claims-nothing-so-it-is-not-lying",
               empty["state"] == "EMPTY" and empty["ok"] is True,
               empty["statement"]),
        _probe("a-complete-document-may-report-a-total",
               nc.qualify(complete)["may_report_total"] is True
               and "may be quoted" in nc.qualify(complete)["statement"],
               nc.qualify(complete)["statement"]),
    ]
    return {"id": "document_carries_the_claim",
            "question": "does the NBOM itself say how much of the network it covers?",
            "phase": "review 4 / 5", "probes": probes}


ROWS = (row_observed_is_not_the_network, row_five_statuses, row_arithmetic_checked,
        row_from_probes, row_document_carries_the_claim)


def measure() -> dict[str, Any]:
    modules = _load()
    rows = []
    for builder in ROWS:
        row = builder(modules)
        failed = [probe for probe in row["probes"] if not probe["ok"]]
        if not failed:
            verdict = VERDICT_PASS
        elif len(failed) * 3 <= len(row["probes"]):
            verdict = VERDICT_PARTIAL
        else:
            verdict = VERDICT_FAIL
        row["verdict"] = verdict
        row["failed"] = [probe["probe"] for probe in failed]
        rows.append(row)
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL)}
    nc = modules["nc"]
    block = nc.matrix(MATRIX, as_of="2026-11-02")
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "statuses": list(nc.STATUSES),
        "reasons": list(nc.REASONS),
        "matrix": block,
        "estate_example": nc.matrix([ESTATE]),
        "summary": nc.summary(block),
        "claim": block["claim"],
        "rows": rows,
        "limits": [
            "the expected count comes from the estate's target list. If nobody "
            "inventoried the network to begin with, the matrix is arithmetically "
            "correct and still describes the wrong denominator — that is why a group "
            "with no targets is UNMEASURED rather than 0%",
            "coverage is counted per endpoint, not per service behind it. One IP with "
            "twelve virtual hosts is one endpoint here and twelve listeners in the "
            "NBOM, and neither number is wrong as long as the unit is read",
            "a probe status vocabulary is a contract. A scanner that starts emitting a "
            "new outcome will have its rows refused until the status is mapped, which "
            "is deliberate: silently bucketing a new failure mode into 'observed' is "
            "the failure this module exists to prevent",
            "the numbers describe a moment. A run six weeks old is still COMPLETE for "
            "the endpoints it probed, so staleness has to be read from the run, not "
            "inferred from coverage_pct",
            "coverage says how much was looked at, never how much cryptography is "
            "there. A 100% covered estate with an empty NBOM is a measurement; a 65% "
            "estate with 6,500 listeners is a floor",
            "attaching the block to a document does not enforce it. A reader that "
            "ignores cryptoscan:network_may_report_total can still quote a total, which "
            "is why qualify() exists for the readers the platform controls",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    block = report["matrix"]
    summary = report["summary"]
    estate = report["estate_example"]
    lines = [
        "# NBOM coverage: an observed endpoint is not the network",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review item 4: an estate with 10,000 endpoints and 6,500 observed must not "
        "produce an NBOM that reads as *the bank's network*. The collection path "
        "already refuses to read a timeout as plaintext; this is the same refusal one "
        "level up.",
        "",
        "```",
        "expected · attempted · observed · failed · unauthorized · excluded",
        "      → unattempted · coverage_pct · status · reasons",
        "      → TOTAL (only when every group is COMPLETE) or FLOOR",
        "```",
        "",
        f"Review's own numbers: **{estate['coverage_pct']}%** — "
        f"{estate['totals']['observed']} of {estate['totals']['expected']} observed, "
        f"{estate['status']}, {estate['totals']['unattempted']} never attempted; "
        f"claim basis **{estate['claim']['basis']}**.",
        "",
        "| status | what it means | can a total be quoted? |",
        "|---|---|---|",
        "| `COMPLETE` | every expected endpoint was observed | yes, for that group |",
        "| `PARTIAL` | some were, and the rest are named | no — a floor |",
        "| `FAILED` | probes ran and none negotiated | no: a scan failure |",
        "| `UNAUTHORIZED` | nothing was attempted | no: an authorization gap |",
        "| `UNMEASURED` | no target list | no: 0% and 100% are both wrong |",
        "",
        "## The estate network coverage matrix",
        "",
        "| Target | Expected | Attempted | Observed | Unattempted | Coverage | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in block["groups"]:
        lines.append(f"| {row['target']} | {row['expected']} | {row['attempted']} | "
                     f"{row['observed']} | {row['unattempted']} | "
                     f"{row['coverage_pct']}% | **{row['status']}** |")
    lines += [
        "",
        f"{summary['statement']}",
        "",
        f"`{report['claim']['basis']}` — {report['claim']['statement']}",
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
        args.json.write_text(json.dumps(report, indent=2, default=str) + "\n",
                             encoding="utf-8")
    if args.md:
        args.md.write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    counts = report["counts"]
    print(f"{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
          f"{counts[VERDICT_FAIL]} fail", file=sys.stderr)
    if not args.check:
        return 0
    if counts[VERDICT_FAIL]:
        return 2
    if counts[VERDICT_PARTIAL]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
