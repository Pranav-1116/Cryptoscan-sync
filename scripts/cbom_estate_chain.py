#!/usr/bin/env python3
"""Guide 147 — the whole CBOM chain over one estate, and the seams between the layers.

Every previous guide proved one layer: the runtime trace, the key inventory, the
evidence classes, the promotion ladder, the coverage block, the handoff, the twin
edges. A reviewer never accepts a layer at a time — they ask whether the *pipeline*
holds together:

    SBOM ─┐
    static ├─→ evidence classes ─→ usage profile ─→ promotion ─→ CBOM document
    config │                                              │
    runtime┤                                              ├─→ PQC handoff
    network┘                                              └─→ twin edges
    KMS ──→ key records ─→ configured vs used
    coverage ──→ what the document may say about totals

``cbom.estate_chain.run`` takes one estate description, runs every layer over the
same evidence, and then checks seven invariants across the results. A failed check
is reported as a broken pipeline, never smoothed away by editing the document.
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
SCHEMA = "cryptoscan.cbom-estate-chain-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

OP = {"application": "payments-api", "pid": 9182, "provider": "OpenSSL",
      "provider_version": "3.0.11", "operation": "EVP_EncryptInit_ex",
      "algorithm": "AES-256-GCM", "key_size": 256, "mode": "GCM",
      "observed_at": "2026-11-02T10:42:11Z", "evidence_id": "RUNTIME-1"}

ENABLED = {"key_ref": "arn:aws:kms:eu-west-1:111:key/abc", "algorithm": "RSA",
           "key_size": 2048, "provider": "AWS_KMS", "status": "ENABLED",
           "created_at": "2025-01-01", "evidence_id": "KMS-1"}
DISABLED = {"key_ref": "arn:aws:kms:eu-west-1:111:key/old", "algorithm": "AES",
            "key_size": 256, "provider": "AWS_KMS", "status": "DISABLED",
            "created_at": "2024-01-01", "evidence_id": "KMS-2"}

ESTATE: dict[str, Any] = {
    "name": "bank-estate-2026-11",
    "as_of": "2026-11-02",
    "components": [{"name": "openssl", "version": "3.0.13", "evidence_id": "SBOM-1",
                    "algorithms": ["AES-256-GCM", "RSA-2048", "AES-128-CBC"]}],
    "declared_versions": [{"name": "openssl", "version": "3.0.13",
                           "evidence_id": "SBOM-1"}],
    "operations": [OP],
    "keys": [ENABLED, DISABLED],
    "key_uses": [
        {"key_ref": ENABLED["key_ref"], "operation": "decrypt",
         "evidence_id": "KMS-USE-1", "observed_at": "2026-11-01"},
        {"key_ref": DISABLED["key_ref"], "operation": "decrypt",
         "evidence_id": "KMS-USE-2", "observed_at": "2026-11-01"},
    ],
    "probes": [{"endpoint": "payments.bank.example:443", "status": "OK",
                "crypto": {"tls_version": "1.3",
                           "cipher_suite": "TLS_AES_256_GCM_SHA384"},
                "evidence_id": "NET-1", "observed_at": "2026-11-02T00:00:00Z"}],
    "findings": [{"algorithm": "AES-128-CBC", "file": "legacy.java", "line": 12,
                  "evidence_id": "STATIC-1"}],
    "conflicts": [
        {"field": "version", "fact": "3.0.13", "source": "sbom", "evidence_id": "SBOM-1"},
        {"field": "version", "fact": "3.0.11", "source": "runtime",
         "evidence_id": "RUNTIME-1"},
        {"field": "cipher_suite", "fact": "TLS_AES_256_GCM_SHA384", "source": "network",
         "evidence_id": "NET-1"},
        {"field": "cipher_suite", "fact": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
         "source": "runtime", "evidence_id": "RUNTIME-2"},
    ],
    "coverage": {"rollup": {"systems": 100, "with_cbom": 62,
                            "counts": {"CURRENT": 50, "STALE": 12, "NEVER_SCANNED": 25,
                                       "FAILED": 8, "NO_TARGET": 5}},
                 "files_scanned": 900},
}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import coverage_render, estate_chain, promotion  # noqa: PLC0415

    return {"ec": estate_chain, "cr": coverage_render, "promo": promotion}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _properties(document: dict[str, Any]) -> dict[str, Any]:
    return {row["name"]: row["value"]
            for row in ((document.get("metadata") or {}).get("properties") or [])}


def _estate(**overrides) -> dict[str, Any]:
    estate = json.loads(json.dumps(ESTATE))
    for key, value in overrides.items():
        if value is None:
            estate.pop(key, None)
        else:
            estate[key] = value
    return estate


# --------------------------------------------------------------------------- #


def row_runtime(modules: dict[str, Any]) -> dict[str, Any]:
    ec = modules["ec"]
    result = ec.run(_estate())
    trace = result["runtime"]["traces"][0]
    correlation = result["runtime"]["correlation"][0]
    unknown = ec.run(_estate(operations=[{**OP, "provider_version": None}]))
    probes = [
        _probe("the-chain-arrives-whole",
               trace["chain"]["process"] == "process:payments-api/9182"
               and trace["chain"]["operation"] == "operation:EVP_EncryptInit_ex",
               " → ".join(trace["chain"].values())),
        _probe("the-version-mismatch-is-reported-not-resolved",
               correlation["state"] == "VERSION_MISMATCH"
               and set(correlation["evidence_ids"]) == {"SBOM-1", "RUNTIME-1"},
               f"{correlation['declared_versions']} declared, "
               f"{correlation['runtime_version']} loaded"),
        _probe("an-unknown-provider-version-is-not-guessed",
               unknown["runtime"]["correlation"][0]["state"] == "RUNTIME_VERSION_UNKNOWN"
               and unknown["runtime"]["providers"][0]["version_known"] is False,
               "the process did not say which provider version it loaded, and the chain "
               "does not fill it in from the SBOM"),
        _probe("runtime-evidence-is-runtime-observed-and-nothing-more",
               all(event["class"] == "RUNTIME_OBSERVED"
                   for event in result["evidence"]["events"]
                   if event.get("layer") == "runtime"
                   and event.get("evidence_id") == "RUNTIME-1"),
               "a trace is an observation of an operation, not a quantum verdict"),
    ]
    return {"id": "runtime",
            "question": "does the runtime layer keep the chain and the disagreement?",
            "phase": "review 7", "probes": probes}


def row_keys(modules: dict[str, Any]) -> dict[str, Any]:
    ec = modules["ec"]
    result = ec.run(_estate())
    records = {record["key_ref"]: record for record in result["keys"]["records"]}
    suppressed = result["evidence"]["suppressed"]
    configured_event = [event for event in result["keys"]["events"]["events"]
                        if event["class"] == "CONFIGURED"]
    probes = [
        _probe("a-key-exists-and-a-key-is-used-are-different-classes",
               all(event["class"] == "CONFIGURED" for event in configured_event)
               and any(event["class"] == "RUNTIME_OBSERVED"
                       for event in result["keys"]["events"]["events"]),
               result["keys"]["events"]["statement"]),
        _probe("a-disabled-key-is-carried-as-not-usable",
               records[DISABLED["key_ref"]]["usable"] is False
               and records[ENABLED["key_ref"]]["usable"] is True,
               f"{records[DISABLED['key_ref']]['status']} key: usable=False"),
        _probe("an-operation-on-a-disabled-key-is-refused-with-its-reason",
               len(suppressed) == 1 and "DISABLED" in suppressed[0]["reason"],
               suppressed[0]["reason"]),
        _probe("no-suppressed-key-operation-reaches-the-evidence-set",
               all(event.get("key_ref") != DISABLED["key_ref"]
                   for event in result["evidence"]["events"]),
               f"{len(result['evidence']['events'])} evidence event(s), none from the "
               "disabled key"),
        _probe("no-key-material-is-ever-carried",
               all(record.get("private_material") == "NOT STORED"
                   for record in result["keys"]["records"]),
               "metadata only: the key layer stores no secret"),
    ]
    return {"id": "keys",
            "question": "is a configured key kept apart from a used key?",
            "phase": "review 11", "probes": probes}


def row_promotion(modules: dict[str, Any]) -> dict[str, Any]:
    ec, promo = modules["ec"], modules["promo"]
    result = ec.run(_estate())
    capability = ec.run({"name": "capabilities-only", "components": [
        {"name": "openssl", "version": "3.0.13", "evidence_id": "SBOM-1",
         "algorithms": ["AES-256-GCM", "RSA-2048"]}]})
    unattributed = ec.run(_estate(operations=[{**OP, "evidence_id": None}], probes=[]))
    runtime_only = ec.run(_estate(probes=[], findings=[]))
    levels = {asset["algorithm"]: asset["promotion_level"]
              for asset in result["promotion"]["assets"]}
    probes = [
        _probe("a-capability-never-becomes-a-document-asset",
               capability["document"]["components"] == []
               and {candidate["algorithm"]
                    for candidate in capability["promotion"]["candidates"]}
               == {"AES-256-GCM", "RSA-2048"},
               capability["promotion"]["statement"]),
        _probe("an-observed-operation-becomes-an-asset",
               [component["name"] for component in result["document"]["components"]]
               == ["AES-256-GCM"],
               f"a candidate for {len(result['promotion']['candidates'])} algorithm(s), "
               f"documented for {len(result['document']['components'])}"),
        _probe("the-level-is-recomputed-from-the-classes",
               all(asset["promotion_level"] == promo.promotion_level(
                       asset["profile"]["observed_classes"])
                   for asset in result["promotion"]["assets"]),
               json.dumps(levels, sort_keys=True)),
        _probe("one-observing-mechanism-never-reads-as-verified",
               {asset["algorithm"]: asset["promotion_level"]
                for asset in runtime_only["promotion"]["assets"]}["AES-256-GCM"] == "RUNTIME"
               and levels["AES-256-GCM"] == "VERIFIED",
               "runtime alone is RUNTIME; runtime and a handshake agreeing is VERIFIED"),
        _probe("an-observation-without-an-evidence-id-is-refused",
               unattributed["document"]["components"] == []
               and any("evidence_id" in str(row.get("reason"))
                       for row in unattributed["evidence"]["refused"]),
               [row["reason"] for row in unattributed["evidence"]["refused"]
                if "evidence_id" in str(row.get("reason"))][0]),
    ]
    return {"id": "promotion",
            "question": "does only the evidence reach the document?",
            "phase": "review 5 / 12", "probes": probes}


def row_the_document(modules: dict[str, Any]) -> dict[str, Any]:
    ec, cr = modules["ec"], modules["cr"]
    result = ec.run(_estate())
    properties = _properties(result["document"])
    empty = ec.run({})
    empty_properties = _properties(empty["document"])
    probes = [
        _probe("the-document-has-no-top-level-properties-array",
               "properties" not in result["document"]
               and result["document"]["metadata"]["properties"],
               "platform claims live in metadata.properties, as CycloneDX expects"),
        _probe("the-document-states-its-coverage",
               properties.get(cr.PROPERTY_COVERAGE)
               and properties.get(cr.PROPERTY_COMPLETENESS) == "PARTIAL",
               f"completeness={properties.get(cr.PROPERTY_COMPLETENESS)}, "
               f"pct={properties.get(cr.PROPERTY_PCT)}"),
        _probe("the-document-does-not-quote-a-total-it-cannot-support",
               result["coverage"]["may_report_total"] is False,
               "62 of 100 systems inspected, so no estate-wide total is asserted"),
        _probe("an-empty-document-says-why-it-is-empty",
               empty_properties.get(cr.PROPERTY_EMPTY) == "true"
               and empty_properties.get(cr.PROPERTY_EMPTY_REASONS),
               empty["empty"]["statement"]),
        _probe("the-document-records-what-it-left-out",
               properties.get("cryptoscan:promoted_assets") == "1"
               and properties.get("cryptoscan:candidates_excluded") == "2",
               f"{properties.get('cryptoscan:promoted_assets')} promoted, "
               f"{properties.get('cryptoscan:candidates_excluded')} excluded"),
    ]
    return {"id": "the_document",
            "question": "can the document be read without asking what it left out?",
            "phase": "review 12 / 20", "probes": probes}


def row_conflicts(modules: dict[str, Any]) -> dict[str, Any]:
    ec = modules["ec"]
    result = ec.run(_estate())
    reconciled = result["conflicts"]["reconciled"]
    edges = result["conflicts"]["edges"]
    agreement = ec.run(_estate(conflicts=[
        {"field": "cipher_suite", "fact": "TLS_AES_256_GCM_SHA384", "source": "network",
         "evidence_id": "NET-1"},
        {"field": "cipher_suite", "fact": "TLS_AES_256_GCM_SHA384", "source": "runtime",
         "evidence_id": "RUNTIME-2"}]))
    probes = [
        _probe("two-observing-layers-that-disagree-are-a-conflict",
               [conflict["field"] for conflict in reconciled["conflicts"]]
               == ["cipher_suite"],
               reconciled["conflicts"][0]["statement"]),
        _probe("a-declaration-against-an-observation-is-a-mismatch-not-a-conflict",
               all(conflict["field"] != "version" for conflict in reconciled["conflicts"])
               and "VERSION_MISMATCH" in {row["state"]
                                          for row in result["runtime"]["correlation"]},
               "the SBOM does not observe; the process tracer owns that comparison"),
        _probe("the-conflict-survives-to-the-graph-as-an-edge",
               len(edges) == len(reconciled["conflicts"]) and bool(edges)
               and all(edge.get("evidence_ids") for edge in edges)
               and "CONFLICTS_WITH" in {edge["kind"]
                                        for edge in result["graph"]["edges"]},
               f"{len(edges)} conflict edge(s), each carrying its evidence ids"),
        _probe("no-single-value-is-asserted-where-the-sources-disagree",
               all(row["value"] is None for row in reconciled["resolved"]
                   if row["field"] == "cipher_suite"),
               "the disagreement is the finding; a human decides"),
        _probe("every-claim-survives-as-a-row",
               len(reconciled["rows"]) == len(ESTATE["conflicts"])
               and reconciled["refused"] == [],
               f"{len(reconciled['rows'])} claim row(s) kept"),
        _probe("agreement-is-not-a-conflict",
               agreement["conflicts"]["reconciled"]["conflicts"] == []
               and agreement["conflicts"]["edges"] == [],
               "two layers agreeing on the same value is a corroboration"),
        _probe("the-graph-hangs-off-the-estate-it-describes",
               any(edge["kind"] == "USES_CRYPTO" for edge in result["graph"]["edges"]),
               f"{len(result['graph']['edges'])} edge(s) on system:{result['estate']}"),
    ]
    return {"id": "conflicts",
            "question": "does a disagreement reach the twin, or get resolved quietly?",
            "phase": "review 8", "probes": probes}


def row_the_seven(modules: dict[str, Any]) -> dict[str, Any]:
    ec = modules["ec"]
    result = ec.run(_estate())
    summary = ec.summary(result)
    broken = dict(result)
    broken["checks"] = [dict(result["checks"][0], ok=False)]
    leaked = ec.disabled_key_check(
        [{"class": "RUNTIME_OBSERVED", "key_ref": DISABLED["key_ref"],
          "evidence_id": "KMS-USE-2"}],
        [{"key_ref": DISABLED["key_ref"], "usable": False, "status": "DISABLED"}])
    router = (SERVICES / "api" / "api" / "routers" / "cbom_usage.py").read_text(encoding="utf-8")
    probes = [
        _probe("all-seven-cross-layer-checks-hold-on-a-mixed-estate",
               summary["checks_passed"] == summary["checks_total"] == len(ec.CHECKS),
               summary["statement"]),
        _probe("the-checks-are-a-named-contract-not-a-count",
               tuple(check["check"] for check in result["checks"]) == ec.CHECKS,
               ", ".join(ec.CHECKS)),
        _probe("a-failing-check-makes-the-pipeline-broken-not-warning",
               ec.summary(broken)["status"] == "BROKEN"
               and ec.summary(broken)["failed_checks"],
               "the response carries the failure; it is not smoothed into the document"),
        _probe("the-disabled-key-check-has-teeth",
               leaked["ok"] is False,
               "a leaked RUNTIME_OBSERVED event on a DISABLED key fails the check"),
        _probe("the-route-exists-typed-and-role-gated",
               '@router.post("/estate-chain"' in router
               and "response_model=CbomEstateChainResponse" in router
               and "require_roles(*CBOM_USAGE_READERS)" in
               router.split("def cbom_estate_chain", 1)[1],
               "POST /cbom/estate-chain"),
    ]
    return {"id": "the_seven",
            "question": "are the invariants checked, or only documented?",
            "phase": "review 7 / 8 / 11 / 12 / 20", "probes": probes}


ROWS = (row_runtime, row_keys, row_promotion, row_the_document, row_conflicts, row_the_seven)


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
    estate = modules["ec"].run(_estate())
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "estate": estate["estate"],
        "summary": modules["ec"].summary(estate),
        "evidence_counts": estate["evidence"]["counts"],
        "graph_edges": len(estate["graph"]["edges"]),
        "document_properties": _properties(estate["document"]),
        "rows": rows,
        "limits": [
            "the chain composes the modules; it does not add a collector. An estate that "
            "omits a layer produces a document that is honest about that layer and silent "
            "about what it never looked at",
            "a passing check means the layers agree with each other, not that the estate is "
            "correctly described. Seven invariants cannot detect a collector that is "
            "consistently wrong",
            "conflicts are only visible when the caller supplies conflicting claims. The "
            "chain does not invent a second source to test the first, and an estate with "
            "one source can never produce a conflict",
            "coverage is read from the estate's rollup. If the caller passes a rollup that "
            "overstates inspection, the document repeats the overstatement with the same "
            "confidence",
            "emptiness is explained from the file counts and the coverage block. An empty "
            "document from a fully covered estate is a real finding; an empty document from "
            "an uncovered one is not evidence of absence, and the reasons say which",
            "the graph is a projection for one run. Persisting it as a twin snapshot and "
            "diffing runs for drift is the estate twin's job, not this guide's",
            "the invariants are structural. They cannot tell whether the seven checks are "
            "the seven a regulator wants; that is a scoping decision made in the review, "
            "not a property of the code",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    summary = report["summary"]
    lines = [
        "# The whole chain over one estate: seven seams, seven checks",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        f"Estate `{report['estate']}` · {summary['documented_assets']} documented asset(s) · "
        f"{summary['candidates_excluded']} candidate(s) excluded · "
        f"{report['graph_edges']} graph edge(s) · coverage "
        f"{summary['coverage_completeness']}",
        "",
        "Each guide before this one proved a layer. This one runs them together, because "
        "the failures a reviewer finds are at the joins:",
        "",
        "```",
        "SBOM ─┐",
        "static ├─→ evidence classes ─→ usage profile ─→ promotion ─→ CBOM document",
        "config │                                              │",
        "runtime┤                                              ├─→ PQC handoff",
        "network┘                                              └─→ twin edges",
        "KMS ──→ key records ─→ configured vs used",
        "coverage ──→ what the document may say about totals",
        "```",
        "",
        "`cbom.estate_chain.run` produces the document once from one evidence set and then "
        "checks the invariants that must hold regardless of the input:",
        "",
        "| # | invariant | what it prevents |",
        "|---|---|---|",
        "| 1 | `no_capability_is_documented_as_usage` | an SBOM's *supports* becoming a "
        "CBOM's *uses* |",
        "| 2 | `every_documented_asset_is_attributable` | an asset nobody can trace to a "
        "source |",
        "| 3 | `promotion_level_matches_the_evidence` | a level that outruns its classes |",
        "| 4 | `conflicts_survive_to_the_graph` | a disagreement resolved by precedence "
        "into silence |",
        "| 5 | `a_disabled_key_never_produces_runtime_evidence` | a decrypt against a "
        "disabled key reading as usage |",
        "| 6 | `coverage_travels_with_the_document` | a total quoted from a partial scan |",
        "| 7 | `emptiness_is_explained` | an empty document read as \"no cryptography\" |",
        "",
        "A failing check is not a warning to be adjusted away: it comes back in `checks`, "
        "and `summary.status` says `BROKEN`.",
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
    lines += ["", "## The document that comes out", "",
              "Metadata properties, verbatim:", "", "```json",
              json.dumps(report["document_properties"], indent=2), "```", "",
              f"Evidence classes: `{json.dumps(report['evidence_counts'], sort_keys=True)}`",
              "", "## What this does not prove", ""]
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
