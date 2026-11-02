#!/usr/bin/env python3
"""Guide 146 — process-level runtime tracing, the review's biggest gap.

Item 7 asks for the chain and nothing shorter::

    payments-api -> PID 9182 -> OpenSSL 3.0.13 -> EVP_EncryptInit_ex
                 -> AES-256-GCM -> key_size=256, mode=GCM -> 2026-11-02 10:42:11
                 -> RUNTIME-92821

``cbom.process_tracing`` keeps every link, refuses a row that is missing one, and
turns a complete chain into a **runtime-confirmed** CBOM asset. It also answers the
question an SBOM cannot: which provider version the process actually loaded, and
whether that matches what the document declares.
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
SCHEMA = "cryptoscan.cbom-process-tracing-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

OP = {"application": "payments-api", "pid": 9182, "provider": "OpenSSL",
      "provider_version": "3.0.13", "operation": "EVP_EncryptInit_ex",
      "algorithm": "AES-256-GCM", "key_size": 256, "mode": "GCM",
      "observed_at": "2026-11-02T10:42:11Z", "evidence_id": "RUNTIME-92821"}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(SERVICES / "devsecops"),
                  str(SERVICES / "governance"), str(SERVICES / "quantum"),
                  str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import process_tracing  # noqa: PLC0415

    return {"pt": process_tracing}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _trace(pt, *operations, **overrides):
    return pt.trace(list(operations) or [{**OP, **overrides}])


def row_the_chain(modules: dict[str, Any]) -> dict[str, Any]:
    pt = modules["pt"]
    body = _trace(pt)
    item = body["traces"][0]
    probes = [
        _probe("the-review-chain-is-kept-whole",
               item["chain"] == {
                   "application": "application:payments-api",
                   "process": "process:payments-api/9182",
                   "provider": "provider:OpenSSL@3.0.13",
                   "operation": "operation:EVP_EncryptInit_ex",
                   "algorithm": "algorithm:AES-256-GCM"},
               " → ".join(item["chain"].values())),
        _probe("the-parameters-survive-the-chain",
               item["parameters"] == {"key_size": 256, "mode": "GCM"},
               json.dumps(item["parameters"], sort_keys=True)),
        _probe("a-trace-without-a-process-is-refused",
               _trace(pt, pid=None)["traces"] == []
               and "pid" in _trace(pt, pid=None)["refused"][0]["reason"],
               _trace(pt, pid=None)["refused"][0]["reason"]),
        _probe("an-unparseable-timestamp-is-refused-not-replaced",
               "unparseable" in _trace(pt, observed_at="sometime tuesday")["refused"][0]["reason"],
               "a timestamp that cannot be parsed is not a timestamp"),
        _probe("the-summary-counts-processes-not-operations",
               len(_trace(pt, OP, {**OP, "evidence_id": "R-2"},
                          {**OP, "pid": 9183, "evidence_id": "R-3"})["processes"]) == 2,
               "two PIDs, three operations"),
    ]
    return {"id": "the_chain",
            "question": "is a runtime trace the whole chain, or a claim about one?",
            "phase": "review 7", "probes": probes}


def row_the_provider(modules: dict[str, Any]) -> dict[str, Any]:
    pt = modules["pt"]
    versioned = pt.provider_observations(_trace(pt)["traces"])
    unversioned = pt.provider_observations(
        _trace(pt, provider_version=None)["traces"])
    probes = [
        _probe("a-provider-is-what-it-was-seen-doing",
               versioned["providers"][0]["algorithms"] == ["AES-256-GCM"]
               and versioned["providers"][0]["operations"] == {"EVP_EncryptInit_ex": 1},
               versioned["providers"][0]["statement"]),
        _probe("operations-are-counted-per-provider",
               pt.provider_observations(
                   _trace(pt, OP, {**OP, "evidence_id": "R-2",
                                   "operation": "EVP_DecryptFinal_ex"})["traces"]
               )["providers"][0]["operations"] == {"EVP_DecryptFinal_ex": 1,
                                                   "EVP_EncryptInit_ex": 1},
               "a provider that encrypts and decrypts is one provider with two operations"),
        _probe("an-unversioned-provider-says-it-cannot-be-compared",
               unversioned["unknown_version"] == ["provider:OpenSSL"]
               and "cannot be compared with an SBOM"
               in unversioned["providers"][0]["statement"],
               unversioned["providers"][0]["statement"]),
        _probe("the-provider-version-is-not-invented",
               _trace(pt, provider_version=None)["traces"][0]["provider_version"] is None,
               "provider_version stays null when the collector did not report it"),
    ]
    return {"id": "the_provider",
            "question": "does the tracer separate 'OpenSSL' from 'OpenSSL 3.0.13'?",
            "phase": "review 7", "probes": probes}


def row_correlation(modules: dict[str, Any]) -> dict[str, Any]:
    pt = modules["pt"]
    declared = [{"name": "openssl", "version": "3.0.11", "evidence_id": "SBOM-1"}]
    mismatch = pt.correlate(pt.provider_observations(_trace(pt)["traces"]), declared)
    match = pt.correlate(pt.provider_observations(_trace(pt)["traces"]),
                         [{"name": "openssl", "version": "3.0.13"}])
    split = pt.correlate(pt.provider_observations(_trace(pt, provider="BoringSSL")["traces"]),
                         [{"name": "openssl", "version": "3.0.13"}])
    unknown = pt.correlate(
        pt.provider_observations(_trace(pt, provider_version=None)["traces"]), declared)
    probes = [
        _probe("the-review-version-mismatch-is-reported-not-resolved",
               mismatch["correlations"][0]["state"] == "VERSION_MISMATCH"
               and mismatch["correlations"][0]["runtime_version"] == "3.0.13"
               and mismatch["correlations"][0]["declared_versions"] == ["3.0.11"],
               mismatch["statement"]),
        _probe("both-sides-keep-their-evidence",
               set(mismatch["correlations"][0]["evidence_ids"])
               == {"SBOM-1", "RUNTIME-92821"},
               ", ".join(mismatch["correlations"][0]["evidence_ids"])),
        _probe("an-agreeing-provider-is-a-match",
               match["correlations"][0]["state"] == "MATCH",
               match["correlations"][0]["detail"]),
        _probe("runtime-only-and-sbom-only-are-both-named",
               {row["state"] for row in split["correlations"]}
               == {"SBOM_ONLY", "RUNTIME_ONLY"},
               split["statement"]),
        _probe("an-unversioned-runtime-provider-cannot-match",
               unknown["correlations"][0]["state"] == "RUNTIME_VERSION_UNKNOWN",
               unknown["correlations"][0]["detail"]),
    ]
    return {"id": "correlation",
            "question": "does the twin say which provider version the process loaded?",
            "phase": "review 7 / 8", "probes": probes}


def row_the_asset(modules: dict[str, Any]) -> dict[str, Any]:
    pt = modules["pt"]
    repeated = pt.to_components(_trace(pt, OP, {**OP, "evidence_id": "R-2"})["traces"])
    two_processes = pt.to_components(
        _trace(pt, OP, {**OP, "pid": 9183, "evidence_id": "R-2"})["traces"])
    bare = pt.to_components(
        _trace(pt, key_size=None, mode=None)["traces"])["components"][0]
    probes = [
        _probe("repeated-operations-are-one-asset-with-a-count",
               len(repeated["components"]) == 1
               and {row["name"]: row["value"]
                    for row in repeated["components"][0]["properties"]}
               ["cryptoscan:occurrences"] == "2",
               repeated["statement"]),
        _probe("a-different-process-is-a-different-asset",
               len(two_processes["components"]) == 2,
               "the process is part of the asset identity"),
        _probe("the-asset-is-runtime-confirmed-with-the-chain-attached",
               {row["name"]: row["value"]
                for row in repeated["components"][0]["properties"]}.get(
                    "cryptoscan:runtime_confirmed") == "true"
               and repeated["components"][0]["cryptoProperties"]["algorithmProperties"]
               ["parameterSetIdentifier"] == "256",
               repeated["components"][0]["bom-ref"]),
        _probe("an-asset-with-no-parameters-claims-no-parameter-set",
               "algorithmProperties" not in bare["cryptoProperties"],
               "an empty parameter object would read as 'known to be empty'"),
        _probe("the-asset-writes-no-quantum-verdict",
               not any(row["name"].startswith("cryptoscan:quantum")
                       for row in repeated["components"][0]["properties"]),
               "the PQC handoff owns that decision, not the collector"),
    ]
    return {"id": "the_asset",
            "question": "does a runtime observation become a runtime-confirmed asset?",
            "phase": "review 7", "probes": probes}


def row_the_twin(modules: dict[str, Any]) -> dict[str, Any]:
    pt = modules["pt"]
    body = pt.graph(_trace(pt, OP, {**OP, "evidence_id": "R-2"})["traces"])
    kinds = {(edge["from"], edge["kind"], edge["to"]) for edge in body["edges"]}
    router = (SERVICES / "api" / "api" / "routers" / "cbom_usage.py").read_text(encoding="utf-8")
    probes = [
        _probe("the-graph-walks-the-whole-chain",
               {
                   ("application:payments-api", "RUNS_PROCESS", "process:payments-api/9182"),
                   ("process:payments-api/9182", "LOADS_PROVIDER", "provider:OpenSSL@3.0.13"),
                   ("provider:OpenSSL@3.0.13", "PERFORMS_OPERATION",
                    "operation:EVP_EncryptInit_ex"),
                   ("operation:EVP_EncryptInit_ex", "RESOLVES_TO",
                    "algorithm:AES-256-GCM"),
               } <= kinds,
               body["statement"]),
        _probe("the-shortcut-exists-for-the-obvious-question",
               ("application:payments-api", "USES_CRYPTO", "algorithm:AES-256-GCM") in kinds,
               "which applications encrypt with AES-256-GCM, without walking four edges"),
        _probe("every-edge-is-observed-and-carries-evidence",
               all(edge["provenance"] == "OBSERVED" for edge in body["edges"])
               and all(edge["evidence_ids"] for edge in body["edges"]),
               "repeat observations merge their evidence ids"),
        _probe("nodes-are-typed-by-their-prefix",
               {node["id"]: node["kind"] for node in body["nodes"]}
               ["operation:EVP_EncryptInit_ex"] == "OPERATION",
               "the twin can filter by kind"),
        _probe("the-route-exists-typed-and-role-gated",
               '@router.post("/runtime-traces"' in router
               and "response_model=CbomRuntimeTraceResponse" in router
               and "require_roles(*CBOM_USAGE_READERS)" in
               router.split("def cbom_runtime_traces", 1)[1],
               "POST /cbom/runtime-traces"),
    ]
    return {"id": "the_twin",
            "question": "does the chain reach the digital twin as evidenced relationships?",
            "phase": "review 7 / 20", "probes": probes}


ROWS = (row_the_chain, row_the_provider, row_correlation, row_the_asset, row_the_twin)


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
            "the platform reads traces; it does not install the tracer. A process that never "
            "called a hooked operation produces no trace, which is indistinguishable from a "
            "process that did not run crypto — only coverage of the tracing tells them apart",
            "pid identifies a process instance, not an application version. Two deployments of "
            "payments-api look alike unless the collector also reports a build id or image "
            "digest, which this module does not require",
            "a provider version is only as good as the collector's lookup: a statically linked "
            "library or a vendored copy may report the wrong version, and the correlation would "
            "then be confidently wrong",
            "correlation matches on library name. 'OpenSSL' vs 'openssl' is normalised, but "
            "'BoringSSL' and 'OpenSSL' are different providers and a fork that renames itself "
            "will read as RUNTIME_ONLY",
            "component identity is (application, process, provider, operation, algorithm, "
            "parameters). An operation repeated across two hosts is one asset with a count, so "
            "per-host provenance needs the host property, not the component",
            "runtime traces prove an operation happened; they do not prove which key, which "
            "purpose or which data. Key-level runtime evidence is the KMS collector's job",
            "the graph is a projection for one submission, not a stored twin. Persisting it, "
            "and diffing successive runtime states for drift, is not in this increment",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Process-level runtime tracing: the chain is the evidence",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail** · "
        f"{report['probes']} probes",
        "",
        "The review's item 7, and the chain it asks for is the whole point:",
        "",
        "```",
        "payments-api -> PID 9182 -> OpenSSL 3.0.13 -> EVP_EncryptInit_ex",
        "             -> AES-256-GCM (key_size=256, mode=GCM)",
        "             -> 2026-11-02 10:42:11 -> RUNTIME-92821",
        "```",
        "",
        "`cbom.process_tracing` keeps every link:",
        "",
        "1. **A partial chain is a claim.** Missing application, pid, operation, algorithm, "
        "evidence id or timestamp → refused, with the missing link named.",
        "2. **The provider version is data, not decoration.** `OpenSSL` without a version is "
        "kept and marked uncomparable, because \"which version\" is the whole question.",
        "3. **Correlation reports, never resolves.** SBOM 3.0.11 against runtime 3.0.13 is a "
        "`VERSION_MISMATCH` with both evidence ids; `RUNTIME_ONLY` and `SBOM_ONLY` are named "
        "separately.",
        "4. **The asset is runtime-confirmed** and carries the chain in `cryptoscan:` "
        "properties — and writes no quantum verdict, because that belongs to the PQC handoff.",
        "5. **The twin gets the chain as edges**, each `RUNTIME_OBSERVED` with its evidence id, "
        "plus the direct application → algorithm shortcut.",
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
