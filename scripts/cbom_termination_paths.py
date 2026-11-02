#!/usr/bin/env python3
"""Guide 149 — TLS termination paths: three relationships, never one attribute.

Review item 9 draws the picture and the consequence:

    Client ──TLS1.3 AES-256-GCM──▶ External LB
    External LB ──TLS1.2 AES-128-GCM──▶ API Gateway
    API Gateway ──TLS1.3 AES-256-GCM──▶ Payments API

Three cryptographic relationships. Not one:

    Payments API = AES-256

The middle hop is weaker than both ends, and it is the only hop a reviewer needs
to see. Equally, reporting the path as one inventory of "AES-256-GCM,
AES-128-GCM" hides *where* the weak suite lives.

``cbom.termination_paths`` chains the hops, keeps one relationship per hop, names
the change between adjacent hops, refuses the merged claim explicitly, and treats
a hop that connects to nothing as a gap rather than as a path.
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
SCHEMA = "cryptoscan.cbom-termination-paths-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

CLIENT_LB = {"from": "Client", "to": "External LB", "observed_on": "External LB",
             "endpoint": "payments.bank.example:443", "tls_version": "1.3",
             "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-9281"}
LB_GATEWAY = {"from": "External LB", "to": "API Gateway", "observed_on": "External LB",
              "endpoint": "gateway.bank.example:443", "tls_version": "1.2",
              "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "evidence_id": "NET-9282"}
GATEWAY_APP = {"from": "API Gateway", "to": "Payments API", "observed_on": "API Gateway",
               "endpoint": "payments-api.internal:8443", "tls_version": "1.3",
               "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-9283"}
PATH = [CLIENT_LB, LB_GATEWAY, GATEWAY_APP]


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import estate_chain, termination_paths  # noqa: PLC0415

    return {"tp": termination_paths, "ec": estate_chain}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


# --------------------------------------------------------------------------- #


def row_three_relationships(modules: dict[str, Any]) -> dict[str, Any]:
    tp = modules["tp"]
    result = tp.build(PATH)
    path = result["paths"][0]
    probes = [
        _probe("the-path-is-chained-not-collected",
               path["nodes"] == ["Client", "External LB", "API Gateway", "Payments API"],
               " → ".join(path["nodes"])),
        _probe("three-hops-are-three-relationships",
               len(result["relationships"]) == 3, result["statement"]),
        _probe("each-hop-keeps-its-own-tls-version",
               [row["tls_version"] for row in result["relationships"]]
               == ["1.3", "1.2", "1.3"],
               ", ".join(str(row["tls_version"]) for row in result["relationships"])),
        _probe("each-hop-keeps-its-own-suite",
               result["relationships"][1]["cipher_suite"]
               == "ECDHE-RSA-AES128-GCM-SHA256",
               result["relationships"][1]["cipher_suite"]),
        _probe("the-middle-hop-owns-aes-128-and-nobody-else-does",
               "AES-128-GCM" in result["relationships"][1]["algorithms"]
               and "AES-128-GCM" not in result["relationships"][0]["algorithms"]
               and "AES-128-GCM" not in result["relationships"][2]["algorithms"],
               "the bulk cipher belongs to the hop that negotiated it"),
        _probe("every-relationship-carries-its-own-evidence",
               [row["evidence_ids"] for row in result["relationships"]]
               == [["NET-9281"], ["NET-9282"], ["NET-9283"]],
               ", ".join(row["evidence_ids"][0] for row in result["relationships"])),
        _probe("a-relationship-statement-names-its-hop",
               result["relationships"][1]["statement"].startswith(
                   "External LB → API Gateway")
               and "TLS 1.2" in result["relationships"][1]["statement"],
               result["relationships"][1]["statement"]),
    ]
    return {"id": "three_relationships",
            "question": "is one path three facts, or one attribute?",
            "phase": "review 9", "probes": probes}


def row_the_change(modules: dict[str, Any]) -> dict[str, Any]:
    tp = modules["tp"]
    result = tp.build(PATH)
    spellings = []
    for spelling in ("TLSv1.2", "TLS1.2", "1.2", "tlsv1.2"):
        hop = {**LB_GATEWAY, "tls_version": spelling,
               "cipher_suite": "TLS_AES_256_GCM_SHA384"}
        other = {**GATEWAY_APP, "to": "X"}
        spellings.append([change["kind"] for change
                          in tp.build([hop, other])["changes"]])
    opaque = tp.build([{**CLIENT_LB, "tls_version": "SSLV3"}, LB_GATEWAY])
    probes = [
        _probe("the-downgrade-in-the-middle-is-named",
               len(result["downgrades"]) == 1
               and result["downgrades"][0]["detail"] == "TLS 1.2 after TLS 1.3",
               result["downgrades"][0]["detail"]),
        _probe("the-upgrade-after-the-downgrade-is-named-too",
               "TLS_VERSION_UPGRADE" in [change["kind"] for change in result["changes"]],
               "a path can weaken and recover in the same breath"),
        _probe("the-bulk-cipher-change-is-what-is-reported",
               "BULK_CIPHER_CHANGED" in [change["kind"] for change in result["changes"]]
               and "['AES-128-GCM'] after ['AES-256-GCM']"
               in [change["detail"] for change in result["changes"]
                   if change["kind"] == "BULK_CIPHER_CHANGED"],
               "comparing whole suites would report a change on every hop"),
        _probe("a-same-version-hop-with-a-new-suite-is-a-suite-change",
               [change["kind"] for change in tp.build([
                   CLIENT_LB,
                   {**CLIENT_LB, "from": "External LB", "to": "API Gateway",
                    "cipher_suite": "ECDHE-ECDSA-AES256-GCM-SHA384",
                    "evidence_id": "NET-9"}])["changes"]] == ["SUITE_CHANGED"],
               "TLS 1.3 → TLS 1.3 with a different suite is still a change"),
        _probe("every-version-spelling-ranks-the-same",
               all("TLS_VERSION_UPGRADE" in kinds for kinds in spellings),
               json.dumps(spellings)),
        _probe("an-unparseable-version-does-not-invent-a-downgrade",
               opaque["downgrades"] == [],
               "SSLV3 is not ranked below TLS 1.3; it is not ranked at all"),
        _probe("the-summary-names-the-weakest-hop",
               tp.summary(result)["weakest_hops"] == ["path 1 hop 2: TLS 1.2 after TLS 1.3"],
               "; ".join(tp.summary(result)["weakest_hops"])),
    ]
    return {"id": "the_change",
            "question": "does the path show where it weakens?",
            "phase": "review 9", "probes": probes}


def row_the_merge(modules: dict[str, Any]) -> dict[str, Any]:
    tp = modules["tp"]
    result = tp.build(PATH)
    merged = result["merged"]
    single = tp.build(PATH[1:2])["merged"]
    empty = tp.build([])["merged"]
    probes = [
        _probe("the-union-is-computed-so-it-can-be-seen",
               merged["algorithms"] == ["AES-256-GCM", "SHA-384", "AES-128-GCM",
                                        "SHA-256", "ECDHE", "RSA"],
               ", ".join(merged["algorithms"])),
        _probe("the-merged-claim-is-refused",
               merged["refused"] is True and merged["hops_differ"] is True,
               merged["statement"]),
        _probe("the-refusal-says-why-it-describes-nothing",
               "no hop negotiates that set" in merged["statement"],
               "a union of three hops is a description of no hop"),
        _probe("a-single-hop-cannot-differ-from-itself",
               single["hops_differ"] is False and single["refused"] is True,
               single["statement"]),
        _probe("there-is-nothing-to-collapse-without-a-path",
               empty["refused"] is False
               and empty["statement"] == "there is no path to collapse",
               empty["statement"]),
    ]
    return {"id": "the_merge",
            "question": "is the naive collapse visible and refused?",
            "phase": "review 9 / 17", "probes": probes}


def row_gaps(modules: dict[str, Any]) -> dict[str, Any]:
    tp = modules["tp"]
    orphan = {**GATEWAY_APP, "from": "Somewhere"}
    broken = tp.build([CLIENT_LB, orphan])
    missing_suite = tp.build([{key: value for key, value in CLIENT_LB.items()
                               if key != "cipher_suite"}])
    no_evidence = tp.build([{**CLIENT_LB, "evidence_id": None}])
    no_start = tp.build([{key: value for key, value in CLIENT_LB.items()
                          if key != "from"}])
    tunnelled = tp.build([{**CLIENT_LB, "terminates": False}])
    probes = [
        _probe("a-hop-with-no-connector-is-a-gap-not-a-path",
               len(broken["paths"]) == 2 and len(broken["gaps"]) == 2,
               f"{len(broken['paths'])} path(s), {len(broken['gaps'])} gap(s)"),
        _probe("the-gap-says-the-chain-was-not-invented",
               "not invented" in broken["gaps"][0]["reason"],
               broken["gaps"][0]["reason"]),
        _probe("a-hop-with-no-suite-is-refused",
               missing_suite["relationships"] == []
               and "negotiated suite" in missing_suite["refused"][0]["reason"],
               missing_suite["refused"][0]["reason"]),
        _probe("a-hop-with-no-evidence-is-refused",
               "evidence id" in no_evidence["refused"][0]["reason"],
               no_evidence["refused"][0]["reason"]),
        _probe("a-hop-with-no-start-node-is-refused",
               "starts from" in no_start["refused"][0]["reason"],
               no_start["refused"][0]["reason"]),
        _probe("a-tunnelling-hop-passes-through-and-terminates-nothing",
               tunnelled["relationships"][0]["mode"] == "PASSES_THROUGH"
               and tunnelled["relationships"][0]["terminated_at"] is None,
               "a middlebox that tunnels TLS owns no suite on that hop"),
    ]
    return {"id": "gaps",
            "question": "what is refused rather than bridged?",
            "phase": "review 9 / 12", "probes": probes}


def row_the_document(modules: dict[str, Any]) -> dict[str, Any]:
    tp, ec = modules["tp"], modules["ec"]
    result = tp.build(PATH)
    components = tp.to_components(result)
    edges = tp.to_edges(result)
    gateway_component = [row for row in components["components"]
                         if row["bom-ref"] == "path:1#hop:2#AES-128-GCM"][0]
    properties = {row["name"]: row["value"] for row in gateway_component["properties"]}
    probes = [
        _probe("one-component-per-path-hop-and-algorithm",
               len(components["components"]) == 8
               and len({row["bom-ref"] for row in components["components"]}) == 8,
               components["statement"]),
        _probe("the-component-names-its-hop-version-and-evidence",
               properties["cryptoscan:from"] == "External LB"
               and properties["cryptoscan:to"] == "API Gateway"
               and properties["cryptoscan:tls_version"] == "1.2"
               and properties["cryptoscan:evidence_id"] == "NET-9282",
               json.dumps({key: properties[key] for key in (
                   "cryptoscan:from", "cryptoscan:to", "cryptoscan:tls_version",
                   "cryptoscan:evidence_id")}, sort_keys=True)),
        _probe("no-component-names-an-application",
               all("cryptoscan:application" not in {row["name"] for row in component[
                   "properties"]} for component in components["components"]),
               "the path names hops, not the application behind them"),
        _probe("every-algorithm-edge-belongs-to-a-hop",
               {edge["from"] for edge in edges["edges"]
                if edge["kind"] == "NEGOTIATES"} == {
                    "hop:Client→External LB", "hop:External LB→API Gateway",
                    "hop:API Gateway→Payments API"},
               "no algorithm edge starts at an application, a system or a host"),
        _probe("the-hops-are-ordered-by-precedes-edges",
               [(edge["from"], edge["to"]) for edge in edges["edges"]
                if edge["kind"] == "PRECEDES"] == [
                    ("hop:Client→External LB", "hop:External LB→API Gateway"),
                    ("hop:External LB→API Gateway", "hop:API Gateway→Payments API")],
               "the order is data, not an assumption about the list"),
        _probe("every-edge-is-network-observed-with-evidence",
               all(edge["provenance"] == "OBSERVED"
                   and edge["classes"] == ["NETWORK_OBSERVED"]
                   and edge["evidence_ids"] for edge in edges["edges"]),
               "a hop with no evidence never becomes an edge"),
        _probe("the-estate-chain-builds-the-path-from-the-same-hops",
               ec.run({"name": "p", "probes": [
                   {**CLIENT_LB, "status": "OK",
                    "crypto": {"cipher_suite": CLIENT_LB["cipher_suite"],
                               "tls_version": "1.3"}},
                   {**LB_GATEWAY, "status": "OK",
                    "crypto": {"cipher_suite": LB_GATEWAY["cipher_suite"],
                               "tls_version": "1.2"}},
               ]})["network"]["path_summary"]["downgrades"] == 1,
               "the chain and the standalone path agree on the same hops"),
    ]
    return {"id": "the_document",
            "question": "can a reviewer see the weak hop in the output?",
            "phase": "review 9 / 12", "probes": probes}


ROWS = (row_three_relationships, row_the_change, row_the_merge, row_gaps,
        row_the_document)


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
    tp = modules["tp"]
    sample = tp.build(PATH)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "path": {"nodes": sample["paths"][0]["nodes"],
                 "relationships": [
                     {"from": row["from"], "to": row["to"],
                      "tls_version": row["tls_version"],
                      "cipher_suite": row["cipher_suite"],
                      "algorithms": row["algorithms"],
                      "evidence_ids": row["evidence_ids"]}
                     for row in sample["relationships"]],
                 "summary": tp.summary(sample)},
        "rows": rows,
        "limits": [
            "the path is built from the hops the collector reported, in the order it "
            "reported them. A missing hop is a gap, not a guess — but a collector that "
            "silently skips a proxy produces a complete-looking path with the wrong "
            "topology",
            "a hop is attributed to the node that observed it, not to the node that "
            "terminated it. Without a probe from the far side, 'External LB → API "
            "Gateway' is the LB's view of that connection",
            "the version comparison ranks TLS 1.0 to 1.3. A suite downgrade within one "
            "version is reported as a bulk-cipher change, which is the fact, but it does "
            "not say whether the change was allowed by policy — that comparison is a "
            "separate, reviewable decision",
            "PASSES_THROUGH depends on the collector saying so. A middlebox that "
            "terminates and re-originates without declaring it looks like a terminator, "
            "and its algorithms are then attributed one hop too far",
            "the merged claim is refused, not repaired. A downstream tool that unions the "
            "components it receives can still produce the claim this module refuses",
            "nothing here covers mTLS identity, pinned certificates or session "
            "resumption: those are properties of the relationship this module does not "
            "model",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    path = report["path"]
    lines = [
        "# TLS termination paths: three relationships, never one attribute",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review item 9, drawn exactly as the review draws it:",
        "",
        "```",
        "Client ──TLS1.3 AES-256-GCM──▶ External LB",
        "External LB ──TLS1.2 AES-128-GCM──▶ API Gateway",
        "API Gateway ──TLS1.3 AES-256-GCM──▶ Payments API",
        "```",
        "",
        "Three cryptographic relationships. Not one *Payments API = AES-256*. The "
        "middle hop is weaker than both ends, and it is the hop a reviewer needs to see.",
        "",
        "`cbom.termination_paths` keeps them apart:",
        "",
        "| hop | relationship | TLS | bulk | evidence |",
        "|---|---|---|---|---|",
    ]
    for index, row in enumerate(path["relationships"], start=1):
        bulk = [algorithm for algorithm in row["algorithms"]
                if algorithm.startswith(("AES", "CHACHA", "3DES"))]
        lines.append(f"| {index} | {row['from']} → {row['to']} | {row['tls_version']} | "
                     f"{', '.join(bulk) or '—'} | {', '.join(row['evidence_ids'])} |")
    lines += [
        "",
        "1. **hops are chained, not collected** — a hop that connects to nothing is a gap, "
        "reported rather than bridged by invention;",
        "2. **one relationship per hop**, with its own version, suite, algorithms and "
        "evidence;",
        "3. **the change between adjacent hops is the finding** — a version downgrade, a "
        "bulk-cipher change, or a suite change at the same version. Versions are compared "
        "by their bulk cipher, because a TLS 1.3 suite names two algorithms and a TLS 1.2 "
        "suite four;",
        "4. **the merged claim is refused explicitly** — the union is computed so the "
        "claim can be seen, then rejected with the reason that no hop negotiates that set;",
        "5. **pass-through hops are named** — a tunnelling middlebox is `PASSES_THROUGH` "
        "and its algorithms belong to the endpoints.",
        "",
        f"`{path['summary']['statement']}` — weakest hop: "
        f"`{'; '.join(path['summary']['weakest_hops']) or 'none'}`.",
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
