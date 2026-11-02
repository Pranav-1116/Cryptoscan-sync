#!/usr/bin/env python3
"""Guide 152 — CBOM → digital twin: one graph, three consumers, no claim upgrades.

Review item 20 draws the architecture this guide implements:

    EVIDENCE (SBOM · STATIC · NETWORK · RUNTIME · HSM/KMS)
                        │
                   CRYPTO GRAPH → CBOM → DIGITAL TWIN
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
      DRIFT           PQC            THREAT
    ANALYSIS       MIGRATION      INTELLIGENCE

The twin is a projection of the same evidence set the CBOM is built from, so the
two cannot disagree. What it adds is the questions an inventory cannot answer: what
changed against policy, what must migrate, and which advisory actually touches code
that is running.

Every probe here checks the same discipline from a different angle: **a downstream
answer may never claim more than the node it read.** A library that supports
AES-128-CBC is not using it; a library that is installed is not necessarily loaded;
a policy row nobody observed is not evidence of absence.
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
SCHEMA = "cryptoscan.cbom-digital-twin-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

ESTATE: dict[str, Any] = {
    "name": "bank-estate-2026-11",
    "as_of": "2026-11-02",
    "components": [{"name": "openssl", "version": "3.0.13", "evidence_id": "SBOM-1",
                    "algorithms": ["AES-256-GCM", "RSA-2048", "AES-128-CBC",
                                   "AES-192-CBC"]}],
    "declared_versions": [{"name": "openssl", "version": "3.0.13",
                           "evidence_id": "SBOM-1"}],
    "operations": [
        {"application": "payments-api", "pid": 9182, "provider": "OpenSSL",
         "provider_version": "3.0.11", "operation": "EVP_EncryptInit_ex",
         "algorithm": "AES-256-GCM", "key_size": 256, "mode": "GCM",
         "observed_at": "2026-11-02T10:42:11Z", "evidence_id": "RUNTIME-1"},
        {"application": "signing-service", "pid": 4410, "provider": "OpenSSL",
         "provider_version": "3.0.11", "operation": "RSA_sign",
         "algorithm": "RSA-2048", "key_size": 2048, "purpose": "SIGNATURE",
         "observed_at": "2026-11-02T10:44:00Z", "evidence_id": "RUNTIME-2"},
    ],
    "keys": [{"key_ref": "kms/key/abc", "algorithm": "RSA", "key_size": 2048,
              "provider": "AWS_KMS", "status": "ENABLED", "created_at": "2025-01-01",
              "evidence_id": "KMS-1"}],
    "key_uses": [{"key_ref": "kms/key/abc", "operation": "decrypt",
                  "evidence_id": "KMS-USE-1"}],
    "probes": [{"endpoint": "payments.bank.example:443", "status": "OK",
                "crypto": {"tls_version": "1.3",
                           "cipher_suite": "TLS_AES_256_GCM_SHA384"},
                "evidence_id": "NET-1"}],
    "findings": [{"algorithm": "AES-128-CBC", "file_path": "legacy.java", "line": 12,
                  "key_size": 128, "mode": "CBC", "evidence_ids": ["STATIC-1"]}],
    "conflicts": [
        {"field": "version", "fact": "3.0.13", "source": "sbom", "evidence_id": "SBOM-1"},
        {"field": "version", "fact": "3.0.11", "source": "runtime",
         "evidence_id": "RUNTIME-1"},
        {"field": "cipher_suite", "fact": "TLS_AES_256_GCM_SHA384", "source": "network",
         "evidence_id": "NET-1"},
        {"field": "cipher_suite", "fact": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
         "source": "runtime", "evidence_id": "RUNTIME-2"}],
    "coverage": {"rollup": {"systems": 100, "with_cbom": 62,
                            "counts": {"CURRENT": 50, "STALE": 12}},
                 "files_scanned": 900},
}

POLICY = [{"algorithm": "AES-256-GCM", "key_size": 256},
          {"algorithm": "RSA-2048", "key_size": 2048},
          {"algorithm": "SHA-1", "allowed": False}]

ADVISORIES = [{"id": "CVE-2024-0001", "component": "openssl", "fixed_in": "3.0.14",
               "severity": "HIGH"},
              {"id": "CVE-2023-9999", "component": "libcrypto", "fixed_in": "1.1.1"}]


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import digital_twin, estate_chain  # noqa: PLC0415

    return {"dt": digital_twin, "ec": estate_chain}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _estate(**overrides) -> dict[str, Any]:
    estate = json.loads(json.dumps(ESTATE))
    for key, value in overrides.items():
        estate[key] = value
    return estate


def _node(twin: dict[str, Any], node_id: str) -> dict[str, Any]:
    return {node["id"]: node for node in twin["nodes"]}[node_id]


# --------------------------------------------------------------------------- #


def row_one_graph(modules: dict[str, Any]) -> dict[str, Any]:
    dt = modules["dt"]
    twin = dt.build(_estate())
    no_network = dt.build(_estate(probes=[]))
    ids = {node["id"] for node in twin["nodes"]}
    dangling = [edge for edge in twin["edges"]
                if edge["from"] not in ids or edge["to"] not in ids]
    probes = [
        _probe("all-five-evidence-families-reach-the-twin",
               len(no_network["unrepresented_families"]) < len(dt.FAMILIES)
               and set(twin["families"]) == set(dt.FAMILIES),
               json.dumps(twin["families"], sort_keys=True)),
        _probe("a-family-with-no-evidence-is-named-not-assumed",
               "network" in no_network["unrepresented_families"]
               and "no evidence yet from" in no_network["statement"],
               no_network["statement"]),
        _probe("no-edge-dangles-so-the-graph-can-be-walked",
               dangling == [], f"{len(twin['edges'])} edge(s), {len(dangling)} dangling"),
        _probe("every-edge-carries-the-evidence-that-drew-it",
               all(edge["evidence_ids"] for edge in twin["edges"]),
               f"{len(twin['edges'])} edge(s) with evidence ids"),
        _probe("the-twin-is-projected-from-the-document-not-rebuilt",
               twin["cbom"]["bomFormat"] == "CycloneDX"
               and twin["chain_schema"] == "cryptoscan.cbom-estate-chain/1",
               twin["chain_schema"]),
        _probe("a-declared-and-an-observed-value-are-resolved-by-precedence",
               not [edge for edge in twin["edges"] if edge["kind"] == "CONFLICTS_WITH"
                    and edge.get("field") == "version"],
               "the version disagreement is precedence, not a conflict"),
        _probe("two-observers-disagreeing-survive-as-a-conflict-edge",
               any(edge["kind"] == "CONFLICTS_WITH" and edge.get("field") == "cipher_suite"
                   for edge in twin["edges"]),
               "cipher_suite has two observed values and both are kept"),
    ]
    return {"id": "one_graph",
            "question": "does every evidence family connect into one graph?",
            "phase": "review 20 / graph", "probes": probes}


def row_no_upgrade(modules: dict[str, Any]) -> dict[str, Any]:
    dt = modules["dt"]
    twin = dt.build(_estate())
    component = _node(twin, "component:openssl")
    candidate = _node(twin, "algorithm:AES-192-CBC")
    static = _node(twin, "algorithm:AES-128-CBC")
    observed = _node(twin, "algorithm:AES-256-GCM")
    key = _node(twin, "key:kms/key/abc")
    consumers = dt.consumers(twin, policy=POLICY, advisories=ADVISORIES)
    drift_algorithms = {row["algorithm"]
                        for row in consumers["consumers"]["drift"]["findings"]}
    probes = [
        _probe("a-library-is-a-capability-whatever-its-algorithms-do",
               component["claim_level"] == "CAPABILITY"
               and component["families"] == ["sbom"],
               f"{component['id']}: {component['claim_level']}"),
        _probe("an-algorithm-only-a-library-lists-stays-a-capability",
               candidate["claim_level"] == "CAPABILITY"
               and candidate["usage"] == "CAPABILITY",
               f"AES-192-CBC is declared by {candidate.get('declared_by')} and used "
               "by nothing"),
        _probe("a-source-tree-call-is-static-evidence-and-says-so",
               static["claim_level"] == "STATIC"
               and static["evidence_ids"] == ["STATIC-1"],
               f"AES-128-CBC {static['claim_level']} from {static['evidence_classes']}"),
        _probe("an-observed-algorithm-inherits-runtime-from-its-strongest-evidence",
               observed["claim_level"] == "RUNTIME"
               and sorted(observed["evidence_ids"]) == ["NET-1", "RUNTIME-1"],
               f"{observed['claim_level']} from {observed['evidence_classes']}"),
        _probe("a-key-is-configured-and-never-observed",
               key["claim_level"] == "CONFIGURED"
               and key["private_material"] == "NOT STORED",
               f"{key['claim_level']}, private_material={key['private_material']}"),
        _probe("no-consumer-claims-more-than-the-node-it-read",
               consumers["claim_check"]["ok"] is True,
               consumers["claim_check"]["detail"]),
        _probe("a-candidate-algorithm-never-reaches-a-consumer-report",
               "AES-192-CBC" not in drift_algorithms
               and "AES-128-CBC" in drift_algorithms,
               f"drift rows: {', '.join(sorted(drift_algorithms)) or 'none'}"),
    ]
    return {"id": "no_upgrade",
            "question": "can a projection or a consumer upgrade a claim?",
            "phase": "review 20 / claims", "probes": probes}


def row_drift(modules: dict[str, Any]) -> dict[str, Any]:
    dt = modules["dt"]
    twin = dt.build(_estate())
    body = dt.drift(twin, POLICY)
    states = {row["algorithm"]: row["state"] for row in body["findings"]}
    unattributed = dt.drift(twin, [{"algorithm": "RSA-2048", "key_size": 2048}])
    clean = dt.drift(twin, [{"algorithm": "AES-256-GCM", "key_size": 256},
                            {"algorithm": "RSA-2048", "key_size": 2048},
                            {"algorithm": "SHA-1", "allowed": False}])
    forbidden = dt.drift(twin, [{"algorithm": "AES-256-GCM", "allowed": False},
                                {"algorithm": "RSA-2048"}])
    wrong_size = dt.drift(twin, [{"algorithm": "AES-256-GCM", "key_size": 128},
                                 {"algorithm": "RSA-2048", "key_size": 2048}])
    probes = [
        _probe("an-algorithm-outside-policy-is-unattributed-not-silent",
               {row["algorithm"]: row["state"]
                for row in unattributed["findings"]}.get("AES-256-GCM") == "UNATTRIBUTED",
               "AES-256-GCM is observed in use and no policy row mentions it"),
        _probe("a-policy-row-nobody-observed-is-not-called-drift",
               states.get("SHA-1") == "POLICY_NOT_OBSERVED" and clean["clean"] is True,
               [row["detail"] for row in body["findings"]
                if row["algorithm"] == "SHA-1"][0][:88]),
        _probe("a-forbidden-algorithm-seen-running-is-drift",
               forbidden["clean"] is False
               and {row["algorithm"]: row["state"] for row in forbidden["findings"]}
               .get("AES-256-GCM") == "UNEXPECTED_USE",
               forbidden["statement"]),
        _probe("the-wrong-parameter-is-parameter-drift",
               {row["algorithm"]: row["state"] for row in wrong_size["findings"]}
               .get("AES-256-GCM") == "PARAMETER_DRIFT",
               wrong_size["counts"]),
        _probe("a-drift-finding-cites-the-evidence-on-both-counts",
               all(row["evidence_ids"] for row in body["findings"]
                   if row["state"] != "POLICY_NOT_OBSERVED"),
               "every observed-side finding carries its evidence ids"),
    ]
    return {"id": "drift",
            "question": "what changed against policy, and what does that prove?",
            "phase": "review 20 / drift", "probes": probes}


def row_pqc_queue(modules: dict[str, Any]) -> dict[str, Any]:
    dt = modules["dt"]
    twin = dt.build(_estate())
    body = dt.pqc_migration(twin)
    rows = {row["algorithm"]: row for row in body["rows"]}
    order = ["IMMEDIATE", "NEAR_TERM", "PLANNED", "MONITOR"]
    ranks = [order.index(row["migration_priority"]) for row in body["rows"]
             if row["migration_priority"] in order]
    capability_only = dt.pqc_migration(dt.build(_estate(operations=[])))
    probes = [
        _probe("an-observed-rsa-operation-is-immediate-migration",
               rows["RSA-2048"]["quantum_status"] == "QUANTUM_SENSITIVE"
               and rows["RSA-2048"]["migration_priority"] == "IMMEDIATE",
               f"RSA-2048 {rows['RSA-2048']['migration_priority']}"),
        _probe("the-quantum-verdict-comes-from-the-registry-not-the-document",
               all(str(row["status_basis"]).startswith("REGISTRY_")
                   for row in body["rows"]),
               json.dumps({name: row["status_basis"] for name, row in rows.items()},
                          sort_keys=True)),
        _probe("the-queue-is-ordered-by-urgency",
               ranks == sorted(ranks), ", ".join(row["migration_priority"]
                                                 for row in body["rows"])),
        _probe("a-capability-only-estate-cannot-lead-with-immediate",
               all(row["migration_priority"] != "IMMEDIATE"
                   for row in capability_only["rows"]),
               capability_only["statement"]),
        _probe("each-row-keeps-the-claim-level-it-was-built-from",
               rows["RSA-2048"]["claim_level"] == "RUNTIME",
               f"RSA-2048 from {rows['RSA-2048']['claim_level']} evidence"),
    ]
    return {"id": "pqc_queue",
            "question": "which crypto has to migrate, and how firmly is that known?",
            "phase": "review 20 / migration", "probes": probes}


def row_threat_intel(modules: dict[str, Any]) -> dict[str, Any]:
    dt = modules["dt"]
    twin = dt.build(_estate())
    body = dt.threat_intelligence(twin, ADVISORIES)
    by_node = {}
    for row in body["findings"]:
        for node in row["nodes"]:
            by_node.setdefault(node, set()).add(row["exposure"])
    unversioned = dt.build(_estate(components=[
        {"name": "openssl", "algorithms": ["AES-256-GCM"], "evidence_id": "SBOM-9"}]))
    unknown = dt.threat_intelligence(unversioned, ADVISORIES[:1])
    absent = dt.threat_intelligence(twin, ADVISORIES[1:])
    probes = [
        _probe("a-provider-a-process-loaded-is-executing-exposure",
               by_node.get("provider:OpenSSL@3.0.11") == {"EXECUTING"},
               "a process has it loaded"),
        _probe("an-installed-component-is-present-not-executing",
               by_node.get("component:openssl") == {"PRESENT"},
               "installed, with nothing saying it is loaded"),
        _probe("a-component-with-no-version-is-neither-confirmed-nor-cleared",
               unknown["findings"][0]["exposure"] == "VERSION_UNKNOWN",
               unknown["findings"][0]["detail"]),
        _probe("an-advisory-for-something-absent-is-not-exposure",
               absent["findings"][0]["exposure"] == "NOT_PRESENT"
               and absent["exposed"] == 0,
               absent["statement"]),
        _probe("a-capability-algorithm-is-never-an-exposure-on-its-own",
               dt.threat_intelligence(twin, [{**ADVISORIES[0],
                                              "component": "aes-128-cbc"}])
               ["findings"][0]["exposure"] == "NOT_PRESENT",
               "a supported-but-unused algorithm is not a running exposure"),
        _probe("the-report-keeps-installed-and-running-apart",
               "installed and running are different exposures" in body["statement"],
               body["statement"]),
    ]
    return {"id": "threat_intel",
            "question": "which advisory touches code that is actually running?",
            "phase": "review 20 / threat", "probes": probes}


ROWS = (row_one_graph, row_no_upgrade, row_drift, row_pqc_queue, row_threat_intel)


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
    dt = modules["dt"]
    twin = dt.build(ESTATE)
    consumers = dt.consumers(twin, policy=POLICY, advisories=ADVISORIES)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "families": list(dt.FAMILIES),
        "node_kinds": list(dt.NODE_KINDS),
        "claim_levels": list(dt.CLAIM_LEVELS),
        "twin": {key: twin[key] for key in
                 ("estate", "statement", "families", "claim_levels")},
        "summary": dt.summary(twin, consumers),
        "rows": rows,
        "limits": [
            "the twin is a projection of the document and the evidence set behind it. "
            "Anything the collectors never saw is absent from the graph, not marked as "
            "unknown — the coverage block says how much was inspected, and that is the "
            "honest bound on the twin",
            "drift compares an observed algorithm with a policy row. It has no opinion "
            "about policy that does not exist yet: an algorithm seen in use with no "
            "policy row is reported as unattributed, not as drift",
            "the PQC queue orders what the twin *observed*. An estate that has not been "
            "traced yet produces a queue of capabilities, and every row says so",
            "threat intelligence matches advisories against component names and "
            "versions. It does not read CVE text, so a name mismatch (libcrypto vs "
            "openssl) is a miss, not a judgement",
            "a version range is read as numeric dotted parts. Vendors with their own "
            "versioning (or backported patches) need their fix to be expressed as a "
            "minimum version, and a backport is invisible here",
            "the three consumers are read-only by construction. Acting on them — "
            "quarantining a key, opening a migration ticket — happens outside the twin, "
            "where the claim level travels with the request",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    twin = report["twin"]
    summary = report["summary"]
    lines = [
        "# CBOM → digital twin: one graph, three consumers",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review item 20's architecture, implemented as a projection rather than a "
        "second inventory: the five evidence families feed one graph, the graph feeds "
        "the CBOM, and the twin is what three consumers read.",
        "",
        "```",
        "SBOM · STATIC · NETWORK · RUNTIME · HSM/KMS",
        "                    ↓",
        "               CRYPTO GRAPH → CBOM → DIGITAL TWIN",
        "                    ↓",
        "        DRIFT · PQC MIGRATION · THREAT INTELLIGENCE",
        "```",
        "",
        f"{twin['statement']}. Claim levels in the twin: "
        + ", ".join(f"`{name}` {count}" for name, count in twin["claim_levels"].items())
        + ".",
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
    lines += [
        "", "## The three consumers on the sample estate", "",
        f"{summary['statement']}", "",
        "| consumer | answer |", "|---|---|",
        f"| drift | {json.dumps(summary['drift'], sort_keys=True)} |",
        f"| PQC migration | {json.dumps(summary['migration'], sort_keys=True)} |",
        f"| threat intelligence | {json.dumps(summary['advisories'], sort_keys=True)} |",
        "", "## Claim levels", "",
        "| level | what it means |", "|---|---|",
        "| `CAPABILITY` | a library lists the algorithm; nothing used it |",
        "| `IMPORTED` | a document or a vendor says so; nobody verified it |",
        "| `CONFIGURED` | a key or setting exists in a store |",
        "| `STATIC` | the source tree contains a call |",
        "| `NETWORK` | an endpoint negotiated it |",
        "| `RUNTIME` | a process performed it |",
        "",
        "A consumer inherits the level of the node it read and may never exceed it. "
        "That is the check `no_upgrade` runs over every consumer row.",
        "", "## What this does not prove", "",
    ]
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
