#!/usr/bin/env python3
"""Guide 148 — network crypto assets: the interface owns the hop, not the application.

Review item 8 is one sentence with a large consequence. If the network layer sees
``TLS_AES_256_GCM_SHA384`` on ``payments.bank.example:443`` and the path is

    Internet → WAF → External LB → API Gateway → Payments API

then the CBOM may say *network crypto asset AES-256-GCM, endpoint
payments.bank.example:443, observed on External LB, evidence NET-9281, hop
Internet → External LB* — and may **not** say *Payments API uses AES-256-GCM*
unless the evidence proves the application terminated the hop. In a bank the load
balancer terminates TLS; the application behind it may speak a different TLS
version with a different suite to the gateway.

``cbom.network_assets`` keeps the attribution and makes the overclaim detectable:
an asset names an application only when the estate declared it (or the hop says
``role: APPLICATION``), and ``audit_graph`` reports every usage edge whose whole
basis is a handshake that terminated in front of its subject.
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
SCHEMA = "cryptoscan.cbom-network-assets-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

LB_HOP = {"from": "Internet", "to": "External LB",
          "endpoint": "payments.bank.example:443", "observed_on": "External LB",
          "cipher_suite": "TLS_AES_256_GCM_SHA384", "tls_version": "1.3",
          "evidence_id": "NET-9281"}
APP_HOP = {"from": "External LB", "to": "payments-api",
           "endpoint": "payments-api.internal:8443", "observed_on": "payments-api",
           "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "tls_version": "1.2",
           "evidence_id": "NET-9282"}
API_GW_HOP = {"from": "External LB", "to": "api-gateway",
              "endpoint": "gateway.bank.example:443", "observed_on": "api-gateway",
              "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "tls_version": "1.2",
              "evidence_id": "NET-9283"}

HOP_PATH = [LB_HOP, API_GW_HOP, APP_HOP]


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import estate_chain, network_assets  # noqa: PLC0415

    return {"na": network_assets, "ec": estate_chain}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _row(result: dict[str, Any], endpoint: str, algorithm: str) -> dict[str, Any]:
    return [row for row in result["assets"]
            if row["endpoint"] == endpoint and row["algorithm"] == algorithm][0]


# --------------------------------------------------------------------------- #


def row_the_shape(modules: dict[str, Any]) -> dict[str, Any]:
    na = modules["na"]
    result = na.assets([LB_HOP], applications=["payments-api"])
    aes = _row(result, "payments.bank.example:443", "AES-256-GCM")
    probes = [
        _probe("the-network-asset-is-the-algorithm",
               aes["algorithm"] == "AES-256-GCM", aes["algorithm"]),
        _probe("the-endpoint-is-the-one-that-negotiated-it",
               aes["endpoint"] == "payments.bank.example:443", aes["endpoint"]),
        _probe("the-asset-says-which-interface-observed-it",
               aes["observed_on"] == "External LB", aes["observed_on"]),
        _probe("the-evidence-id-travels-with-the-asset",
               aes["evidence_ids"] == ["NET-9281"], ", ".join(aes["evidence_ids"])),
        _probe("the-hop-is-named-not-just-indexed",
               aes["hop"] == {"from": "Internet", "to": "External LB"}
               and aes["hop_label"] == "Internet → External LB", aes["hop_label"]),
        _probe("the-terminator-is-classified",
               aes["interface_role"] == "LOAD_BALANCER", aes["interface_role"]),
        _probe("the-statement-says-who-owns-the-fact",
               "interface fact" in aes["statement"]
               and "not attributed to any application" in aes["statement"],
               aes["statement"]),
        _probe("the-tls-version-is-kept-with-the-algorithm",
               aes["tls_versions"] == ["1.3"], ", ".join(aes["tls_versions"])),
    ]
    return {"id": "the_shape",
            "question": "does an observation produce the asset the review asks for?",
            "phase": "review 8", "probes": probes}


def row_the_owner(modules: dict[str, Any]) -> dict[str, Any]:
    na = modules["na"]
    fronting = na.assets([LB_HOP], applications=["payments-api"])
    proven = na.assets([APP_HOP], applications=["payments-api"])
    untrusted = na.assets([APP_HOP])
    declared = na.assets([{**APP_HOP, "role": "APPLICATION"}])
    path = na.assets(HOP_PATH, applications=["payments-api"])
    aes_at_lb = _row(fronting, "payments.bank.example:443", "AES-256-GCM")
    bulk_behind = _row(proven, "payments-api.internal:8443", "AES-128-GCM")
    probes = [
        _probe("a-fronting-terminator-is-not-an-application",
               aes_at_lb["application"] is None
               and aes_at_lb["application_inference"] == "NOT_PROVEN",
               "the LB terminated the handshake; the application behind it was not observed"),
        _probe("a-declared-application-terminates-its-own-hop",
               bulk_behind["application"] == "payments-api"
               and bulk_behind["interface_role"] == "APPLICATION",
               f"{bulk_behind['algorithm']} is attributed to {bulk_behind['application']}"),
        _probe("an-undeclared-name-is-not-taken-on-trust",
               untrusted["assets"][0]["application"] is None
               and untrusted["assets"][0]["application_inference"] == "NOT_PROVEN",
               "a hostname that looks like an application is still a hop terminator"),
        _probe("a-hop-may-declare-itself-the-application",
               declared["assets"][0]["application_inference"] == "PROVEN",
               "role=APPLICATION is a claim the collector makes, not one this module invents"),
        _probe("the-two-hops-do-not-share-an-attribution",
               _row(path, "payments.bank.example:443", "AES-256-GCM")["application"] is None
               and _row(path, "payments-api.internal:8443", "AES-128-GCM")["application"]
               == "payments-api",
               "the LB's AES-256-GCM and the application's AES-128-GCM are different facts"),
        _probe("the-gateway-is-not-the-application-either",
               _row(path, "gateway.bank.example:443", "AES-256-GCM")["application"] is None
               and _row(path, "gateway.bank.example:443",
                        "AES-256-GCM")["interface_role"] == "API_GATEWAY",
               "an API gateway in the middle of the path terminates its own hop"),
        _probe("the-summary-says-how-much-stayed-with-the-interface",
               na.summary(path)["attributed_to_an_application"] == 4
               and len(na.summary(path)["not_attributed"]) == 6,
               na.summary(path)["statement"]),
    ]
    return {"id": "the_owner",
            "question": "who does the algorithm belong to?",
            "phase": "review 8 / 9", "probes": probes}


def row_merging(modules: dict[str, Any]) -> dict[str, Any]:
    na = modules["na"]
    repeat = na.assets([LB_HOP, {**LB_HOP, "evidence_id": "NET-9290"}])
    upgraded = na.assets([LB_HOP, {**LB_HOP, "evidence_id": "NET-9291",
                                   "tls_version": "1.2"}])
    second = na.assets([LB_HOP, {**LB_HOP, "endpoint": "openbanking.bank.example:443",
                                 "evidence_id": "NET-9292"}])
    roles = {row["algorithm"]: row["role_in_suite"] for row in na.assets([APP_HOP])["assets"]}
    probes = [
        _probe("a-repeated-observation-merges-its-evidence",
               _row(repeat, "payments.bank.example:443",
                    "AES-256-GCM")["evidence_ids"] == ["NET-9281", "NET-9290"],
               ", ".join(_row(repeat, "payments.bank.example:443",
                              "AES-256-GCM")["evidence_ids"])),
        _probe("a-hop-that-changed-version-keeps-both",
               _row(upgraded, "payments.bank.example:443",
                    "AES-256-GCM")["tls_versions"] == ["1.2", "1.3"],
               ", ".join(_row(upgraded, "payments.bank.example:443",
                              "AES-256-GCM")["tls_versions"])),
        _probe("two-endpoints-are-two-assets",
               len(second["assets"]) == 4 and len(second["endpoints"]) == 2,
               second["statement"]),
        _probe("the-role-inside-the-suite-survives",
               roles.get("AES-128-GCM") == "BULK" and roles.get("ECDHE") == "KEY_EXCHANGE",
               json.dumps(roles, sort_keys=True)),
        _probe("an-openssl-suite-keeps-its-bulk-cipher",
               "AES-128-GCM" in roles,
               "ECDHE-RSA-AES128-GCM-SHA256 tokenises to AES128_GCM, which the suite "
               "table now covers"),
    ]
    return {"id": "merging",
            "question": "does one connection produce one asset, or a pile of rows?",
            "phase": "review 8", "probes": probes}


def row_refusals(modules: dict[str, Any]) -> dict[str, Any]:
    na = modules["na"]
    no_endpoint = na.assets([{**LB_HOP, "endpoint": None}])
    no_suite = na.assets([{**LB_HOP, "cipher_suite": None}])
    no_evidence = na.assets([{**LB_HOP, "evidence_id": None}])
    no_owner = na.assets([{**LB_HOP, "observed_on": None, "to": None}])
    not_object = na.assets(["External LB"])
    fallback = _row(na.assets([{**LB_HOP, "observed_on": None}]),
                    "payments.bank.example:443", "AES-256-GCM")
    probes = [
        _probe("a-hop-with-no-endpoint-is-refused",
               no_endpoint["assets"] == [] and no_endpoint["refused"],
               no_endpoint["refused"][0]["reason"]),
        _probe("a-hop-with-no-suite-attributes-no-algorithm",
               no_suite["assets"] == [] and "suite" in no_suite["refused"][0]["reason"],
               no_suite["refused"][0]["reason"]),
        _probe("a-handshake-with-no-evidence-is-inventory-not-fact",
               no_evidence["assets"] == []
               and "evidence id" in no_evidence["refused"][0]["reason"],
               no_evidence["refused"][0]["reason"]),
        _probe("a-path-position-is-not-an-owner",
               no_owner["assets"] == []
               and "no interface" in no_owner["refused"][0]["reason"],
               no_owner["refused"][0]["reason"]),
        _probe("a-hop-that-is-not-an-object-is-refused",
               not_object["refused"][0]["reason"] == "a hop must be an object",
               not_object["refused"][0]["reason"]),
        _probe("the-hop-target-is-used-when-no-observer-was-recorded",
               fallback["observed_on"] == "External LB",
               "a hop that names its target names its terminator"),
    ]
    return {"id": "refusals",
            "question": "what is refused rather than attributed to nobody?",
            "phase": "review 8 / 12", "probes": probes}


def row_the_document(modules: dict[str, Any]) -> dict[str, Any]:
    na = modules["na"]
    result = na.assets(HOP_PATH, applications=["payments-api"])
    components = na.to_components(result)["components"]
    lb = [component for component in components
          if component["bom-ref"] == "network:payments.bank.example:443#AES-256-GCM"][0]
    properties = {row["name"]: row["value"] for row in lb["properties"]}
    proven = [component for component in components
              if component["bom-ref"] == "network:payments-api.internal:8443#AES-128-GCM"][0]
    proven_properties = {row["name"]: row["value"] for row in proven["properties"]}
    probes = [
        _probe("one-component-per-endpoint-and-algorithm",
               len({component["bom-ref"] for component in components}) == len(components)
               == len(result["assets"]),
               f"{len(components)} component(s) for {len(result['assets'])} asset(s)"),
        _probe("the-component-is-a-cyclonedx-cryptographic-asset",
               lb["type"] == "cryptographic-asset"
               and lb["cryptoProperties"]["assetType"] == "algorithm",
               lb["bom-ref"]),
        _probe("the-five-fields-are-carried-as-properties",
               properties["cryptoscan:endpoint"] == "payments.bank.example:443"
               and properties["cryptoscan:observed_on"] == "External LB"
               and properties["cryptoscan:hop"] == "Internet → External LB"
               and properties["cryptoscan:evidence_id"] == "NET-9281",
               json.dumps({key: properties[key] for key in (
                   "cryptoscan:endpoint", "cryptoscan:observed_on",
                   "cryptoscan:hop", "cryptoscan:evidence_id")}, sort_keys=True)),
        _probe("no-application-is-written-where-none-was-proven",
               "cryptoscan:application" not in properties
               and properties["cryptoscan:application_inference"] == "NOT_PROVEN",
               "the LB component names the interface, not the application"),
        _probe("a-proven-application-is-written-down",
               proven_properties.get("cryptoscan:application") == "payments-api"
               and proven_properties["cryptoscan:application_inference"] == "PROVEN",
               proven["bom-ref"]),
        _probe("the-network-level-is-on-the-component",
               properties["cryptoscan:promotion_level"] == "NETWORK"
               and properties["cryptoscan:observed_classes"] == "NETWORK_OBSERVED",
               "a network observation promotes to NETWORK, not to VERIFIED"),
    ]
    return {"id": "the_document",
            "question": "can a reviewer read the component without guessing the hop?",
            "phase": "review 8 / 12", "probes": probes}


def row_the_audit(modules: dict[str, Any]) -> dict[str, Any]:
    na, ec = modules["na"], modules["ec"]
    result = na.assets([LB_HOP], applications=["payments-api"])
    overclaim = na.audit_graph({"edges": [{
        "from": "application:payments-api", "kind": "USES_CRYPTO",
        "to": "algorithm:AES-256-GCM", "evidence_classes": ["NETWORK_OBSERVED"],
        "evidence_ids": ["NET-9281"]}]}, result)
    system = na.audit_graph({"edges": [{
        "from": "system:bank-estate", "kind": "USES_CRYPTO",
        "to": "algorithm:AES-256-GCM",
        "evidence_classes": ["NETWORK_OBSERVED"]}]}, result)
    runtime = na.audit_graph({"edges": [{
        "from": "application:payments-api", "kind": "USES_CRYPTO",
        "to": "algorithm:AES-256-GCM",
        "evidence_classes": ["RUNTIME_OBSERVED", "NETWORK_OBSERVED"]}]}, result)
    unknown = na.audit_graph({"edges": [{
        "from": "application:payments-api", "kind": "USES_CRYPTO",
        "to": "algorithm:SHA-1", "evidence_classes": ["NETWORK_OBSERVED"]}]}, result)
    other_kind = na.audit_graph({"edges": [{
        "from": "application:payments-api", "kind": "NEGOTIATES",
        "to": "algorithm:AES-256-GCM",
        "evidence_classes": ["NETWORK_OBSERVED"]}]}, result)
    estate = ec.run({
        "name": "bank-estate-2026-11",
        "probes": [{**LB_HOP, "status": "OK",
                    "crypto": {"cipher_suite": LB_HOP["cipher_suite"],
                               "tls_version": LB_HOP["tls_version"]}}],
    })
    probes = [
        _probe("an-application-edge-resting-on-a-fronting-hop-is-an-overclaim",
               len(overclaim["overclaims"]) == 1
               and overclaim["overclaims"][0]["terminated_at"] == ["External LB"],
               overclaim["statement"]),
        _probe("the-overclaim-carries-the-role-that-terminated-it",
               overclaim["overclaims"][0]["interface_roles"] == ["LOAD_BALANCER"],
               ", ".join(overclaim["overclaims"][0]["interface_roles"])),
        _probe("a-system-edge-is-audited-too",
               system["overclaims"] and
               system["overclaims"][0]["subject"] == "system:bank-estate",
               "an estate-level claim is the same claim, one level up"),
        _probe("an-edge-with-runtime-evidence-is-not-an-overclaim",
               runtime["overclaims"] == [],
               "the application was observed doing it; the handshake is corroboration"),
        _probe("an-algorithm-the-network-never-saw-is-not-audited",
               unknown["checked_edges"] == 0, "no network asset, no network claim"),
        _probe("another-edge-kind-is-not-a-usage-claim",
               other_kind["overclaims"] == [], "NEGOTIATES is the endpoint's, not a use"),
        _probe("the-estate-chain-exposes-the-audit",
               "components" in estate["network"]
               and estate["network"]["audit"]["checked_edges"] > 0
               and bool(estate["network"]["audit"]["overclaims"]),
               estate["network"]["audit"]["statement"]),
    ]
    return {"id": "the_audit",
            "question": "is the review's overclaim detectable, or only documented?",
            "phase": "review 8 / 20", "probes": probes}


ROWS = (row_the_shape, row_the_owner, row_merging, row_refusals, row_the_document,
        row_the_audit)


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
    na = modules["na"]
    sample = na.assets(HOP_PATH, applications=["payments-api"])
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "sample": {"assets": len(sample["assets"]), "endpoints": sample["endpoints"],
                   "interfaces": sample["interfaces"], "roles": sample["roles"],
                   "summary": na.summary(sample)},
        "rows": rows,
        "limits": [
            "the identification of a hop's role is a name heuristic plus whatever the "
            "collector declares. A load balancer called 'edge01' is UNKNOWN here, which is "
            "the honest answer and also an operational gap: the collector should report a "
            "role rather than a hostname",
            "the module cannot see the path. It attributes each hop by itself; a hop whose "
            "'from' is wrong, or a probe that went through a CDN the operator did not "
            "record, produces a correct attribution for the wrong topology",
            "an application is proven by declaration, not by observation. Declaring the "
            "wrong set of applications turns NOT_PROVEN into PROVEN, and the audit will "
            "then be silent about a real overclaim",
            "the audit only sees a graph it is given. A report that never builds a "
            "USES_CRYPTO edge cannot overclaim here, and equally cannot be checked here",
            "network evidence proves what was negotiated, not what is enforced: a suite "
            "offered in a handshake says nothing about the algorithms the application uses "
            "on the data afterwards",
            "a certificate's public key algorithm arrives as its own evidence category. "
            "ECDSA-P256 in a certificate is the certificate's, and this module deliberately "
            "never turns it into an application algorithm",
            "one endpoint may front several applications through SNI; without per-SNI "
            "probing the hop is one asset, and the mapping to applications stays unproven",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    sample = report["sample"]
    lines = [
        "# Network crypto assets: the interface owns the hop",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review item 8, in the review's own words: if network observes "
        "`TLS_AES_256_GCM_SHA384`, the CBOM should say *network crypto asset AES-256-GCM, "
        "endpoint payments.bank.example:443, observed on External LB, evidence NET-9281, "
        "hop Internet → External LB* — **not** *Payments API uses AES-256-GCM*, unless the "
        "evidence proves that.",
        "",
        "```",
        "Internet → WAF → External LB → API Gateway → Payments API",
        "                        ^",
        "                        the handshake terminates here",
        "```",
        "",
        "`cbom.network_assets` keeps the attribution:",
        "",
        "1. **one asset per (endpoint, algorithm)** carrying `observed_on`, the hop label, "
        "the interface role and its evidence ids;",
        "2. **no application name unless proven** — declared by the estate, or declared by "
        "the hop itself as `role: APPLICATION`. A hostname is never read as proof;",
        "3. **the terminator is classified** — `WAF`, `LOAD_BALANCER`, `API_GATEWAY`, "
        "`REVERSE_PROXY`, `CDN`, `APPLICATION`, else `UNKNOWN`;",
        "4. **a hop with no owner or no evidence is refused**, because \"somewhere in the "
        "path\" is what lets the wrong system inherit the algorithms;",
        "5. **the overclaim is detectable** — `audit_graph` reports every `USES_CRYPTO` "
        "edge whose whole basis is a handshake that terminated in front of its subject.",
        "",
        f"On the sample path: {sample['assets']} asset(s) over "
        f"{len(sample['endpoints'])} endpoint(s) and {len(sample['interfaces'])} "
        f"interface(s); roles `{json.dumps(sample['roles'], sort_keys=True)}`; "
        f"{sample['summary']['statement']}.",
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
