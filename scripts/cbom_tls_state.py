#!/usr/bin/env python3
"""Guide 154 — supported, configured, negotiated: three states, three evidences.

Review item 7, as written:

    SUPPORTED: TLS 1.2, TLS 1.3 · CONFIGURED: TLS 1.2+ · NEGOTIATED: TLS 1.3
    "TLS 1.2 supported" does not mean "TLS 1.2 currently used"
    "TLS 1.3 negotiated" doesn't prove "TLS 1.3 is the only supported protocol"

The NBOM only ever recorded the third one. This guide adds the model that keeps all
three apart, each with its own evidence, and refuses the two conclusions a reader
wants to draw from a handshake: that an old protocol is disabled, and that the
negotiated version is the endpoint's minimum.
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
SCHEMA = "cryptoscan.cbom-tls-state-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

ENDPOINT = "payments.bank.example:443"

OBSERVATIONS: list[dict[str, Any]] = [
    {"endpoint": ENDPOINT, "state": "NEGOTIATED", "tls_version": "1.3",
     "cipher_suite": "TLS_AES_256_GCM_SHA384", "group": "X25519",
     "signature_algorithm": "ECDSA-P256", "evidence_id": "NET-1",
     "observed_at": "2026-11-02T10:00:00Z"},
    {"endpoint": ENDPOINT, "state": "SUPPORTED", "tls_version": "1.3",
     "evidence_id": "ENUM-1", "enumeration_complete": True},
    {"endpoint": ENDPOINT, "state": "SUPPORTED", "tls_version": "1.2",
     "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "evidence_id": "ENUM-1",
     "enumeration_complete": True},
    {"endpoint": ENDPOINT, "state": "CONFIGURED", "tls_version": "1.2",
     "evidence_id": "CFG-1"},
]

LEGACY = {"endpoint": "legacy.bank.example:443", "state": "NEGOTIATED",
          "tls_version": "1.2", "evidence_id": "NET-2"}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import tls_state  # noqa: PLC0415

    return {"ts": tls_state}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _endpoint(result: dict[str, Any], endpoint: str = ENDPOINT) -> dict[str, Any]:
    return {item["endpoint"]: item for item in result["endpoints"]}[endpoint]


# --------------------------------------------------------------------------- #


def row_three_states(modules: dict[str, Any]) -> dict[str, Any]:
    ts = modules["ts"]
    result = ts.observe(OBSERVATIONS)
    item = _endpoint(result)
    probes = [
        _probe("the-review-s-three-states-are-three-state-sets",
               item["supported"]["versions"] == ["TLS1.2", "TLS1.3"]
               and item["configured"]["versions"] == ["TLS1.2"]
               and item["negotiated"]["versions"] == ["TLS1.3"],
               item["statement"]),
        _probe("every-state-carries-its-own-evidence-ids",
               item["supported"]["evidence_ids"] == ["ENUM-1"]
               and item["configured"]["evidence_ids"] == ["CFG-1"]
               and item["negotiated"]["evidence_ids"] == ["NET-1"],
               "supported=ENUM-1, configured=CFG-1, negotiated=NET-1"),
        _probe("the-negotiated-facets-belong-to-the-handshake",
               item["negotiated"]["groups"] == ["X25519"]
               and item["negotiated"]["signature_algorithms"] == ["ECDSA-P256"]
               and item["supported"]["groups"] == [],
               "X25519 and ECDSA-P256 are negotiated facts, not offered ones"),
        _probe("a-document-s-word-for-configured-is-the-same-state",
               _endpoint(ts.observe([{"endpoint": "a:443", "state": "ENABLED",
                                      "tls_version": "1.3", "evidence_id": "CFG-9"}]),
                         "a:443")["configured"]["versions"] == ["TLS1.3"],
               "ENABLED in a config document is CONFIGURED here"),
        _probe("an-ssh-advertised-list-is-supported-not-negotiated",
               _endpoint(ts.observe([{"endpoint": "ssh:22", "state": "ADVERTISED",
                                      "cipher_suite": "chacha20-poly1305@openssh.com",
                                      "evidence_id": "SSH-1"}]), "ssh:22")
               ["supported"]["suites"] == ["chacha20-poly1305@openssh.com"],
               "ADVERTISED → SUPPORTED, so review item 13 can use the same model"),
    ]
    return {"id": "three_states",
            "question": "are supported, configured and negotiated three answers?",
            "phase": "review 7", "probes": probes}


def row_no_inference(modules: dict[str, Any]) -> dict[str, Any]:
    ts = modules["ts"]
    result = ts.observe([*OBSERVATIONS, LEGACY])
    legacy = _endpoint(result, "legacy.bank.example:443")
    unknown_state = ts.observe([{"endpoint": "a:443", "state": "MAYBE",
                                 "tls_version": "1.3", "evidence_id": "X-1"}])
    no_evidence = ts.observe([{"endpoint": "a:443", "state": "SUPPORTED",
                               "tls_version": "1.3"}])
    no_facet = ts.observe([{"endpoint": "a:443", "state": "NEGOTIATED",
                            "evidence_id": "N-1"}])
    probes = [
        _probe("a-negotiated-handshake-says-nothing-about-what-else-is-supported",
               legacy["supported"]["versions"] == []
               and legacy["negotiated"]["versions"] == ["TLS1.2"],
               "legacy: negotiated TLS1.2, supported unknown"),
        _probe("support-for-a-protocol-does-not-say-it-is-in-use",
               result["endpoints"][1]["supported"]["versions"] == ["TLS1.2", "TLS1.3"]
               and result["endpoints"][1]["negotiated"]["versions"] == ["TLS1.3"],
               "TLS1.2 supported, TLS1.3 negotiated"),
        _probe("a-fact-whose-state-nobody-stated-is-refused",
               unknown_state["endpoints"] == []
               and "cannot be sorted into one" in unknown_state["refused"][0]["reason"],
               unknown_state["refused"][0]["reason"]),
        _probe("a-state-with-no-evidence-id-is-a-claim-and-is-refused",
               no_evidence["endpoints"] == []
               and "must be provable, not asserted" in no_evidence["refused"][0]["reason"],
               no_evidence["refused"][0]["reason"]),
        _probe("a-state-fact-about-nothing-is-refused",
               no_facet["endpoints"] == []
               and "says nothing about the endpoint" in no_facet["refused"][0]["reason"],
               no_facet["refused"][0]["reason"]),
        _probe("the-summary-names-the-endpoints-only-negotiation-was-seen-on",
               ts.summary(result)["negotiated_only"] == ["legacy.bank.example:443"],
               ts.summary(result)["statement"]),
    ]
    return {"id": "no_inference",
            "question": "can one state be inferred from another?",
            "phase": "review 7 / 3", "probes": probes}


def row_disabled_claims(modules: dict[str, Any]) -> dict[str, Any]:
    ts = modules["ts"]
    result = ts.observe([*OBSERVATIONS, LEGACY])
    proven = ts.disabled(result, endpoint=ENDPOINT, version="1.1")
    in_use = ts.disabled(result, endpoint=ENDPOINT, version="1.3")
    still_offered = ts.disabled(result, endpoint=ENDPOINT, version="1.2")
    not_enumerated = ts.disabled(result, endpoint="legacy.bank.example:443", version="1.1")
    incomplete = ts.disabled(
        ts.observe([{"endpoint": "a:443", "state": "SUPPORTED", "tls_version": "1.3",
                     "evidence_id": "ENUM-2", "enumeration_complete": False},
                    {"endpoint": "a:443", "state": "NEGOTIATED", "tls_version": "1.3",
                     "evidence_id": "NET-3"}]),
        endpoint="a:443", version="1.2")
    probes = [
        _probe("a-complete-enumeration-proves-a-protocol-is-gone",
               proven["state"] == "DISABLED_PROVEN" and proven["proven"] is True,
               proven["statement"]),
        _probe("a-protocol-that-was-negotiated-is-not-disabled",
               in_use["state"] == "IN_USE" and in_use["proven"] is False,
               in_use["statement"]),
        _probe("a-protocol-still-offered-is-not-disabled",
               still_offered["state"] == "SUPPORTED",
               still_offered["statement"]),
        _probe("a-modern-handshake-is-not-an-enumeration",
               not_enumerated["state"] == "NOT_ENUMERATED"
               and "a modern handshake is not an enumeration"
               in not_enumerated["statement"],
               not_enumerated["statement"]),
        _probe("a-partial-enumeration-cannot-speak-for-what-it-never-asked",
               incomplete["state"] == "ENUMERATION_INCOMPLETE"
               and "never asked about" in incomplete["statement"],
               incomplete["statement"]),
        _probe("an-endpoint-nobody-observed-is-unknown-not-clean",
               ts.disabled(result, endpoint="ghost:443", version="1.1")["state"]
               == "UNKNOWN",
               "no observation, so nothing is known"),
    ]
    return {"id": "disabled_claims",
            "question": "when may the platform say an old protocol is disabled?",
            "phase": "review 3 / 7", "probes": probes}


def row_minimum(modules: dict[str, Any]) -> dict[str, Any]:
    ts = modules["ts"]
    result = ts.observe([*OBSERVATIONS, LEGACY])
    configured = ts.minimum(result, endpoint=ENDPOINT)
    enumerated = ts.minimum(
        ts.observe([{"endpoint": "a:443", "state": "SUPPORTED", "tls_version": "1.3",
                     "evidence_id": "ENUM-3", "enumeration_complete": True},
                    {"endpoint": "a:443", "state": "SUPPORTED", "tls_version": "1.2",
                     "evidence_id": "ENUM-3", "enumeration_complete": True}]),
        endpoint="a:443")
    negotiated_only = ts.minimum(result, endpoint="legacy.bank.example:443")
    probes = [
        _probe("configuration-is-the-first-basis-for-a-minimum",
               configured["version"] == "TLS1.2" and configured["basis"] == "CONFIGURED"
               and configured["claimable"] is True,
               configured["statement"]),
        _probe("a-complete-enumeration-is-the-second-basis",
               enumerated["version"] == "TLS1.2"
               and enumerated["basis"] == "SUPPORTED_ENUMERATION",
               enumerated["statement"]),
        _probe("a-negotiated-version-is-never-a-minimum",
               negotiated_only["basis"] == "NEGOTIATED_ONLY"
               and negotiated_only["claimable"] is False,
               negotiated_only["statement"]),
        _probe("an-endpoint-nobody-observed-has-no-minimum",
               ts.minimum(result, endpoint="ghost:443")["claimable"] is False,
               "no observation, so no minimum"),
        _probe("the-basis-travels-with-the-answer",
               len({configured["basis"], enumerated["basis"],
                    negotiated_only["basis"]}) == 3,
               f"{configured['basis']} · {enumerated['basis']} · "
               f"{negotiated_only['basis']}"),
    ]
    return {"id": "minimum",
            "question": "what may be called the endpoint's minimum version?",
            "phase": "review 7", "probes": probes}


def row_document(modules: dict[str, Any]) -> dict[str, Any]:
    ts = modules["ts"]
    result = ts.observe([*OBSERVATIONS, LEGACY])
    document = {"bomFormat": "CycloneDX", "specVersion": "1.5",
                "components": [{"type": "network-endpoint", "bom-ref": "endpoint:1",
                                "name": ENDPOINT},
                               {"type": "network-endpoint", "bom-ref": "endpoint:2",
                                "name": "other:443"}]}
    attached = ts.attach(document, result)
    names = [row["name"] for row in attached["components"][0]["properties"]]
    properties = {row["name"]: row["value"]
                  for row in ts.properties(_endpoint(result))}
    probes = [
        _probe("each-state-becomes-its-own-property",
               {"cryptoscan:supported_tls_version",
                "cryptoscan:configured_tls_version",
                "cryptoscan:negotiated_tls_version"} <= set(names),
               json.dumps(sorted(set(names))[:4])),
        _probe("no-merged-version-property-exists-to-be-misread",
               "cryptoscan:tls_version" not in names,
               "a single tls_version property would force every reader to guess its state"),
        _probe("the-enumeration-flag-travels-with-the-endpoint",
               properties["cryptoscan:tls_enumeration_complete"] == "true",
               "cryptoscan:tls_enumeration_complete = true"),
        _probe("evidence-ids-travel-per-state-not-as-one-list",
               properties["cryptoscan:supported_evidence_id"] == "ENUM-1"
               and properties["cryptoscan:negotiated_evidence_id"] == "NET-1",
               "supported=ENUM-1, negotiated=NET-1"),
        _probe("an-endpoint-the-model-does-not-know-is-left-alone",
               "properties" not in attached["components"][1],
               "other:443 is untouched"),
    ]
    return {"id": "document",
            "question": "can a document reader merge the three states by accident?",
            "phase": "review 7 / 6", "probes": probes}


ROWS = (row_three_states, row_no_inference, row_disabled_claims, row_minimum, row_document)


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
    ts = modules["ts"]
    result = ts.observe([*OBSERVATIONS, LEGACY])
    item = _endpoint(result)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "states": list(ts.STATES),
        "bases": list(ts.BASES),
        "endpoint": item,
        "summary": ts.summary(result),
        "rows": rows,
        "limits": [
            "SUPPORTED is only as complete as the enumeration behind it. The model "
            "records the flag rather than inferring it, because a scanner that tries "
            "one ClientHello has not asked the endpoint anything about old protocols",
            "the model holds facts, not policy quality. It can say TLS1.1 is disabled; "
            "it cannot say whether TLS1.2 is acceptable for this data classification, "
            "which is a policy judgement made elsewhere",
            "a configured minimum is an intent. If nothing measures the endpoint "
            "against it, the configuration is a declaration and the drift between it "
            "and what was negotiated is a separate finding",
            "the three states share one vocabulary across TLS, SSH and IKE, but the "
            "collectors do not exist yet for SSH and IKE. The alias table is ready; the "
            "evidence is not",
            "an endpoint is identified by host:port here. Two virtual hosts behind one "
            "address need SNI in the identity before their state sets can be kept "
            "apart — that is the open asset-identity item, not a solved problem",
            "refusals are reported per row rather than failing the batch. A single "
            "evidence-less claim does not silence the endpoints that were measured, and "
            "it does not disappear either",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    item = report["endpoint"]
    lines = [
        "# Supported, configured, negotiated: three states, three evidences",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review item 7: `TLS 1.2 supported` is not `TLS 1.2 in use`, and "
        "`TLS 1.3 negotiated` does not prove it is the only supported protocol. The "
        "NBOM only ever recorded the third.",
        "",
        "```",
        "SUPPORTED   what the endpoint offered when asked      (enumeration evidence)",
        "CONFIGURED  what policy says it should do             (configuration evidence)",
        "NEGOTIATED  what one handshake actually produced      (handshake evidence)",
        "```",
        "",
        f"`{item['endpoint']}` — {item['statement']}",
        "",
        "| conclusion | may it be drawn? | basis |",
        "|---|---|---|",
        "| a protocol is **disabled** | only from a complete authorized enumeration | "
        "`DISABLED_PROVEN`, else `NOT_ENUMERATED` / `ENUMERATION_INCOMPLETE` |",
        "| the endpoint's **minimum** version | from configuration, then a complete "
        "enumeration | `CONFIGURED` · `SUPPORTED_ENUMERATION` · `NEGOTIATED_ONLY` "
        "(not claimable) |",
        "| a protocol is **in use** | from a negotiated handshake | `NEGOTIATED` |",
        "| what else the endpoint **supports** | only from an enumeration | never from "
        "a handshake |",
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
