#!/usr/bin/env python3
"""Guide 160 — network topology as relationships that carry their own evidence.

Review item 12:

    Relationships: `CONNECTS_TO`, `ROUTES_TO`, `TERMINATES_TLS`, `RE_ENCRYPTS`,
    `PASSTHROUGH`, `PROTECTED_BY`, `USES_CERTIFICATE`, `USES_HSM`, `USES_KMS`. Every
    relationship needs `evidence_id`, `observed_at`, `source`, `confidence` — otherwise
    the topology is fiction.

A topology is the most persuasive artefact the platform produces and therefore the one
most able to lie. Here an edge with no evidence is **not drawn**, `confidence` is
derived from what the evidence supports rather than supplied, and the two claims that
are almost always wrong — `RE_ENCRYPTS` and `PASSTHROUGH` — each have a gate.
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
SCHEMA = "cryptoscan.cbom-topology-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

HOPS = [
    {"from": "Internet", "to": "External LB", "role": "LOAD_BALANCER",
     "cipher_suite": "TLS_AES_256_GCM_SHA384", "tls_version": "1.3",
     "evidence_id": "NET-1", "observed_at": "2026-11-01T00:00:00Z"},
    {"from": "External LB", "to": "Internal LB", "role": "LOAD_BALANCER",
     "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "tls_version": "1.2",
     "evidence_id": "NET-2", "observed_at": "2026-11-01T00:00:00Z"},
    {"from": "Internal LB", "to": "payments.bank.example:8443", "role": "SERVER",
     "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "tls_version": "1.3",
     "evidence_id": "NET-3", "observed_at": "2026-11-01T00:00:00Z"},
    {"from": "10.20.1.10", "to": "External LB", "role": "LOAD_BALANCER",
     "cipher_suite": "TLS_AES_256_GCM_SHA384", "tls_version": "1.3",
     "evidence_id": "NET-4", "observed_at": "2026-11-01T00:00:00Z"},
]
CERTIFICATES = [
    {"endpoint": "External LB", "certificate_ref": "CERT-9281", "evidence_id": "CERT-E1",
     "source": "network-probe", "observed_at": "2026-11-01T00:00:00Z"},
    {"endpoint": "Internal LB", "certificate_ref": "CERT-9282", "evidence_id": "CERT-E2",
     "source": "network-probe", "observed_at": "2026-11-01T00:00:00Z"},
]
KEYS = [
    {"host": "Internal LB", "hsm_id": "HSM-1", "evidence_id": "HSM-E1",
     "observed_at": "2026-11-01T00:00:00Z"},
    {"host": "payments.bank.example:8443", "kms_id": "KMS-1", "evidence_id": "KMS-E1",
     "observed_at": "2026-11-01T00:00:00Z"},
]
DECLARED = [
    {"kind": "PROTECTED_BY", "from": "payments.bank.example:8443", "to": "WAF-1",
     "evidence_id": "CMDB-7", "observed_at": "2026-10-01T00:00:00Z", "source": "cmdb",
     "evidence_class": "DECLARED"},
    {"kind": "ROUTES_TO", "from": "External LB", "to": "Internal LB",
     "evidence_id": "CMDB-8", "observed_at": "2026-10-01T00:00:00Z", "source": "cmdb",
     "evidence_class": "DECLARED"},
]
NODES = [
    {"name": "External LB", "role": "LOAD_BALANCER"},
    {"name": "Internal LB", "role": "LOAD_BALANCER"},
    {"name": "payments.bank.example:8443", "role": "SERVER"},
    {"name": "WAF-1", "role": "WAF"},
    {"name": "Internet", "role": "UNKNOWN"},
    {"name": "10.20.1.10", "role": "UNKNOWN"},
    {"name": "CERT-9281", "role": "CERTIFICATE"},
    {"name": "CERT-9282", "role": "CERTIFICATE"},
    {"name": "HSM-1", "role": "HSM"},
    {"name": "KMS-1", "role": "KMS"},
]


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import topology  # noqa: PLC0415

    return {"tp": topology}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _estate(modules: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    tp = modules["tp"]
    claims = tp.from_hops(HOPS, CERTIFICATES, KEYS)
    body = tp.build([*claims["claims"], *DECLARED], nodes=NODES)
    return body, claims


def row_the_vocabulary(modules: dict[str, Any]) -> dict[str, Any]:
    tp = modules["tp"]
    body, _ = _estate(modules)
    probes = [
        _probe("the-nine-kinds-are-the-whole-vocabulary",
               tp.KINDS == ("CONNECTS_TO", "ROUTES_TO", "TERMINATES_TLS", "RE_ENCRYPTS",
                            "PASSTHROUGH", "PROTECTED_BY", "USES_CERTIFICATE",
                            "USES_HSM", "USES_KMS"),
               ", ".join(tp.KINDS)),
        _probe("a-kind-outside-the-vocabulary-is-refused",
               "not one of the nine" in tp.build(
                   [{"kind": "MAGIC", "from": "a", "to": "b", "evidence_id": "E",
                     "observed_at": "2026-11-01T00:00:00Z", "source": "s"}]
               )["refused"][0]["reason"],
               "MAGIC is not a relationship"),
        _probe("every-written-edge-carries-the-four-required-fields",
               all(edge["evidence_id"] and edge["observed_at"] and edge["source"]
                   and edge["confidence"] in tp.CONFIDENCE for edge in body["edges"]),
               f"{len(body['edges'])} edge(s), each with evidence, time, source and "
               "confidence"),
        _probe("the-kinds-present-and-absent-are-both-named",
               set(body["counts"]) <= set(tp.KINDS)
               and "RE_ENCRYPTS" in body["kinds_unused"],
               f"used {sorted(body['counts'])}; unused {len(body['kinds_unused'])}"),
        _probe("the-topology-states-what-an-edge-does-not-mean",
               any("permitted flow" in line for line in tp.NOT_PROVEN)
               and any("packet capture" in line for line in tp.NOT_PROVEN),
               f"{len(tp.NOT_PROVEN)} stated limit(s)"),
    ]
    return {"id": "the_vocabulary",
            "question": "is every relationship one of the nine, with its provenance?",
            "phase": "review 12", "probes": probes}


def row_confidence(modules: dict[str, Any]) -> dict[str, Any]:
    tp = modules["tp"]
    body, _ = _estate(modules)
    overclaim = tp.build([{"kind": "CONNECTS_TO", "from": "a", "to": "b",
                           "evidence_id": "E-1", "observed_at": "2026-11-01T00:00:00Z",
                           "source": "cmdb", "evidence_class": "DECLARED",
                           "confidence": "OBSERVED"}])
    probes = [
        _probe("confidence-is-derived-from-the-evidence-class",
               body["confidence"]["OBSERVED"] == 10
               and body["confidence"]["DECLARED"] == 4,
               f"{body['confidence']['OBSERVED']} observed, "
               f"{body['confidence']['DECLARED']} declared"),
        _probe("a-handshake-behind-an-edge-makes-it-observed",
               all(edge["confidence"] == "OBSERVED" for edge in body["edges"]
                   if edge["kind"] in {"CONNECTS_TO", "TERMINATES_TLS",
                                       "USES_CERTIFICATE"}),
               "network observations stay observed"),
        _probe("an-inventory-binding-is-declared-not-observed",
               {edge["kind"]: edge["confidence"] for edge in body["edges"]
                if edge["kind"] in {"USES_HSM", "USES_KMS", "PROTECTED_BY", "ROUTES_TO"}}
               == {"USES_HSM": "DECLARED", "USES_KMS": "DECLARED",
                   "PROTECTED_BY": "DECLARED", "ROUTES_TO": "DECLARED"},
               "four declared edges, four declared confidences"),
        _probe("a-claim-that-calls-itself-observed-is-corrected-and-flagged",
               overclaim["edges"][0]["confidence"] == "DECLARED"
               and overclaim["overclaimed"]
               and "called themselves observed" in overclaim["statement"],
               "the caller may under-claim, never over-claim"),
        _probe("an-edge-with-no-evidence-is-not-drawn",
               tp.build([{"kind": "CONNECTS_TO", "from": "a", "to": "b"}])["edges"] == [],
               "an uncited relationship is fiction"),
    ]
    return {"id": "confidence",
            "question": "who decides how strongly an edge is asserted?",
            "phase": "review 12", "probes": probes}


def row_the_two_gates(modules: dict[str, Any]) -> dict[str, Any]:
    tp = modules["tp"]
    base = {"evidence_id": "NET-9", "observed_at": "2026-11-01T00:00:00Z",
            "source": "network-probe", "evidence_class": "NETWORK_OBSERVED"}
    reenc = tp.build([{**base, "kind": "RE_ENCRYPTS", "from": "External LB",
                       "to": "Internal LB"}])
    reenc_ok = tp.build([{**base, "kind": "RE_ENCRYPTS", "from": "External LB",
                          "to": "Internal LB",
                          "handshakes": [{"evidence_id": "NET-1"},
                                         {"evidence_id": "NET-2"}]}])
    pass_no_session = tp.build([{**base, "kind": "PASSTHROUGH", "from": "External LB",
                                 "to": "Internal LB"}])
    pass_ok = tp.build([{**base, "kind": "PASSTHROUGH", "from": "External LB",
                         "to": "Internal LB", "session_id": "TLS-SESS-9"}])
    probes = [
        _probe("re-encryption-without-two-handshakes-is-refused",
               reenc["edges"] == []
               and "two handshakes in one path" in reenc["refused"][0]["reason"],
               reenc["refused"][0]["reason"]),
        _probe("re-encryption-with-a-decrypt-and-a-new-encrypt-is-written",
               reenc_ok["edges"] and reenc_ok["edges"][0]["kind"] == "RE_ENCRYPTS",
               "two handshakes, one path"),
        _probe("passthrough-without-a-session-identifier-is-refused",
               pass_no_session["edges"] == []
               and "session identifier" in pass_no_session["refused"][0]["reason"],
               "a scanner sees two handshakes and cannot tell the difference"),
        _probe("passthrough-with-the-same-session-on-both-hops-is-written",
               pass_ok["edges"] and pass_ok["edges"][0]["kind"] == "PASSTHROUGH",
               "TLS-SESS-9 continued"),
        _probe("neither-gate-is-satisfied-by-the-chain-guide-s-assembled-evidence",
               "RE_ENCRYPTS" not in {edge["kind"] for edge in _estate(modules)[0]["edges"]},
               "the estate contains no re-encryption claim, so none is drawn"),
    ]
    return {"id": "the_two_gates",
            "question": "which claims need more than one observation, and is that enforced?",
            "phase": "review 12", "probes": probes}


def row_the_audit(modules: dict[str, Any]) -> dict[str, Any]:
    tp = modules["tp"]
    body, _ = _estate(modules)
    clean = tp.audit(body)
    misattributed = tp.build([{**HOPS[0], "kind": "TERMINATES_TLS", "from": "Internet",
                               "to": "Payments API", "evidence_id": "NET-1",
                               "observed_at": "2026-11-01T00:00:00Z",
                               "source": "network-probe",
                               "evidence_class": "NETWORK_OBSERVED"}],
                            nodes=[{"name": "Internet", "role": "LOAD_BALANCER"},
                                   {"name": "Payments API", "role": "APPLICATION"}])
    probes = [
        _probe("an-honest-topology-audits-clean-and-says-so",
               clean["clean"] is True and "internally honest" in clean["statement"],
               clean["statement"]),
        _probe("a-terminating-device-s-tls-read-as-the-application-s-is-a-finding",
               tp.audit(misattributed, applications=["payments api"])["counts"]
               == {"TLS_ATTRIBUTED_TO_AN_APPLICATION": 1},
               "a load balancer's TLS 1.3 never becomes the application's property"),
        _probe("a-node-that-appears-only-because-an-edge-names-it-is-flagged",
               "UNDECLARED_NODE" in tp.audit(
                   tp.build([{**HOPS[0], "kind": "CONNECTS_TO", "from": "External LB",
                              "to": "payments.bank.example:8443",
                              "evidence_id": "NET-1",
                              "observed_at": "2026-11-01T00:00:00Z",
                              "source": "network-probe",
                              "evidence_class": "NETWORK_OBSERVED"}],
                           nodes=[{"name": "External LB", "role": "LOAD_BALANCER"}])
               )["counts"],
               "an unnamed node is a hole in the inventory"),
        _probe("the-audit-refuses-a-document-that-is-not-a-topology",
               _raises(lambda: tp.audit({"edges": []}), "not a"),
               "a foreign document is rejected, not audited"),
        _probe("the-summary-reports-the-observed-share-and-the-unused-kinds",
               tp.summary(body)["observed_share"] == round(10 / 14, 2)
               and "RE_ENCRYPTS" in tp.summary(body)["unused_kinds"],
               f"observed share {tp.summary(body)['observed_share']}"),
    ]
    return {"id": "the_audit",
            "question": "can the topology be read back and found honest?",
            "phase": "review 12", "probes": probes}


def row_from_observations(modules: dict[str, Any]) -> dict[str, Any]:
    tp = modules["tp"]
    body, claims = _estate(modules)
    silent = tp.from_hops([{"from": "a", "to": "b", "cipher_suite": "AES128-SHA"}])
    probes = [
        _probe("hops-and-certificates-become-claims-with-their-own-evidence",
               claims["claims"] and all(claim["evidence_id"] and claim["observed_at"]
                                        for claim in claims["claims"]),
               claims["statement"]),
        _probe("an-observation-that-saw-nothing-derives-no-claim",
               silent["claims"] == [],
               "a hop with no evidence id produces nothing"),
        _probe("a-certificate-presentation-becomes-a-use-edge",
               "USES_CERTIFICATE" in body["counts"]
               and {edge["to"] for edge in body["edges"]
                    if edge["kind"] == "USES_CERTIFICATE"} == {"CERT-9281", "CERT-9282"},
               "two presentations, two edges"),
        _probe("an-hsm-and-a-kms-binding-are-two-kinds-not-one",
               {"USES_HSM", "USES_KMS"} <= set(body["counts"]),
               "HSM-1 and KMS-1 are different questions"),
        _probe("a-claim-with-one-end-missing-is-refused",
               "needs both ends" in tp.build(
                   [{"kind": "CONNECTS_TO", "from": "Internet",
                     "evidence_id": "NET-1", "observed_at": "2026-11-01T00:00:00Z",
                     "source": "network-probe"}])["refused"][0]["reason"],
               "half an edge is not an edge"),
    ]
    return {"id": "from_observations",
            "question": "does the topology come from evidence rather than from wishes?",
            "phase": "review 12", "probes": probes}


def _raises(call, needle: str) -> bool:
    try:
        call()
    except ValueError as exc:
        return needle in str(exc)
    return False


ROWS = (row_the_vocabulary, row_confidence, row_the_two_gates, row_the_audit,
        row_from_observations)


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
    body, claims = _estate(modules)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "kinds": list(tp.KINDS),
        "confidences": list(tp.CONFIDENCE),
        "required_fields": list(tp.REQUIRED),
        "claims": claims,
        "topology": body,
        "audit": tp.audit(body),
        "summary": tp.summary(body),
        "rows": rows,
        "limits": [
            "the topology contains what was collected. A device nobody probed is "
            "absent, and absence is not the same as disconnected",
            "`CONNECTS_TO` is reachability observed by an authorized scanner, not an "
            "approved flow: no firewall policy, no proxy configuration and no ACL is "
            "read here",
            "`PASSTHROUGH` rests on the same session identifier appearing on both hops "
            "in one collector's view. It is stronger than a guess and weaker than a "
            "packet capture, and it says nothing about what the device inspects",
            "`PROTECTED_BY` is a position in a path. A WAF that sits in front of an "
            "application may inspect nothing, and this model cannot tell",
            "confidence describes the evidence, not the certainty of the network's "
            "behaviour: an `OBSERVED` edge was observed once, and a once-observed path "
            "can be decommissioned the same afternoon",
            "the nine kinds are fixed. A relationship that does not fit them is "
            "refused rather than given a new name, so the vocabulary cannot drift into "
            "one kind per collector",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    topology = report["topology"]
    summary = report["summary"]
    lines = [
        "# Network topology as relationships that carry their own evidence",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review item 12: every relationship needs `evidence_id`, `observed_at`, "
        "`source` and `confidence` — otherwise the topology is fiction. Here the fourth "
        "is derived from the first three, and an edge that cannot carry all four is not "
        "drawn.",
        "",
        "```",
        "claim ──▶ evidence_id · observed_at · source ──▶ confidence (derived)",
        "                                              └─ no evidence ⇒ refused, not drawn",
        "```",
        "",
        f"{topology['statement']}",
        "",
        f"Audit: {report['audit']['statement']}",
        "",
        "| kind | what it may claim | typical confidence |",
        "|---|---|---|",
        "| `CONNECTS_TO` | a connection was made | `OBSERVED` |",
        "| `ROUTES_TO` | a path was declared or observed | `DECLARED` |",
        "| `TERMINATES_TLS` | this device terminated the handshake | `OBSERVED` |",
        "| `RE_ENCRYPTS` | decrypt **and** a new handshake downstream | `OBSERVED`, gate |",
        "| `PASSTHROUGH` | one session continued | `OBSERVED`, gate |",
        "| `PROTECTED_BY` | a device sits in front | `DECLARED` |",
        "| `USES_CERTIFICATE` | this endpoint presented this certificate | `OBSERVED` |",
        "| `USES_HSM` / `USES_KMS` | an inventory binding | `DECLARED` |",
        "",
        "| field | source |",
        "|---|---|",
        "| `evidence_id` | required — an uncited edge is fiction |",
        "| `observed_at` | required — an observation without a moment is a claim |",
        "| `source` | required — the collector or register that produced it |",
        "| `confidence` | **derived** from the evidence class, never supplied |",
        "",
        f"Observed share: {summary['observed_share']} · unused kinds: "
        f"{', '.join(summary['unused_kinds']) or 'none'}",
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
