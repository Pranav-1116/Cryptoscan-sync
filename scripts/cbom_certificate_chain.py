#!/usr/bin/env python3
"""Guide 159 — endpoint → certificate → key → signature → issuer → trust chain.

Review item 9:

    Endpoint → certificate → public key → algorithm → key size/curve → signature
    algorithm → issuer → validity → trust chain, e.g. CERT-9281 with ECDSA P-256,
    ECDSA-SHA256, issuer BANK-ICA-01, expiry, SAN. Better evidence for CBOM and PKI
    intelligence.

The certificate was already a record; what was missing is the **chain** — which
certificate signed which, where the path stops, and whether the stop is an anchor or a
hole. Two lines keep it honest: the path is assembled from names and key identifiers
and **no signature is verified**, so an anchored path is a shape and not a trust
decision; and an issuer that is absent from the inventory is a **collection gap**, not
a root.
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
SCHEMA = "cryptoscan.certificate-chain-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)

LEAF = {
    "certificate_ref": "CERT-9281", "subject": "CN=payments.bank.example",
    "issuer": "CN=BANK-ICA-01", "serial": "0A1B2C",
    "fingerprint_sha256": "aa11bb22cc33dd44",
    "san": ["payments.bank.example"], "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2027-01-01T00:00:00Z", "public_key_algorithm": "ECDSA",
    "key_size": 256, "curve": "P-256", "signature_algorithm": "ECDSA-SHA256",
    "authority_key_id": "ski-ica", "endpoint": "payments.bank.example:443",
    "evidence_id": "CERT-E1", "source": "network-probe",
    "observed_at": "2026-11-01T00:00:00Z",
}
INTERMEDIATE = {
    "certificate_ref": "CERT-ICA1", "subject": "CN=BANK-ICA-01",
    "issuer": "CN=BANK-ROOT-01", "is_ca": True, "not_before": "2020-01-01T00:00:00Z",
    "not_after": "2030-01-01T00:00:00Z", "public_key_algorithm": "RSA", "key_size": 4096,
    "signature_algorithm": "SHA256-RSA", "subject_key_id": "ski-ica",
    "evidence_id": "CERT-E2", "source": "pki-export",
}
ROOT_CA = {
    "certificate_ref": "CERT-ROOT", "subject": "CN=BANK-ROOT-01",
    "issuer": "CN=BANK-ROOT-01", "is_ca": True, "not_after": "2035-01-01T00:00:00Z",
    "public_key_algorithm": "RSA", "key_size": 4096, "signature_algorithm": "SHA256-RSA",
    "evidence_id": "CERT-E3", "source": "pki-export",
}
ORPHAN = {
    "certificate_ref": "CERT-ORPHAN", "subject": "CN=partner.bank.example",
    "issuer": "CN=PARTNER-CA-01", "not_after": "2027-06-01T00:00:00Z",
    "public_key_algorithm": "RSA", "key_size": 2048, "signature_algorithm": "SHA256-RSA",
    "endpoint": "partner.bank.example:443", "evidence_id": "CERT-E4",
    "source": "network-probe",
}
EXPIRING = {
    "certificate_ref": "CERT-SOON", "subject": "CN=legacy.bank.example",
    "issuer": "CN=BANK-ICA-01", "not_after": "2026-11-20T00:00:00Z",
    "not_before": "2025-11-20T00:00:00Z", "public_key_algorithm": "RSA", "key_size": 1024,
    "signature_algorithm": "SHA1-RSA", "authority_key_id": "ski-ica",
    "endpoint": "legacy.bank.example:443", "evidence_id": "CERT-E5",
    "source": "network-probe",
}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import certificate_chain, usage_evidence  # noqa: PLC0415

    return {"cc": certificate_chain, "ue": usage_evidence}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _estate(modules: dict[str, Any]) -> dict[str, Any]:
    return modules["cc"].chain([LEAF, INTERMEDIATE, ROOT_CA, ORPHAN, EXPIRING],
                               anchors=["CERT-ROOT"], now=NOW)


def row_the_hop(modules: dict[str, Any]) -> dict[str, Any]:
    cc, ue = modules["cc"], modules["ue"]
    body = cc.certificate(LEAF, now=NOW)
    evidence = ue.certificate_evidence(LEAF)
    probes = [
        _probe("one-certificate-carries-every-field-the-review-names",
               body["public_key"]["algorithm"] == "ECDSA"
               and body["public_key"]["key_size"] == 256
               and body["public_key"]["curve"] == "P-256"
               and body["signature_algorithm"] == "ECDSA-SHA256"
               and body["issuer"] == "CN=BANK-ICA-01"
               and body["days_to_expiry"] > 0 and body["san"] == ["payments.bank.example"],
               f"{body['certificate_ref']} · ECDSA P-256 · ECDSA-SHA256 · "
               f"{body['issuer']} · {body['state']}"),
        _probe("the-endpoint-it-was-observed-on-travels-with-it",
               body["endpoints"] == ["payments.bank.example:443"]
               and body["source"] == "network-probe"
               and body["observed_at"] == "2026-11-01T00:00:00Z",
               "an endpoint, a source and a time on every hop"),
        _probe("validity-is-a-state-with-a-number-not-a-boolean",
               body["state"] == "VALID" and body["days_to_expiry"] > 30
               and "valid for" in body["state_note"],
               body["state_note"]),
        _probe("revocation-is-unknown-and-says-so",
               body["revocation"] == "UNKNOWN"
               and any("revoked" in line for line in cc.NOT_PROVEN),
               "no OCSP and no CRL is consulted here"),
        _probe("the-certificate-key-never-becomes-the-application-s-algorithm",
               evidence["application_operation_proven"] is False
               and evidence["usage"] == "CERTIFICATE_ONLY",
               evidence["statement"][:96] + "…"),
        _probe("no-private-material-is-stored",
               body["private_material"] == "NOT_STORED"
               and "PRIVATE KEY" not in json.dumps(body).upper(),
               body["private_material"]),
    ]
    return {"id": "the_hop",
            "question": "does one certificate answer the review's whole chain question?",
            "phase": "review 9", "probes": probes}


def row_the_chain(modules: dict[str, Any]) -> dict[str, Any]:
    cc = modules["cc"]
    estate = _estate(modules)
    leaf = next(path for path in estate["paths"]
                if path["certificate_ref"] == "CERT-9281")
    probes = [
        _probe("the-leaf-resolves-to-a-root-through-its-intermediate",
               leaf["resolution"] == "ANCHORED" and leaf["depth"] == 3
               and [hop["certificate_ref"] for hop in leaf["path"]]
               == ["CERT-9281", "CERT-ICA1", "CERT-ROOT"],
               leaf["statement"]),
        _probe("the-issuer-is-matched-by-key-id-first-and-name-second",
               leaf["matched_by"][0] == "AUTHORITY_KEY_ID"
               and "ISSUER_NAME" in leaf["matched_by"],
               ", ".join(leaf["matched_by"])),
        _probe("an-anchored-path-is-called-anchored-and-never-trusted",
               estate["resolutions"].get("ANCHORED") == 4
               and "anchored" in estate["statement"].lower()
               and "TRUSTED" not in json.dumps(estate),
               "a shape, not a trust decision"),
        _probe("a-certificate-whose-issuer-is-absent-is-a-hole",
               [path for path in estate["paths"]
                if path["certificate_ref"] == "CERT-ORPHAN"][0]["resolution"]
               == "INCOMPLETE",
               [path["missing_issuer"] for path in estate["paths"]
                if path["resolution"] == "INCOMPLETE"][0]),
        _probe("an-unconfirmed-root-is-listed-as-an-unconfirmed-anchor",
               estate["anchors_unconfirmed"] == []
               and cc.chain([LEAF, INTERMEDIATE, ROOT_CA], now=NOW)[
                   "anchors_unconfirmed"] == ["CERT-ROOT"],
               "declaring CERT-ROOT removes it from the unconfirmed list"),
        _probe("the-chain-states-that-no-signature-was-verified",
               "no signature was verified" in estate["statement"],
               estate["statement"][-82:]),
    ]
    return {"id": "the_chain",
            "question": "is a path a path, or a claim that the path is trusted?",
            "phase": "review 9", "probes": probes}


def row_what_the_chain_finds(modules: dict[str, Any]) -> dict[str, Any]:
    cc = modules["cc"]
    estate = _estate(modules)
    summary = cc.summary(estate)
    soon = estate["certificates"]["CERT-SOON"]
    probes = [
        _probe("an-expiring-certificate-is-a-state-with-a-date",
               soon["state"] == "EXPIRING" and soon["days_to_expiry"] == 17
               and "expires in 17 day(s)" in soon["state_note"],
               soon["state_note"]),
        _probe("a-1024-bit-key-and-a-sha1-signature-are-both-reported",
               {"WEAK_KEY", "WEAK_SIGNATURE"} <= {problem["kind"]
                                                 for problem in soon["problems"]},
               ", ".join(problem["kind"] for problem in soon["problems"])),
        _probe("quantum-exposure-is-marked-per-certificate-without-a-verdict",
               "CERT-9281" in summary["quantum_vulnerable"]
               and all(problem["kind"] == "QUANTUM_VULNERABLE"
                       for problem in estate["certificates"]["CERT-9281"]["problems"]),
               f"{len(summary['quantum_vulnerable'])} certificate(s) depend on a "
               "broken-by-Shor assumption"),
        _probe("the-summary-names-what-is-expiring-and-what-is-incomplete",
               summary["expiring"] == ["CERT-SOON"]
               and summary["incomplete"] == ["CERT-ORPHAN"],
               f"expiring {summary['expiring']} · incomplete {summary['incomplete']}"),
        _probe("a-missing-expiry-is-a-collection-gap-not-a-pass",
               "collection gap" in cc.certificate({**LEAF, "not_after": None},
                                                  now=NOW)["state_note"],
               "an absent notAfter is unknown"),
    ]
    return {"id": "what_the_chain_finds",
            "question": "does the chain turn into PKI findings a team can act on?",
            "phase": "review 9", "probes": probes}


def row_the_edges(modules: dict[str, Any]) -> dict[str, Any]:
    cc = modules["cc"]
    estate = _estate(modules)
    edges = cc.edges(estate)
    uses = [edge for edge in edges["edges"] if edge["kind"] == "USES_CERTIFICATE"]
    signed = [edge for edge in edges["edges"] if edge["kind"] == "SIGNED_BY"]
    probes = [
        _probe("every-edge-carries-evidence-source-and-confidence",
               all(edge["evidence_id"] and edge["source"]
                   and edge["confidence"] in {"OBSERVED", "ASSEMBLED"}
                   and (edge["confidence"] == "ASSEMBLED" or edge["observed_at"])
                   for edge in edges["edges"]),
               f"{len(edges['edges'])} edge(s); an OBSERVED edge also carries its time"),
        _probe("a-certificate-presented-by-an-endpoint-is-an-observed-edge",
               all(edge["confidence"] == "OBSERVED" for edge in uses)
               and "payments.bank.example:443" in {edge["from"] for edge in uses},
               ", ".join(sorted({edge["from"] for edge in uses}))),
        _probe("a-signature-edge-is-assembled-and-says-it-was-not-verified",
               all(edge["confidence"] == "ASSEMBLED" for edge in signed)
               and all("not verified" in edge["detail"] for edge in signed),
               f"{len(signed)} assembled edge(s)"),
        _probe("a-missing-issuer-is-a-hole-rather-than-a-drawn-edge",
               any(row["confidence"] == "ABSENT" and row["to"] == "CN=PARTNER-CA-01"
                   for row in edges["refused"])
               and "reported as holes" in edges["statement"],
               edges["statement"]),
        _probe("a-presentation-with-no-observation-time-is-not-written",
               any(row["confidence"] == "UNTIMED" for row in edges["refused"])
               and "no observation time" in edges["statement"],
               "an OBSERVED edge without a moment is a claim, not evidence"),
        _probe("an-edge-is-not-duplicated-once-per-descendant",
               len({(edge["from"], edge["to"]) for edge in edges["edges"]})
               == len(edges["edges"]),
               f"{len(edges['edges'])} unique edge(s)"),
    ]
    return {"id": "the_edges",
            "question": "does the chain become topology without inventing an edge?",
            "phase": "review 9 / 12 boundary", "probes": probes}


def row_shape(modules: dict[str, Any]) -> dict[str, Any]:
    cc = modules["cc"]
    refused = cc.chain([LEAF, "not a certificate", {"certificate_ref": "CERT-X"}], now=NOW)
    probes = [
        _probe("a-certificate-with-no-reference-is-refused",
               _raises(lambda: cc.certificate({"subject": "CN=x", "evidence_id": "E"},
                                              now=NOW), "needs a reference"),
               "a chain cannot cite a certificate it cannot name"),
        _probe("a-certificate-with-no-evidence-is-refused",
               _raises(lambda: cc.certificate({"certificate_ref": "CERT-1"}, now=NOW),
                       "no evidence id"),
               "an uncited hop is not evidence"),
        _probe("a-non-certificate-is-refused-rather-than-coerced",
               len(refused["refused"]) == 2, refused["statement"]),
        _probe("the-chain-refuses-a-document-that-is-not-a-chain",
               _raises(lambda: cc.edges({"paths": []}), "not a"),
               "a foreign document is rejected, not drawn"),
        _probe("two-certificates-sharing-a-public-key-are-reported",
               cc.chain([LEAF, {**LEAF, "certificate_ref": "CERT-COPY",
                                "subject": "CN=other.example"},
                         INTERMEDIATE, ROOT_CA], now=NOW)["shared_public_keys"]
               != {},
               "one key, two certificates"),
        _probe("every-claim-the-chain-cannot-make-is-stated",
               len(cc.NOT_PROVEN) >= 4
               and any("trust" in line for line in cc.NOT_PROVEN)
               and any("revoked" in line for line in cc.NOT_PROVEN),
               f"{len(cc.NOT_PROVEN)} stated limit(s)"),
    ]
    return {"id": "shape",
            "question": "do the refusals say what the chain will not do?",
            "phase": "review 9", "probes": probes}


def _raises(call, needle: str) -> bool:
    try:
        call()
    except ValueError as exc:
        return needle in str(exc)
    return False


ROWS = (row_the_hop, row_the_chain, row_what_the_chain_finds, row_the_edges, row_shape)


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
    cc = modules["cc"]
    estate = _estate(modules)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "positions": list(cc.POSITIONS),
        "states": list(cc.STATES),
        "resolutions": list(cc.RESOLUTIONS),
        "matches": list(cc.MATCHES),
        "estate": estate,
        "edges": cc.edges(estate),
        "summary": cc.summary(estate),
        "rows": rows,
        "limits": [
            "the chain is assembled from subject/issuer names and key identifiers. No "
            "signature is verified, no path-length constraint is enforced and no policy "
            "is consulted, so `ANCHORED` describes a shape and never a trust decision",
            "trust is a property of the relying party's store, which this inventory does "
            "not read. A certificate that chains to the bank's root may still be "
            "rejected by a client that does not carry that root",
            "revocation is unknown on every row: no OCSP response and no CRL is "
            "consulted, and a missing answer is not a good answer",
            "a certificate whose issuer is absent from the inventory stops the path. "
            "That is a collection gap — usually a missing intermediate — and the guide "
            "reports the missing subject rather than treating the last hop as a root",
            "the key-size and signature floors are the model's own, chosen to be "
            "explainable rather than to match any particular regulator's table",
            "two certificates sharing a public key are reported, not explained: key "
            "reuse can be a deliberate staging certificate or a mistake, and telling "
            "them apart needs the PKI's own records",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    summary = report["summary"]
    estate = report["estate"]
    lines = [
        "# Endpoint → certificate → key → signature → issuer → trust chain",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review item 9: the certificate was already a record; the missing piece is the "
        "**chain** — which certificate signed which, where the path stops, and whether "
        "the stop is an anchor or a hole.",
        "",
        "```",
        "endpoint ──USES_CERTIFICATE──▶ leaf ──SIGNED_BY──▶ intermediate ──▶ root",
        "   OBSERVED                    │                     │",
        "                               └── key · signature · validity · SAN · problems",
        "```",
        "",
        f"{estate['statement']}",
        "",
        f"Expiring: {', '.join(summary['expiring']) or 'none'} · incomplete: "
        f"{', '.join(summary['incomplete']) or 'none'} · quantum-vulnerable keys: "
        f"{len(summary['quantum_vulnerable'])}",
        "",
        "| state | meaning |",
        "|---|---|",
        "| `VALID` | more than 30 days left |",
        "| `EXPIRING` | 30 days or fewer |",
        "| `EXPIRED` | past `notAfter` |",
        "| `NOT_YET_VALID` | before `notBefore` |",
        "| `UNKNOWN` | no expiry recorded — a collection gap, not a pass |",
        "",
        "| resolution | meaning |",
        "|---|---|",
        "| `ANCHORED` | the path reached a declared (or self-signed CA) root |",
        "| `INCOMPLETE` | the named issuer is not in the inventory |",
        "| `LOOP` | the issuer name is ambiguous or the path closes on itself |",
        "| `UNRESOLVED` | nothing above this certificate is known |",
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
