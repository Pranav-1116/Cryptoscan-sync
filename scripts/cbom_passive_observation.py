#!/usr/bin/env python3
"""Guide 163 — passive observation, with the privacy contract enforced in code.

Review item 15 asks for passive observation and gates it on a privacy contract. This guide
implements the contract as a check that runs **before** a record is accepted:
`cbom.passive_observation` refuses a capture containing a prohibited field, a field it
cannot classify, or a field the contract does not list, instead of quietly stripping them.

The two things a passive collector usually gets wrong are modelled as failures:
**pseudonyms without a per-deployment salt** (a fixed salt makes an address a global
identifier) and **observations that outlive their retention** (an inventory citing a
two-year-old capture is worse than one that admits it has nothing).
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
SCHEMA = "cryptoscan.cbom-passive-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

CONTRACT = dict(
    contract_id="DPC-2026-01",
    owner="dpo@bank.example",
    purposes=["CRYPTO_INVENTORY", "WEAK_PROTOCOL_DETECTION"],
    lawful_basis="legitimate interest: protecting the bank's own network",
    salt_id="salt-2026q4",
    reviewed_at="2026-10-28",
    collects=["dst", "dst_port", "protocol", "tls_version", "cipher_suite", "kex_group",
              "signature_algorithm", "certificate_sha256", "certificate_key_type",
              "certificate_key_bits", "first_seen", "last_seen",
              "bytes_client_to_server", "bytes_server_to_client", "evidence_id",
              "client_address", "server_name", "ja3"],
)

PAYMENTS = {
    "evidence_id": "CAP-1", "dst": "10.20.1.10", "dst_port": 443, "protocol": "tls",
    "tls_version": "TLSv1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "kex_group": "x25519", "signature_algorithm": "sha256WithRSAEncryption",
    "certificate_sha256": "ab" * 32, "certificate_key_type": "RSA",
    "certificate_key_bits": 2048,
    "first_seen": "2026-11-01T00:00:00Z", "last_seen": "2026-11-01T00:10:00Z",
    "bytes_client_to_server": 48213, "bytes_server_to_client": 918442,
    "client_address": "10.30.4.51", "server_name": "payments.bank.example",
    "ja3": "ab12f0c1b2",
}
PORTAL = {
    "evidence_id": "CAP-2", "dst": "10.20.1.11", "dst_port": 443, "protocol": "tls",
    "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "kex_group": "x25519", "certificate_sha256": "cd" * 32,
    "certificate_key_type": "EC", "certificate_key_bits": 256,
    "first_seen": "2026-11-02T00:00:00Z", "last_seen": "2026-11-02T00:20:00Z",
    "bytes_client_to_server": 5120, "bytes_server_to_client": 88210,
}
LEGACY = {
    "evidence_id": "CAP-3", "dst": "10.20.1.12", "dst_port": 443, "protocol": "tls",
    "tls_version": "TLSv1.0", "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "kex_group": "secp256r1", "certificate_key_type": "RSA",
    "certificate_key_bits": 1024,
    "first_seen": "2026-10-30T00:00:00Z", "last_seen": "2026-10-30T00:05:00Z",
    "client_address": "10.30.9.9",
}
STALE = {
    "evidence_id": "CAP-OLD", "dst": "10.20.1.13", "dst_port": 443, "protocol": "tls",
    "tls_version": "TLSv1.1", "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "first_seen": "2026-01-01T00:00:00Z", "last_seen": "2026-01-02T00:00:00Z",
}
AS_OF = "2026-11-03T00:00:00Z"
CAPTURES = [PAYMENTS, PORTAL, LEGACY, STALE]


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import passive_observation  # noqa: PLC0415

    return {"po": passive_observation}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _raises(call, needle: str) -> bool:
    try:
        call()
    except ValueError as exc:
        return needle in str(exc)
    return False


def _privacy(po, **overrides):
    return po.contract(**{**CONTRACT, **overrides})


def row_the_contract(modules: dict[str, Any]) -> dict[str, Any]:
    po = modules["po"]
    body = _privacy(po)
    bare = po.contract()
    probes = [
        _probe("a-contract-that-cannot-be-checked-is-not-enforceable",
               bare["enforceable"] is False and len(bare["problems"]) >= 4,
               f"{len(bare['problems'])} problem(s) on an empty contract"),
        _probe("a-complete-contract-names-owner-purpose-and-retention",
               body["enforceable"] is True
               and "CRYPTO_INVENTORY" in body["statement"]
               and "90d metadata / 30d pseudonymous" in body["statement"],
               body["statement"]),
        _probe("a-prohibited-field-cannot-be-contracted-for",
               _privacy(po, collects=[*CONTRACT["collects"], "payload"])["enforceable"]
               is False,
               "payload is refused at contract time, not at capture time"),
        _probe("pseudonymous-data-may-not-outlive-metadata",
               _privacy(po, retention_days={"METADATA": 30, "PSEUDONYMOUS": 90})
               ["enforceable"] is False,
               "retention is per class and the shorter one is the binding one"),
        _probe("collecting-a-pseudonym-needs-a-deployment-salt-id",
               _privacy(po, salt_id=None)["enforceable"] is False,
               "without a salt id the pseudonym would be a global identifier"),
    ]
    return {"id": "the_contract",
            "question": "is the privacy contract a check rather than a paragraph?",
            "phase": "review 15", "probes": probes}


def row_enforcement(modules: dict[str, Any]) -> dict[str, Any]:
    po = modules["po"]
    privacy = _privacy(po)
    probes = [
        _probe("a-clean-capture-is-accepted",
               po.observe(PAYMENTS, privacy=privacy, salt="k")["evidence_id"] == "CAP-1",
               "handshake metadata only"),
        _probe("payload-is-refused-rather-than-stripped",
               _raises(lambda: po.observe({**PAYMENTS, "payload": "GET /"},
                                          privacy=privacy, salt="k"), "prohibited"),
               "a sanitise() that quietly drops it would teach the schema to accept it"),
        _probe("an-unclassifiable-field-is-refused",
               _raises(lambda: po.observe({**PAYMENTS, "session_ticket": "x"},
                                          privacy=privacy, salt="k"), "cannot classify"),
               "unknown is not the same as harmless"),
        _probe("a-field-outside-the-contract-is-refused",
               _raises(lambda: po.observe({**PAYMENTS, "bytes_client_to_server": 1,
                                           "packets": 9}, privacy=_privacy(
                   po, collects=[name for name in CONTRACT["collects"]
                                 if name != "packets"]), salt="k"),
                       "outside the contract"),
               "the contract lists what may be collected and the collector adds nothing"),
        _probe("a-capture-without-an-evidence-id-is-refused",
               _raises(lambda: po.observe({k: v for k, v in PAYMENTS.items()
                                           if k != "evidence_id"},
                                          privacy=privacy, salt="k"), "evidence"),
               "a capture with no record is a claim"),
    ]
    return {"id": "enforcement",
            "question": "are prohibited fields refused visibly instead of dropped?",
            "phase": "review 15", "probes": probes}


def row_pseudonyms(modules: dict[str, Any]) -> dict[str, Any]:
    po = modules["po"]
    privacy = _privacy(po)
    one = po.observe(PAYMENTS, privacy=privacy, salt="salt-one")
    two = po.observe(PAYMENTS, privacy=privacy, salt="salt-two")
    probes = [
        _probe("an-address-becomes-a-keyed-pseudonym-and-the-raw-value-never-lands",
               one["fields"]["client_address"].startswith("p-")
               and "10.30.4.51" not in json.dumps(one),
               one["fields"]["client_address"]),
        _probe("two-deployments-cannot-join-their-pseudonyms",
               one["fields"]["client_address"] != two["fields"]["client_address"],
               "different salt, different pseudonym"),
        _probe("the-salt-id-is-recorded-and-the-salt-is-not",
               one["pseudonym_salt"] == "salt-2026q4"
               and "salt-one" not in json.dumps(one),
               "the record can be audited without holding the secret"),
        _probe("a-pseudonym-without-a-salt-is-refused",
               _raises(lambda: po.observe(PAYMENTS, privacy=privacy, salt=None),
                       "no salt was supplied"),
               "better a refusal than a raw address in the store"),
        _probe("metadata-stays-readable-so-the-inventory-is-still-useful",
               one["fields"]["dst"] == "10.20.1.10"
               and one["fields"]["cipher_suite"] ==
               "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
               "the cryptography is the point; the client is not"),
    ]
    return {"id": "pseudonyms",
            "question": "can an address be followed across records without being stored?",
            "phase": "review 15", "probes": probes}


def row_retention(modules: dict[str, Any]) -> dict[str, Any]:
    po = modules["po"]
    body = po.estate(CAPTURES, privacy=_privacy(po), salt="k", as_of=AS_OF)
    live = [row for row in body["observations"] if not row["expired"]]
    probes = [
        _probe("an-observation-expires-with-its-shortest-lived-field",
               next(row for row in body["observations"]
                    if row["evidence_id"] == "CAP-1")["expires_with"] == "PSEUDONYMOUS",
               "30 days, because a pseudonym lives beside the metadata"),
        _probe("an-observation-past-retention-is-marked-expired",
               body["expired"] == ["CAP-OLD"],
               ", ".join(body["expired"])),
        _probe("an-expired-observation-contributes-no-facts",
               all("CAP-OLD" not in fact["evidence_ids"]
                   for fact in po.to_algorithms(body)["facts"]),
               "retention is not a suggestion"),
        _probe("the-live-count-excludes-what-is-no-longer-evidence",
               body["live"] == 3 and len(live) == 3,
               body["statement"]),
        _probe("expiry-is-computed-against-an-explicit-as-of-not-the-wall-clock",
               po.estate(CAPTURES, privacy=_privacy(po), salt="k",
                         as_of="2027-06-01T00:00:00Z")["live"] == 0,
               "the same captures, a later moment, nothing left to cite"),
    ]
    return {"id": "retention",
            "question": "does an observation stop being evidence when its retention ends?",
            "phase": "review 15", "probes": probes}


def row_facts_and_shape(modules: dict[str, Any]) -> dict[str, Any]:
    po = modules["po"]
    privacy = _privacy(po)
    body = po.estate(CAPTURES, privacy=privacy, salt="k", as_of=AS_OF)
    facts = po.to_algorithms(body)
    summary = po.summary(body)
    probes = [
        _probe("a-passive-fact-says-how-it-was-collected",
               all(fact["collection"] == "PASSIVE"
                   and fact["confidence"] == "OBSERVED"
                   and fact["contract_id"] == "DPC-2026-01"
                   for fact in facts["facts"]),
               f"{len(facts['facts'])} fact(s), each citing the contract"),
        _probe("a-passive-fact-is-never-promoted-to-configured",
               "CONFIGURED" not in json.dumps(facts)
               and "DECLARED" not in json.dumps(facts),
               "a tap asked the device nothing"),
        _probe("roles-come-from-the-same-vocabulary-as-the-rest-of-the-platform",
               {fact["role"] for fact in facts["facts"]}
               <= {"PROTOCOL", "BULK", "KEY_EXCHANGE", "SIGNATURE", "MAC"},
               ", ".join(sorted({fact["role"] for fact in facts["facts"]})),
               ),
        _probe("refusals-stay-visible-in-the-estate",
               len(po.estate([PAYMENTS, {**PAYMENTS, "evidence_id": "CAP-9",
                                         "cookie": "session=1"}],
                             privacy=privacy, salt="k")["refused"]) == 1,
               "one accepted, one refused, both counted"),
        _probe("the-report-states-what-a-passive-tap-cannot-prove",
               any("one conversation" in line for line in summary["not_proven"])
               and any("pseudonym" in line for line in summary["not_proven"])
               and any("payload" in line for line in summary["not_proven"]),
               f"{len(summary['not_proven'])} stated limit(s)"),
    ]
    return {"id": "facts_and_shape",
            "question": "does passive collection reach the CBOM without overreach?",
            "phase": "review 15 / 16 boundary", "probes": probes}


ROWS = (row_the_contract, row_enforcement, row_pseudonyms, row_retention,
        row_facts_and_shape)


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
    po = modules["po"]
    privacy = _privacy(po)
    body = po.estate(CAPTURES, privacy=privacy, salt="k", as_of=AS_OF)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "as_of": AS_OF,
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "classes": list(po.CLASSES),
        "fields": dict(po.FIELDS),
        "purposes": list(po.PURPOSES),
        "contract": privacy,
        "estate": body,
        "facts": po.to_algorithms(body),
        "summary": po.summary(body),
        "rows": rows,
        "limits": [
            "one capture is one conversation. A client can negotiate weaker than the "
            "server's policy allows on the next one, so a suite seen is not a policy",
            "a tap sees the traffic on its own span: what is tunnelled past it, off-net "
            "or on a path it does not cover is invisible, not absent",
            "a pseudonym is unlinkable across deployments and still a link inside one: "
            "the same client pseudonym appearing twice is a correlation",
            "the model reads handshake metadata only. It refuses payload, cookies and "
            "authorization headers, so it cannot say what was sent",
            "certificate validity is not derived from a fingerprint; the chain is "
            "guide 159's subject",
            "the contract is a technical check on the collector, not a legal opinion. "
            "An owner must still decide the lawful basis and sign it",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    body = report["estate"]
    contract = report["contract"]
    fields = report["fields"]
    lines = [
        "# Passive observation, with the privacy contract enforced in code",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · as of "
        f"{report['as_of']} · **{counts[VERDICT_PASS]} pass · "
        f"{counts[VERDICT_PARTIAL]} partial · {counts[VERDICT_FAIL]} fail** · "
        f"{report['probes']} probes",
        "",
        "Review item 15: cryptography recorded from traffic the estate already sends, "
        "gated on a privacy contract that is checked **before** a record is accepted.",
        "",
        "```",
        "capture ──▶ field known?  ──no──▶ refuse (unclassifiable)",
        "             │yes",
        "             ▼",
        "        prohibited?     ──yes─▶ refuse (never even stripped)",
        "             │no",
        "             ▼",
        "        in the contract? ──no──▶ refuse (the collector adds nothing)",
        "             │yes",
        "             ▼  pseudonymous ⇒ keyed hash, raw value discarded",
        "        observation: OBSERVED · contract · expiry",
        "```",
        "",
        contract["statement"],
        "",
        "| class | fields |",
        "|---|---|",
    ]
    for cls in report["classes"]:
        names = sorted(name for name, value in fields.items() if value == cls)
        lines.append(f"| `{cls}` | {', '.join(f'`{name}`' for name in names)} |")
    lines += [
        "",
        f"Live observations: {body['live']} · expired: "
        f"{', '.join(body['expired']) or 'none'} · refused: {len(body['refused'])}",
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
