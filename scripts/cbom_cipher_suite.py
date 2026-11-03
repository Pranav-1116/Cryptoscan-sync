#!/usr/bin/env python3
"""Guide 158 — a cipher suite is four decisions, and TLS 1.3 names only two of them.

Review item 8:

    `TLS_AES_256_GCM_SHA384` alone is not enough to describe TLS 1.3, because a TLS 1.3
    suite names only the AEAD and the hash. Key exchange and authentication come from
    the handshake — the group agreed, the signature algorithm used, the key in the
    certificate.

Flattening a suite into algorithm names loses the fields a migration question needs.
This guide decomposes a handshake into KEY_EXCHANGE · AUTHENTICATION · ENCRYPTION ·
HASH, records *where each answer came from*, and refuses to fill a gap with the
commonest guess — that a suite with no key-exchange token is RSA key transport.
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
SCHEMA = "cryptoscan.cipher-suite-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

TLS12 = "ECDHE-RSA-AES128-GCM-SHA256"
TLS13 = "TLS_AES_256_GCM_SHA384"
HANDSHAKES = [
    {"endpoint": "payments.bank.example:443", "cipher_suite": TLS13,
     "tls_version": "1.3", "group": "X25519",
     "signature_algorithm": "ECDSA_SECP256R1_SHA256", "evidence_id": "NET-1"},
    {"endpoint": "partner.bank.example:443", "cipher_suite": TLS12,
     "tls_version": "1.2", "evidence_id": "NET-2"},
    {"endpoint": "legacy.bank.example:443", "cipher_suite": "AES128-SHA",
     "tls_version": "1.2", "evidence_id": "NET-3"},
    {"endpoint": "broken.bank.example:443", "cipher_suite": "RC4-SHA",
     "tls_version": "1.2", "evidence_id": "NET-4"},
    {"endpoint": "bare13.bank.example:443", "cipher_suite": TLS13,
     "tls_version": "1.3", "evidence_id": "NET-5"},
]


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import cipher_suite, usage_collectors  # noqa: PLC0415

    return {"cs": cipher_suite, "uc": usage_collectors}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def row_four_dimensions(modules: dict[str, Any]) -> dict[str, Any]:
    cs = modules["cs"]
    twelve = cs.decompose(TLS12, tls_version="1.2")
    thirteen = cs.decompose(TLS13, tls_version="1.3", group="X25519",
                            signature_algorithm="ECDSA_SECP256R1_SHA256")
    bare = cs.decompose(TLS13, tls_version="1.3")
    probes = [
        _probe("a-tls12-suite-names-all-four-dimensions",
               twelve["not_named"] == []
               and twelve["dimensions"]["KEY_EXCHANGE"]["algorithm"] == "ECDHE"
               and twelve["dimensions"]["AUTHENTICATION"]["algorithm"] == "RSA",
               twelve["statement"][:92] + "…"),
        _probe("a-tls13-suite-names-two-and-takes-the-rest-from-the-handshake",
               bare["not_named"] == ["KEY_EXCHANGE", "AUTHENTICATION"]
               and thirteen["not_named"] == []
               and thirteen["dimensions"]["KEY_EXCHANGE"]["evidence"] == "NEGOTIATED",
               "X25519 and ECDSA-P256 arrive from the handshake, not the suite"),
        _probe("every-dimension-records-where-its-answer-came-from",
               {row["evidence"] for row in thirteen["dimensions"].values()}
               == {"NAMED_IN_SUITE", "NEGOTIATED"},
               "named_in_suite for the AEAD and hash, negotiated for the other two"),
        _probe("a-missing-key-exchange-is-unknown-and-not-rsa",
               bare["dimensions"]["KEY_EXCHANGE"]["algorithm"] is None
               and "not RSA" in bare["dimensions"]["KEY_EXCHANGE"]["note"],
               bare["dimensions"]["KEY_EXCHANGE"]["note"]),
        _probe("the-certificate-key-can-supply-the-authentication",
               cs.decompose(TLS13, tls_version="1.3", group="X25519",
                            certificate_key={"algorithm": "RSA", "key_size": 2048}
                            )["dimensions"]["AUTHENTICATION"]["method"]
               == "CERTIFICATE_KEY",
               "the certificate's key is named as the source"),
    ]
    return {"id": "four_dimensions",
            "question": "does one suite string become four decisions with their evidence?",
            "phase": "review 8", "probes": probes}


def row_strength(modules: dict[str, Any]) -> dict[str, Any]:
    cs = modules["cs"]
    rows = {
        "strong": cs.decompose(TLS13, tls_version="1.3", group="X25519"),
        "acceptable": cs.decompose("TLS_RSA_WITH_AES_128_GCM_SHA256", tls_version="1.2"),
        "weak": cs.decompose("AES128-SHA", tls_version="1.2"),
        "broken": cs.decompose("RC4-SHA", tls_version="1.2"),
        "unknown": cs.decompose("FOO-BAR", tls_version="1.2"),
    }
    probes = [
        _probe("an-aead-suite-under-an-ephemeral-group-is-strong",
               rows["strong"]["strength"]["rating"] == "STRONG"
               and rows["strong"]["strength"]["forward_secrecy"] is True
               and rows["strong"]["strength"]["aead"] is True,
               rows["strong"]["strength"]["note"]),
        _probe("no-forward-secrecy-caps-the-rating-without-breaking-it",
               rows["acceptable"]["strength"]["rating"] == "ACCEPTABLE"
               and rows["acceptable"]["strength"]["forward_secrecy"] is False
               and rows["acceptable"]["strength"]["aead"] is True,
               rows["acceptable"]["strength"]["note"]),
        _probe("cbc-mode-is-weak-and-says-why",
               rows["weak"]["strength"]["rating"] == "WEAK"
               and rows["weak"]["strength"]["aead"] is False
               and rows["weak"]["dimensions"]["HASH"]["algorithm"] == "SHA-1",
               rows["weak"]["statement"][-64:]),
        _probe("a-token-that-must-not-be-enabled-is-broken-not-weak",
               rows["broken"]["strength"]["rating"] == "BROKEN"
               and rows["broken"]["strength"]["broken_tokens"] == ["RC4"],
               rows["broken"]["strength"]["note"]),
        _probe("an-unrecognised-suite-is-unknown-and-says-so",
               rows["unknown"]["strength"]["rating"] == "UNKNOWN"
               and rows["unknown"]["recognised"] is False,
               rows["unknown"]["strength"]["note"]),
    ]
    return {"id": "strength",
            "question": "does the decomposition answer why a suite is weak?",
            "phase": "review 8 / 11", "probes": probes}


def row_algorithm_facts(modules: dict[str, Any]) -> dict[str, Any]:
    cs, uc = modules["cs"], modules["uc"]
    thirteen = cs.decompose(TLS13, tls_version="1.3", group="X25519",
                            signature_algorithm="ECDSA_SECP256R1_SHA256",
                            evidence_id="NET-1")
    facts = cs.to_algorithms(thirteen)
    roles = {fact["role"]: fact["algorithm"] for fact in facts["facts"]}
    suite_facts = uc.algorithms_from_cipher_suite(TLS13)
    bare_facts = cs.to_algorithms(cs.decompose(TLS13, tls_version="1.3"))
    probes = [
        _probe("the-facts-use-the-roles-the-cbom-already-knows",
               set(roles) == {"KEY_EXCHANGE", "SIGNATURE", "BULK", "HASH"}
               and {fact["role"] for fact in suite_facts} <= set(roles),
               ", ".join(f"{role}={algorithm}" for role, algorithm in sorted(roles.items()))),
        _probe("handshake-facts-are-marked-as-not-coming-from-the-suite",
               facts["from_handshake"] == 2 and facts["from_suite"] == 2
               and {fact["algorithm"] for fact in facts["facts"] if fact["from_suite"]}
               == {"AES-256-GCM", "SHA-384"},
               "the suite names the AEAD and the hash; the handshake names the rest"),
        _probe("an-absent-dimension-produces-no-fact-at-all",
               [fact["role"] for fact in bare_facts["facts"]] == ["BULK", "HASH"],
               "two facts from a suite that names two things"),
        _probe("facts-carry-the-evidence-and-the-endpoint-they-came-from",
               all(fact["evidence_ids"] == ["NET-1"] and fact["class"]
                   == "NETWORK_OBSERVED" for fact in facts["facts"]),
               "NET-1 on every fact"),
        _probe("no-fact-claims-a-quantum-verdict",
               not any("quantum" in json.dumps(fact).lower() for fact in facts["facts"]),
               "quantum relevance is the handoff's job, not this model's"),
    ]
    return {"id": "algorithm_facts",
            "question": "can the decomposition feed the CBOM without a second vocabulary?",
            "phase": "review 8 / 9", "probes": probes}


def row_frontier(modules: dict[str, Any]) -> dict[str, Any]:
    cs = modules["cs"]
    full = cs.frontier(cs.decompose(TLS13, tls_version="1.3", group="X25519",
                                    signature_algorithm="ECDSA_SECP256R1_SHA256"))
    bare = cs.frontier(cs.decompose(TLS13, tls_version="1.3"))
    rows = {row["dimension"]: row for row in full["dimensions"]}
    probes = [
        _probe("the-migration-frontier-names-the-dimensions-to-replace",
               rows["KEY_EXCHANGE"]["quantum_relevant"] is True
               and rows["AUTHENTICATION"]["quantum_relevant"] is True
               and rows["ENCRYPTION"]["quantum_relevant"] is False,
               full["statement"]),
        _probe("a-symmetric-bulk-cipher-is-not-flagged-as-quantum-critical",
               rows["ENCRYPTION"]["quantum_relevant"] is False
               and "post-quantum" not in rows["ENCRYPTION"]["next_action"],
               "AES-256-GCM needs a bigger key at most, not a new primitive"),
        _probe("an-unknown-dimension-asks-for-evidence-before-a-plan",
               "collect the handshake context" in {row["dimension"]: row
                                                   for row in bare["dimensions"]}
               ["AUTHENTICATION"]["next_action"],
               "a migration plan built on an unknown dimension would be a guess"),
        _probe("the-frontier-counts-what-is-quantum-relevant",
               "2 of 4 dimension(s) are quantum-relevant" in full["statement"],
               full["statement"]),
    ]
    return {"id": "frontier",
            "question": "which of the four decisions does a PQC migration touch?",
            "phase": "review 8 / 15 boundary", "probes": probes}


def row_batch_and_shape(modules: dict[str, Any]) -> dict[str, Any]:
    cs = modules["cs"]
    batch = cs.handshake(HANDSHAKES)
    refused = cs.handshake([{"endpoint": "x:443"}, {"endpoint": "y:443",
                                                    "cipher_suite": "FOO"}])
    probes = [
        _probe("a-batch-decomposes-every-endpoint-and-counts-the-ratings",
               len(batch["handshakes"]) == len(HANDSHAKES)
               and batch["ratings"].get("STRONG") == 2
               and batch["ratings"].get("BROKEN") == 1,
               batch["statement"]),
        _probe("a-row-with-no-suite-is-refused-not-decomposed",
               refused["refused"][0]["reason"] == "a decomposition needs a cipher suite"
               and len(refused["handshakes"]) == 1,
               refused["statement"]),
        _probe("a-non-row-is-refused",
               cs.handshake(["not a row"])["refused"][0]["reason"]
               == "a handshake row must be an object",
               "a string is not a handshake"),
        _probe("the-model-states-what-one-handshake-cannot-prove",
               any("only one the endpoint accepts" in line for line in cs.NOT_PROVEN)
               and any("forward secrecy is a property" in line for line in cs.NOT_PROVEN),
               f"{len(cs.NOT_PROVEN)} stated limit(s)"),
        _probe("nothing-in-the-output-calls-anything-an-attack",
               not any(word in json.dumps(batch).lower()
                       for word in ("attack", "compromise", "exploit")),
               "a weak suite is a configuration fact"),
    ]
    return {"id": "batch_and_shape",
            "question": "does a batch of handshakes produce a usable, honest report?",
            "phase": "review 8", "probes": probes}


ROWS = (row_four_dimensions, row_strength, row_algorithm_facts, row_frontier,
        row_batch_and_shape)


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
    cs = modules["cs"]
    batch = cs.handshake(HANDSHAKES)
    by_endpoint = {row["endpoint"]: row for row in batch["handshakes"]}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "dimensions": list(cs.DIMENSIONS),
        "evidence_sources": list(cs.EVIDENCE),
        "ratings": list(cs.RATINGS),
        "batch": batch,
        "algorithms": cs.to_algorithms(by_endpoint["bare13.bank.example:443"]),
        "frontier": cs.frontier(by_endpoint["payments.bank.example:443"]),
        "rows": rows,
        "limits": [
            "one negotiated suite is one handshake. It is not the endpoint's configured "
            "set, and it is not proof that a stronger suite could not be negotiated",
            "the group, the signature algorithm and the certificate come from the "
            "handshake or the certificate. When a collector records only the suite, "
            "those dimensions stay unknown — deliberately, because the usual guess "
            "(no key-exchange token means RSA) is wrong for TLS 1.3",
            "forward secrecy is a property of the method named, not of the "
            "implementation: a correct ECDHE suite in a defective stack is still "
            "defective",
            "the strength ladder is explainable rather than scored: AEAD, bulk key size, "
            "mode and whether the suite names a token that must not be enabled. A "
            "reviewer can disagree with one rating without distrusting the rest",
            "a legacy identifier the token table does not model is reported as unknown "
            "rather than mapped to the nearest mode. `AES128` with no mode token is read "
            "as CBC because that is what the identifier means in TLS 1.2, and it is "
            "noted as such",
            "nothing here decides quantum status: `frontier()` says which dimensions are "
            "quantum-relevant and leaves the verdict to the PQC handoff",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    batch = report["batch"]
    lines = [
        "# A cipher suite is four decisions, and TLS 1.3 names only two",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review item 8: a suite string is not a description. `TLS_AES_256_GCM_SHA384` "
        "names an AEAD and a hash; the key exchange and the signature are decided by "
        "the handshake, and an inventory that flattens the suite into a list of names "
        "cannot answer a migration question.",
        "",
        "```",
        "KEY_EXCHANGE · AUTHENTICATION · ENCRYPTION · HASH",
        "     ↑ group        ↑ signature        ↑ AEAD         ↑ PRF",
        "     └── NAMED_IN_SUITE ─┬─ NEGOTIATED ─┬─ NOT_NAMED (unknown, never RSA) ──┘",
        "```",
        "",
        f"{batch['statement']}",
        "",
        "| rating | what it means |",
        "|---|---|",
        "| `STRONG` | AEAD bulk cipher, ≥128-bit key, ephemeral key exchange |",
        "| `ACCEPTABLE` | AEAD and ≥128-bit, but no forward secrecy |",
        "| `WEAK` | CBC mode or a bulk key below 128 bits |",
        "| `BROKEN` | RC4, 3DES/DES, NULL, EXPORT or anonymous key exchange |",
        "| `UNKNOWN` | the identifier names a mode this table does not model |",
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
