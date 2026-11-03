#!/usr/bin/env python3
"""Guide 161 — SSH negotiates four things, two of them per direction.

Review item 13 asks for SSH depth. SSH is not one cipher suite: it negotiates **key
exchange, host key, cipher and MAC**, and cipher and MAC run in **each direction
separately**. A host that encrypts toward the client with `chacha20-poly1305` and toward
the server with `aes128-cbc` has one weak direction, and an inventory recording "SSH,
AES-128" cannot say which.

Two SSH-specific traps are modelled here: `ssh-rsa` is the **SHA-1 signature algorithm**
and not "RSA" (`rsa-sha2-256` is the modern one), and the **client's preference decides**
— the server's offer is a different question from what was used, the same
SUPPORTED/CONFIGURED/NEGOTIATED distinction guide 154 keeps for TLS.
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
SCHEMA = "cryptoscan.cbom-ssh-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

MODERN = {
    "host": "jump.bank.example", "port": 22, "banner": "SSH-2.0-OpenSSH_9.6",
    "evidence_id": "SSH-1", "observed_at": "2026-11-01T00:00:00Z",
    "source": "ssh-probe", "host_key_fingerprint": "SHA256:abc",
    "negotiated": {"kex": "curve25519-sha256", "host_key": "ssh-ed25519",
                   "cipher_client_to_server": "chacha20-poly1305@openssh.com",
                   "cipher_server_to_client": "chacha20-poly1305@openssh.com"},
}
LEGACY = {
    "host": "legacy.bank.example", "port": 22, "evidence_id": "SSH-2",
    "observed_at": "2026-11-01T00:00:00Z", "source": "ssh-probe",
    "negotiated": {"kex": "diffie-hellman-group1-sha1", "host_key": "ssh-rsa",
                   "cipher": "3des-cbc", "mac": "hmac-md5"},
}
SPLIT = {
    "host": "payments.bank.example", "port": 22, "evidence_id": "SSH-3",
    "observed_at": "2026-11-01T00:00:00Z", "source": "ssh-probe",
    "negotiated": {"kex": "ecdh-sha2-nistp256", "host_key": "rsa-sha2-256",
                   "cipher_client_to_server": "aes256-gcm@openssh.com",
                   "cipher_server_to_client": "aes128-cbc",
                   "mac_server_to_client": "hmac-sha1-96"},
}
ESTATE = [MODERN, LEGACY, SPLIT]


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import ssh_crypto  # noqa: PLC0415

    return {"sc": ssh_crypto}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def row_four_negotiations(modules: dict[str, Any]) -> dict[str, Any]:
    sc = modules["sc"]
    body = sc.session(MODERN)
    probes = [
        _probe("a-session-is-four-negotiations-not-one-cipher",
               body["kex"]["algorithm"] == "curve25519-sha256"
               and body["host_key"]["algorithm"] == "ssh-ed25519"
               and body["directions"]["CLIENT_TO_SERVER"]["cipher"]["algorithm"]
               == "chacha20-poly1305@openssh.com",
               body["statement"]),
        _probe("both-directions-are-recorded-with-their-own-algorithms",
               set(body["directions"]) == {"CLIENT_TO_SERVER", "SERVER_TO_CLIENT"}
               and all(row["evidence"] in {"NEGOTIATED", "UNKNOWN"}
                       for row in body["directions"].values()),
               "c→s and s→c, separately"),
        _probe("an-asymmetric-session-names-the-weak-direction",
               sc.session(SPLIT)["asymmetric"] is True
               and "the weaker one decides" in sc.session(SPLIT)["statement"],
               "aes256-gcm one way, aes128-cbc the other"),
        _probe("an-aead-cipher-does-not-negotiate-a-separate-mac",
               body["directions"]["CLIENT_TO_SERVER"]["mac"] is None
               and sc.session({**MODERN, "negotiated": {
                   **MODERN["negotiated"],
                   "cipher_client_to_server": "aes256-cbc",
                   "mac_client_to_server": "hmac-sha2-256"}})
               ["directions"]["CLIENT_TO_SERVER"]["mac"]["algorithm"] == "hmac-sha2-256",
               "poly1305 authenticates; a CBC cipher still needs its MAC"),
        _probe("the-host-key-fingerprint-travels-and-the-key-never-does",
               body["host_key_fingerprint"] == "SHA256:abc"
               and body["private_material"] == "NOT_STORED",
               body["private_material"]),
    ]
    return {"id": "four_negotiations",
            "question": "does one SSH session become four answers, per direction?",
            "phase": "review 13", "probes": probes}


def row_ssh_specific(modules: dict[str, Any]) -> dict[str, Any]:
    sc = modules["sc"]
    probes = [
        _probe("ssh-rsa-is-sha1-and-not-the-same-as-rsa-sha2",
               sc.algorithm("ssh-rsa", "HOST_KEY")["rating"] == "DEPRECATED"
               and "SHA-1" in sc.algorithm("ssh-rsa", "HOST_KEY")["reason"]
               and sc.algorithm("rsa-sha2-256", "HOST_KEY")["rating"] == "ACCEPTABLE",
               "the same key type, two different signature algorithms"),
        _probe("the-server-s-offer-is-kept-apart-from-what-was-used",
               sc.session({**MODERN, "server_supported": {
                   "kex": "curve25519-sha256,diffie-hellman-group1-sha1",
                   "cipher": "chacha20-poly1305@openssh.com,aes128-cbc"}})
               ["server_supported"]["cipher"] == ["chacha20-poly1305@openssh.com",
                                                  "aes128-cbc"]
               and sc.session(MODERN)["state"] == "NEGOTIATED",
               "SUPPORTED and NEGOTIATED are different answers"),
        _probe("an-unknown-algorithm-is-not-called-broken",
               sc.algorithm("some-future-kex@example.com", "KEX")["rating"]
               == "ACCEPTABLE",
               "a name this table does not know is not a verdict"),
        _probe("a-dimension-outside-the-four-is-refused",
               _raises(lambda: sc.algorithm("x", "COMPRESSION"), "is not one of"),
               "compression is not a cryptographic negotiation"),
        _probe("a-session-with-no-evidence-is-refused",
               _raises(lambda: sc.session({"host": "h"}), "no evidence id"),
               "an SSH claim without a session record is a claim"),
    ]
    return {"id": "ssh_specific",
            "question": "are the two SSH-specific traps handled rather than flattened?",
            "phase": "review 13", "probes": probes}


def row_the_estate(modules: dict[str, Any]) -> dict[str, Any]:
    sc = modules["sc"]
    body = sc.estate(ESTATE)
    summary = sc.summary(body)
    probes = [
        _probe("the-estate-names-every-deprecated-algorithm-and-who-uses-it",
               set(body["deprecated"]) == {"diffie-hellman-group1-sha1", "ssh-rsa",
                                           "3des-cbc", "hmac-md5", "aes128-cbc",
                                           "hmac-sha1-96"}
               and body["deprecated"]["ssh-rsa"] == ["legacy.bank.example"],
               body["statement"]),
        _probe("hosts-with-an-asymmetric-session-are-listed",
               body["asymmetric_directions"] == ["payments.bank.example"],
               ", ".join(body["asymmetric_directions"])),
        _probe("a-session-is-never-summarised-as-one-algorithm",
               all({"kex", "host_key", "directions"} <= set(session)
                   for session in body["sessions"]),
               "four answers per session, not one"),
        _probe("a-refused-session-is-listed-not-dropped",
               len(sc.estate([MODERN, {"host": "x"}, "nonsense"])["refused"]) == 2
               and "refused" in sc.estate([{"host": "x"}])["statement"],
               "two refusals, both visible"),
        _probe("the-estate-states-what-one-session-cannot-prove",
               any("only one the server accepts" in line for line in sc.NOT_PROVEN)
               and any("known_hosts" in line for line in sc.NOT_PROVEN),
               f"{len(summary['not_proven'])} stated limit(s)"),
    ]
    return {"id": "the_estate",
            "question": "does the SSH estate turn into findings with hosts attached?",
            "phase": "review 13", "probes": probes}


def row_facts(modules: dict[str, Any]) -> dict[str, Any]:
    sc = modules["sc"]
    body = sc.to_algorithms(sc.estate(ESTATE))
    roles = {fact["role"] for fact in body["facts"]}
    probes = [
        _probe("facts-use-the-roles-the-rest-of-the-platform-uses",
               roles == {"KEY_EXCHANGE", "SIGNATURE", "BULK", "MAC"},
               ", ".join(sorted(roles))),
        _probe("every-fact-is-marked-as-an-ssh-network-observation",
               all(fact["protocol"] == "SSH" and fact["class"] == "NETWORK_OBSERVED"
                   and fact["evidence_ids"] for fact in body["facts"]),
               f"{len(body['facts'])} fact(s), each cited"),
        _probe("quantum-exposure-is-named-without-a-migration-verdict",
               "ssh-rsa" in body["quantum_vulnerable"]
               and "curve25519-sha256" in body["quantum_vulnerable"]
               and not any("quantum" in json.dumps(fact["parameters"]).lower()
                           for fact in body["facts"]),
               ", ".join(body["quantum_vulnerable"])),
        _probe("a-symmetric-cipher-is-not-called-quantum-vulnerable",
               sc.algorithm("aes256-gcm@openssh.com", "CIPHER")["quantum_vulnerable"]
               is None,
               "AES needs a bigger key at most, not a new primitive"),
        _probe("a-document-that-is-not-an-ssh-estate-is-refused",
               _raises(lambda: sc.to_algorithms({"sessions": []}), "not a"),
               "a foreign document is rejected, not converted"),
    ]
    return {"id": "facts",
            "question": "does SSH feed the CBOM without a second vocabulary?",
            "phase": "review 13 / 16 boundary", "probes": probes}


def row_shape(modules: dict[str, Any]) -> dict[str, Any]:
    sc = modules["sc"]
    probe_rows = sc.session({**MODERN, "banner": "SSH-2.0-OpenSSH_7.4"})
    probes = [
        _probe("the-banner-is-recorded-and-never-judged",
               probe_rows["banner"] == "SSH-2.0-OpenSSH_7.4"
               and not any("banner" in json.dumps(problem)
                           for problem in probe_rows["problems"]),
               "a version string is not a cryptographic property"),
        _probe("an-empty-algorithm-name-is-refused",
               _raises(lambda: sc.algorithm("", "KEX"), "needs a name"),
               "no name, no algorithm"),
        _probe("a-non-object-session-is-refused",
               _raises(lambda: sc.session("nope"), "must be an object"),
               "a string is not a session"),
        _probe("the-deprecation-and-quantum-tables-are-explainable",
               all(isinstance(reason, str) and reason for reason in
                   sc.DEPRECATED.values())
               and len(sc.DEPRECATED) >= 10
               and all(isinstance(note, str) for note in sc.QUANTUM_VULNERABLE.values()),
               f"{len(sc.DEPRECATED)} deprecated entries, each with a reason"),
        _probe("nothing-in-the-report-calls-anything-an-attack",
               not any(word in json.dumps(sc.estate(ESTATE)).lower()
                       for word in ("attack", "compromise", "exploit")),
               "a weak SSH algorithm is a configuration fact"),
    ]
    return {"id": "shape",
            "question": "does the report refuse to say more than the session shows?",
            "phase": "review 13", "probes": probes}


def _raises(call, needle: str) -> bool:
    try:
        call()
    except ValueError as exc:
        return needle in str(exc)
    return False


ROWS = (row_four_negotiations, row_ssh_specific, row_the_estate, row_facts, row_shape)


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
    sc = modules["sc"]
    body = sc.estate(ESTATE)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "dimensions": list(sc.DIMENSIONS),
        "directions": list(sc.DIRECTIONS),
        "deprecated": sorted(sc.DEPRECATED),
        "estate": body,
        "facts": sc.to_algorithms(body),
        "summary": sc.summary(body),
        "rows": rows,
        "limits": [
            "one session is one negotiation. The server's full offer is a different "
            "question, and a modern algorithm in use today can be the client's "
            "preference rather than the server's policy",
            "SSH takes the first algorithm on the client's list that the server also "
            "offers, so a weak client can choose a weak algorithm against a strong "
            "server. Both lists matter and this model records both when they are given",
            "a host key is trusted by the client's known_hosts, which this model does "
            "not read. A fingerprint identifies a key; it does not vouch for it",
            "the deprecation table is a hand-maintained list with a reason per entry, "
            "not a compliance mapping. An operator can disagree with one row without "
            "distrusting the rest",
            "compression, port forwarding and agent forwarding are not negotiated "
            "cryptography in the sense this model measures, and none is judged here",
            "a version banner is recorded and never scored: OpenSSH 7.4 is not a weak "
            "algorithm, it is a version that may support weak ones",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    body = report["estate"]
    lines = [
        "# SSH negotiates four things, two of them per direction",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review item 13: SSH is not a cipher suite. It negotiates **key exchange, host "
        "key, cipher and MAC**, and the last two run in each direction separately.",
        "",
        "```",
        "KEX · HOST_KEY · CIPHER (c→s, s→c) · MAC (c→s, s→c)",
        "  │        │        └── an AEAD cipher negotiates no separate MAC",
        "  │        └── ssh-rsa is SHA-1, rsa-sha2-256 is not",
        "  └── the client's preference decides, not the server's",
        "```",
        "",
        f"{body['statement']}",
        "",
        "| dimension | deprecated examples | why |",
        "|---|---|---|",
        "| `KEX` | `diffie-hellman-group1-sha1` | 1024-bit group with SHA-1 |",
        "| `HOST_KEY` | `ssh-rsa`, `ssh-dss` | SHA-1 signatures; DSA limited to 1024 bits |",
        "| `CIPHER` | `3des-cbc`, `aes128-cbc`, `arcfour*` | 64-bit blocks, no AEAD, RC4 |",
        "| `MAC` | `hmac-md5`, `hmac-sha1-96` | MD5, truncated SHA-1 |",
        "",
        f"Deprecated in use: {', '.join(sorted(body['deprecated'])) or 'none'}",
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
