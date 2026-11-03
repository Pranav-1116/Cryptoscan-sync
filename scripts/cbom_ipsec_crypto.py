#!/usr/bin/env python3
"""Guide 162 — IPsec negotiates twice, and PFS is not the DH group in phase 1.

Review item 14 asks for VPN/IPsec depth. An IPsec tunnel has **two security
associations**, negotiated separately:

    IKE SA    (phase 1)  encryption · PRF/integrity · DH group
    CHILD SA  (phase 2)  ESP encryption · ESP integrity · PFS group

The distinction that matters is the last column. A CHILD SA with **no PFS group**
derives its keys from the IKE SA's key material, so one compromised peer key decrypts
every rekeyed tunnel back to the start — and a configuration reading
`AES-256 / SHA-256 / DH14` looks strong while having no forward secrecy for data. PFS is
therefore its own field, never inferred from the phase-1 DH group.
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
SCHEMA = "cryptoscan.cbom-ipsec-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

DC = {
    "peer": "dc1.fw.bank.example", "local": "10.1.0.1", "ike_version": "IKEv2",
    "authentication": "CERTIFICATE", "state": "ESTABLISHED", "evidence_id": "VPN-1",
    "observed_at": "2026-11-01T00:00:00Z", "source": "firewall-api",
    "ike": {"proposal": ["AES256", "SHA256", "DH14"]},
    "child": {"proposal": ["AES256", "SHA256"], "pfs": "DH14", "lifetime": 3600},
}
BRANCH = {
    "peer": "branch42.fw.bank.example", "local": "10.1.0.1", "ike_version": "1",
    "authentication": "PSK", "mode": "AGGRESSIVE", "state": "ESTABLISHED",
    "evidence_id": "VPN-2", "observed_at": "2026-11-01T00:00:00Z",
    "source": "firewall-api",
    "ike": {"proposal": ["3DES", "SHA1", "DH2"]},
    "child": {"proposal": ["3DES", "MD5"]},
}
PARTNER = {
    "peer": "partner.example", "local": "10.1.0.1", "ike_version": "IKEv2",
    "authentication": "PSK", "state": "ESTABLISHED", "evidence_id": "VPN-3",
    "observed_at": "2026-11-02T00:00:00Z", "source": "firewall-api",
    "ike": {"proposal": ["AES128", "SHA1", "DH19"]},
    "child": {"proposal": ["AES128GCM16"]},
}
ESTATE = [DC, BRANCH, PARTNER]


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import ipsec_crypto  # noqa: PLC0415

    return {"ic": ipsec_crypto}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _raises(call, needle: str) -> bool:
    try:
        call()
    except ValueError as exc:
        return needle in str(exc)
    return False


def _ratings(body: dict[str, Any]) -> set[str]:
    return {problem["rating"] for problem in body["problems"]}


def row_two_phases(modules: dict[str, Any]) -> dict[str, Any]:
    ic = modules["ic"]
    body = ic.tunnel(DC)
    probes = [
        _probe("a-tunnel-is-two-security-associations",
               body["ike_proposal"] and body["child_proposal"]
               and {row["phase"] for row in body["ike_proposal"]} == {"IKE"}
               and {row["phase"] for row in body["child_proposal"]} == {"CHILD"},
               "phase 1 and phase 2 are recorded separately"),
        _probe("a-clean-sa-has-no-problems",
               body["problems"] == [] and body["worst"] is None,
               f"aes256/sha256/dh14 with a PFS group: {len(body['problems'])} problem(s)"),
        _probe("the-phase-1-group-does-not-count-as-pfs",
               ic.tunnel({**DC, "child": {"proposal": ["AES256"], "pfs": None}})
               ["forward_secrecy_for_data"] is False,
               "DH14 in phase 1 says nothing about the data path"),
        _probe("a-phase-2-without-pfs-is-named-as-such",
               "NO_FORWARD_SECRECY" in _ratings(
                   ic.tunnel({**DC, "child": {"proposal": ["AES256"]}})),
               "no PFS group, so the CHILD keys derive from the IKE SA"),
        _probe("the-statement-names-both-phases",
               "ike aes256" in body["statement"] and "child aes256" in body["statement"],
               body["statement"]),
    ]
    return {"id": "two_phases",
            "question": "does one tunnel become two security associations?",
            "phase": "review 14", "probes": probes}


def row_pfs(modules: dict[str, Any]) -> dict[str, Any]:
    ic = modules["ic"]
    estate = ic.estate(ESTATE)
    probes = [
        _probe("the-estate-lists-peers-without-forward-secrecy",
               estate["without_pfs"] == ["branch42.fw.bank.example", "partner.example"],
               ", ".join(estate["without_pfs"])),
        _probe("a-strong-looking-proposal-is-still-flagged",
               ic.tunnel(PARTNER)["worst"] == "NO_FORWARD_SECRECY"
               and ic.tunnel(PARTNER)["forward_secrecy_for_data"] is False,
               "aes128gcm16 sounds modern and has no PFS group"),
        _probe("the-weak-pfs-group-is-judged-on-its-own",
               ic.transform("DH2", phase="CHILD")["rating"] == "WEAK"
               and ic.transform("DH2", phase="CHILD")["group_bits"] == 1024,
               "PFS with a 1024-bit group is forward secrecy against yesterday"),
        _probe("the-statement-counts-the-peer-without-pfs",
               "2 without a PFS group" in estate["statement"],
               estate["statement"]),
        _probe("a-valid-pfs-group-is-not-a-problem",
               ic.tunnel({**DC, "child": {"proposal": ["AES256"], "pfs": "DH19"}})
               ["problems"] == [],
               "DH19 (ECDH P-256) is an acceptable PFS group"),
    ]
    return {"id": "pfs",
            "question": "is forward secrecy for data its own answer, not an inference?",
            "phase": "review 14", "probes": probes}


def row_vpn_specific(modules: dict[str, Any]) -> dict[str, Any]:
    ic = modules["ic"]
    branch = ic.tunnel(BRANCH)
    probes = [
        _probe("ikev1-aggressive-mode-with-a-psk-is-an-offline-attack",
               "OFFLINE_PSK_ATTACK" in _ratings(branch)
               and branch["worst"] == "OFFLINE_PSK_ATTACK",
               "a hash of the PSK travels on the wire"),
        _probe("the-same-psk-on-ikev2-is-not-that-finding",
               "OFFLINE_PSK_ATTACK" not in _ratings(
                   ic.tunnel({**PARTNER, "authentication": "PSK"})),
               "IKEv2 has no aggressive mode"),
        _probe("an-ikev2-record-claiming-aggressive-mode-is-normalised",
               ic.tunnel({**PARTNER, "mode": "AGGRESSIVE"})["mode"] == "IKEV2_SA_INIT",
               "the mode does not exist in IKEv2"),
        _probe("null-encryption-is-reported-and-not-called-safe",
               "NO_CONFIDENTIALITY" in _ratings(
                   ic.tunnel({**DC, "child": {"proposal": ["ENCR_NULL", "SHA256"],
                                              "pfs": "DH14"}})),
               "integrity without encryption over the internet"),
        _probe("a-tunnel-with-no-child-sa-says-so",
               "NO_CHILD_SA" in _ratings(ic.tunnel({**DC, "child": {}})),
               "one SA is not a tunnel"),
    ]
    return {"id": "vpn_specific",
            "question": "are the VPN-specific traps handled rather than flattened?",
            "phase": "review 14", "probes": probes}


def row_the_estate(modules: dict[str, Any]) -> dict[str, Any]:
    ic = modules["ic"]
    estate = ic.estate(ESTATE)
    summary = ic.summary(estate)
    probes = [
        _probe("the-estate-names-the-weak-transforms-in-use",
               set(estate["weak_transforms_in_use"]) == {"3des", "dh2", "md5", "sha1"},
               ", ".join(estate["weak_transforms_in_use"])),
        _probe("ikev1-peers-are-listed",
               estate["ikev1"] == ["branch42.fw.bank.example"],
               ", ".join(estate["ikev1"])),
        _probe("a-refused-tunnel-is-listed-not-dropped",
               len(ic.estate([DC, {"ike_version": "2"}, "nonsense"])["refused"]) == 2,
               "two refusals, visible in the estate"),
        _probe("the-summary-repeats-the-worst-finding-per-peer",
               summary["worst"]["branch42.fw.bank.example"] == "OFFLINE_PSK_ATTACK",
               json.dumps(summary["worst"])),
        _probe("the-estate-states-what-one-sa-cannot-prove",
               any("peer's policy" in line for line in ic.NOT_PROVEN)
               and any("pre-shared key" in line for line in ic.NOT_PROVEN),
               f"{len(summary['not_proven'])} stated limit(s)"),
    ]
    return {"id": "the_estate",
            "question": "does the VPN surface turn into findings with peers attached?",
            "phase": "review 14", "probes": probes}


def row_facts(modules: dict[str, Any]) -> dict[str, Any]:
    ic = modules["ic"]
    body = ic.to_algorithms(ic.estate(ESTATE))
    roles = {fact["role"] for fact in body["facts"]}
    probes = [
        _probe("facts-use-the-roles-the-rest-of-the-platform-uses",
               roles == {"KEY_EXCHANGE", "PRF_AND_INTEGRITY", "BULK"},
               ", ".join(sorted(roles))),
        _probe("every-fact-carries-its-phase-and-protocol",
               all(fact["protocol"] == "IPSEC" and fact["class"] == "NETWORK_OBSERVED"
                   and fact["phase"] in {"IKE", "CHILD"} and fact["evidence_ids"]
                   for fact in body["facts"]),
               f"{len(body['facts'])} fact(s), each cited"),
        _probe("a-group-transform-carries-its-size",
               any(fact["role"] == "KEY_EXCHANGE"
                   and fact["parameters"].get("group_bits") == 1024
                   for fact in body["facts"]),
               "a DH fact without its group size is not a fact"),
        _probe("a-symmetric-cipher-is-not-called-quantum-vulnerable",
               not any(fact["quantum_vulnerable"] for fact in body["facts"]
                       if fact["algorithm"].startswith(("aes", "3des", "chacha"))),
               "AES/3DES need a bigger key at most, not a new primitive"),
        _probe("a-document-that-is-not-an-ipsec-estate-is-refused",
               _raises(lambda: ic.to_algorithms({"tunnels": []}), "not a"),
               "a foreign document is rejected, not converted"),
    ]
    return {"id": "facts",
            "question": "does IPsec feed the CBOM without a second vocabulary?",
            "phase": "review 14 / 16 boundary", "probes": probes}


def row_shape(modules: dict[str, Any]) -> dict[str, Any]:
    ic = modules["ic"]
    probes = [
        _probe("an-unknown-ike-version-is-refused",
               _raises(lambda: ic.tunnel({**DC, "ike_version": "3"}), "unknown"),
               "IKEv1 and IKEv2 have different transform vocabularies"),
        _probe("an-sa-with-no-evidence-is-refused",
               _raises(lambda: ic.tunnel({k: v for k, v in DC.items()
                                          if k != "evidence_id"}), "no evidence id"),
               "an SA without a record is a claim"),
        _probe("an-unknown-transform-is-not-called-weak",
               ic.transform("some-future-transform", phase="CHILD")["rating"]
               == "UNKNOWN",
               "UNKNOWN, not WEAK: the table cannot see it"),
        _probe("a-phase-outside-the-two-is-refused",
               _raises(lambda: ic.transform("AES256", phase="PHASE3"), "is not one of"),
               "IPsec has two phases"),
        _probe("the-only-attack-finding-describes-a-property-not-an-event",
               all("can be attacked offline" in problem["detail"]
                   for body_row in ic.estate(ESTATE)["tunnels"]
                   for problem in body_row["problems"]
                   if problem["rating"] == "OFFLINE_PSK_ATTACK")
               and not any(word in json.dumps(
                   [problem for body_row in ic.estate(ESTATE)["tunnels"]
                    for problem in body_row["problems"]]).lower()
                   for word in ("detected", "has been", "we saw")),
               "the rating names what aggressive mode would allow, not what happened"),
    ]
    return {"id": "shape",
            "question": "does the report refuse to say more than the SA shows?",
            "phase": "review 14", "probes": probes}


ROWS = (row_two_phases, row_pfs, row_vpn_specific, row_the_estate, row_facts, row_shape)


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
    ic = modules["ic"]
    body = ic.estate(ESTATE)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "phases": list(ic.PHASES),
        "versions": list(ic.VERSIONS),
        "weak_transforms": dict(ic.WEAK_TRANSFORMS),
        "groups": {name: dict(spec) for name, spec in ic.DH_GROUPS.items()},
        "estate": body,
        "facts": ic.to_algorithms(body),
        "summary": ic.summary(body),
        "rows": rows,
        "limits": [
            "one SA pair is one choice. The peer's full proposal list is a different "
            "question, and a good transform in use may be the other side's preference",
            "an established SA is a configuration. Liveness, byte counters and whether "
            "the tunnel is carrying anything are not read here",
            "PSK strength is invisible: the model can see that a pre-shared key is in "
            "use and that aggressive mode would expose a hash of it, not whether that "
            "secret is guessable",
            "certificate authentication is only as strong as the chain behind it, which "
            "is guide 159's subject and not re-derived here",
            "the weak-transform table is a hand-maintained list with a reason per entry, "
            "not a compliance mapping; an operator can dispute one row without "
            "distrusting the rest",
            "a tunnel that is down, deleted or half-open is recorded as its state says "
            "and is not inferred to be one of those",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    body = report["estate"]
    lines = [
        "# IPsec negotiates twice, and PFS is not the DH group in phase 1",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review item 14: a VPN tunnel has two security associations, and a CHILD SA "
        "without its own PFS group has no forward secrecy for data even when phase 1 "
        "used a strong group.",
        "",
        "```",
        "IKE SA    (phase 1)   encryption · PRF/integrity · DH group",
        "CHILD SA  (phase 2)   ESP encryption · ESP integrity · PFS group",
        "  │                                              │",
        "  │                                              └── absent ⇒ no forward secrecy",
        "  └── IKEv1 + aggressive mode + PSK ⇒ offline PSK attack",
        "```",
        "",
        body["statement"],
        "",
        "| transform | rating | why |",
        "|---|---|---|",
    ]
    for name, reason in sorted(report["weak_transforms"].items()):
        lines.append(f"| `{name}` | weak | {reason} |")
    lines += [
        "",
        f"Peers without forward secrecy: {', '.join(body['without_pfs']) or 'none'}",
        "",
        f"IKEv1 still in use: {', '.join(body['ikev1']) or 'none'}",
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
