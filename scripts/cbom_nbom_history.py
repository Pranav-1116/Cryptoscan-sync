#!/usr/bin/env python3
"""Guide 155 — NBOM history: snapshots, changes, and NETWORK_CRYPTO_REGRESSION.

Review items 18 and 21:

    OBSERVE → NORMALIZE → HASH → COMPARE → CHANGE?
    ...endpoint added or removed, port changed, certificate changed, TLS version
    changed, cipher changed, SNI changed, ALPN changed, trust path changed.
    TLS1.3/AES-256 on 2026-11-01 against TLS1.2/AES-128 on 2026-11-02 is a
    CRYPTOGRAPHIC_REGRESSION.

The NBOM says itself that network discovery is point-in-time. A point has no memory,
so this guide adds the memory: a normalised snapshot with a digest over **state** (not
provenance), a complete change list, and the short subset that is a weakening —
`NETWORK_CRYPTO_REGRESSION` — which carries both sides of the evidence and states
what it does not prove.
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
SCHEMA = "cryptoscan.nbom-history-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

PAYMENTS = {
    "host": "payments.bank.example", "port": 443, "tls_version": "1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384", "sni": "payments.bank.example",
    "alpn": "h2", "evidence_id": "NET-1",
    "certificate": {"fingerprint_sha256": "aa11", "issuer": "BANK-ICA-01",
                    "not_after": "2027-01-01", "public_key_algorithm": "ECDSA",
                    "public_key_size": 256},
}
PARTNER = {
    "host": "partner.bank.example", "port": 443, "tls_version": "1.2",
    "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "evidence_id": "NET-2",
    "certificate": {"fingerprint_sha256": "bb22", "issuer": "PARTNER-CA"},
}
#: The review's own regression example, as one endpoint.
REGRESSED = {**PAYMENTS, "tls_version": "1.2",
             "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256",
             "certificate": {**PAYMENTS["certificate"], "fingerprint_sha256": "cc33",
                             "issuer": "BANK-ICA-02"},
             "evidence_id": "NET-9"}

#: The same downgrade with the certificate left alone, so a restoration later is a
#: protocol event and not a certificate rotation happening in reverse.
SOFT = {**PAYMENTS, "tls_version": "1.2",
        "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "evidence_id": "NET-9"}

SYSTEMS = {"payments.bank.example:443": ["Payments API", "Payments System"]}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import nbom_history  # noqa: PLC0415

    return {"nh": nbom_history}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _snap(nh, rows, taken_at: str):
    return nh.snapshot(rows, taken_at=taken_at, collector="authorized-scanner")


def _kinds(comparison: dict[str, Any]) -> set[str]:
    return {change["kind"] for change in comparison["changes"]}


# --------------------------------------------------------------------------- #


def row_snapshot_is_a_state(modules: dict[str, Any]) -> dict[str, Any]:
    nh = modules["nh"]
    first = _snap(nh, [PAYMENTS, PARTNER], "2026-11-01T00:00:00Z")
    reordered = _snap(nh, [PARTNER, PAYMENTS], "2026-11-01T03:00:00Z")
    re_evidenced = _snap(nh, [{**PAYMENTS, "evidence_id": "NET-77"}, PARTNER],
                         "2026-11-01T06:00:00Z")
    spellings = _snap(nh, [{**PAYMENTS, "endpoint": "Payments.Bank.Example:443",
                            "host": None}, PARTNER], "2026-11-01T00:00:00Z")
    refused: dict[str, str] = {}
    for name, rows in (("duplicate", [PAYMENTS, {**PAYMENTS, "tls_version": "1.2"}]),
                       ("hostless", [{"port": 443, "tls_version": "1.3"}])):
        try:
            nh.snapshot(rows)
        except ValueError as exc:
            refused[name] = str(exc)
    probes = [
        _probe("the-hash-covers-state-not-the-run",
               first["hash"] == reordered["hash"] == re_evidenced["hash"],
               f"{first['hash'][:12]} for three runs of the same state"),
        _probe("a-different-spelling-of-the-same-endpoint-is-the-same-endpoint",
               spellings["hash"] == first["hash"],
               "payments.bank.example:443 from the endpoint form"),
        _probe("re-collecting-the-same-fact-does-not-read-as-a-change",
               nh.compare(first, re_evidenced)["identical"] is True,
               nh.compare(first, re_evidenced)["statement"]),
        _probe("two-observations-of-one-endpoint-are-refused-not-merged",
               "appears twice" in refused.get("duplicate", ""),
               refused.get("duplicate", "accepted")),
        _probe("an-endpoint-with-no-host-cannot-be-identified",
               "needs a host" in refused.get("hostless", ""),
               refused.get("hostless", "accepted")),
        _probe("the-evidence-ids-travel-outside-the-digest",
               first["endpoints"][1]["evidence_ids"] == ["NET-1"]
               and "NET-1" not in first["endpoints"][1]["digest"],
               "evidence is provenance, not state"),
    ]
    return {"id": "snapshot_is_a_state",
            "question": "is a snapshot a state, or a record of one collection run?",
            "phase": "review 18 / 21", "probes": probes}


def row_the_change_list(modules: dict[str, Any]) -> dict[str, Any]:
    nh = modules["nh"]
    before = _snap(nh, [PAYMENTS, PARTNER], "2026-11-01T00:00:00Z")
    after = _snap(nh, [
        {**PAYMENTS, "port": 8443, "alpn": "http/1.1", "sni": "other.bank.example"},
        {**PARTNER, "certificate": {**PARTNER["certificate"],
                                    "fingerprint_sha256": "dd44",
                                    "issuer": "PARTNER-CA-2"}},
        {"host": "new.bank.example", "port": 9443, "tls_version": "1.3",
         "evidence_id": "NET-5"},
    ], "2026-11-02T00:00:00Z")
    comparison = nh.compare(before, after)
    kinds = _kinds(comparison)
    probes = [
        _probe("a-listener-that-moved-port-is-one-change-not-two",
               "PORT_CHANGED" in kinds and "ENDPOINT_REMOVED" not in kinds
               and sorted(kinds).count("ENDPOINT_ADDED") == 1,
               ", ".join(sorted(kinds)) + " (one arrival is the genuinely new host)"),
        _probe("a-new-listener-is-named-as-a-change-that-needs-an-owner",
               "ENDPOINT_ADDED" in kinds,
               [change["detail"] for change in comparison["changes"]
                if change["kind"] == "ENDPOINT_ADDED"][0]),
        _probe("a-changed-certificate-and-issuer-are-both-reported",
               {"CERTIFICATE_CHANGED", "TRUST_PATH_CHANGED"} <= kinds,
               "two facts, because a rotation and a new trust anchor are different"),
        _probe("sni-and-alpn-changes-are-low-severity-but-never-silent",
               {"SNI_CHANGED", "ALPN_CHANGED"} <= kinds
               and all(change["severity"] == "LOW" for change in comparison["changes"]
                       if change["kind"] in {"SNI_CHANGED", "ALPN_CHANGED"}),
               "both kept, both LOW"),
        _probe("every-change-carries-the-evidence-from-both-sides",
               all(change["evidence_after"] is not None and "evidence_before" in change
                   for change in comparison["changes"]),
               "before and after evidence ids on every row"),
        _probe("two-identical-snapshots-say-so-instead-of-listing-nothing",
               nh.compare(before, before)["identical"] is True
               and "same hash" in nh.compare(before, before)["statement"],
               nh.compare(before, before)["statement"]),
    ]
    return {"id": "the_change_list",
            "question": "is every kind of network change reported, with its evidence?",
            "phase": "review 21", "probes": probes}


def row_downgrade_is_not_any_change(modules: dict[str, Any]) -> dict[str, Any]:
    nh = modules["nh"]
    before = _snap(nh, [PAYMENTS], "2026-11-01T00:00:00Z")
    worsened = nh.compare(before, _snap(nh, [REGRESSED], "2026-11-02T00:00:00Z"))
    upgraded = nh.compare(before, _snap(nh, [PAYMENTS], "2026-11-02T00:00:00Z"))
    protocol_down = [change for change in worsened["changes"]
                     if change["kind"] == "TLS_VERSION_CHANGED"][0]
    suite_down = [change for change in worsened["changes"]
                  if change["kind"] == "CIPHER_SUITE_CHANGED"][0]
    weak_class = nh.compare(
        before, _snap(nh, [{**PAYMENTS, "cipher_suite": "ECDHE-RSA-AES128-SHA"}],
                      "2026-11-02T00:00:00Z"))
    probes = [
        _probe("the-review-s-example-downgrades-the-protocol",
               protocol_down["severity"] == "HIGH"
               and protocol_down["direction"] == "DOWNGRADE"
               and protocol_down["before"] == "TLS1.3"
               and protocol_down["after"] == "TLS1.2",
               protocol_down["detail"]),
        _probe("aes-256-to-aes-128-is-a-downgrade-even-on-the-same-version",
               suite_down["severity"] == "HIGH"
               and suite_down["direction"] == "DOWNGRADE"
               and "smaller key" in suite_down["detail"],
               suite_down["detail"]),
        _probe("the-hash-in-a-suite-name-is-not-a-key-size",
               nh._suite_strength("ECDHE-RSA-AES128-GCM-SHA256")["key_bits"] == 128
               and nh._suite_strength("TLS_AES_256_GCM_SHA384")["key_bits"] == 256,
               "AES128…SHA256 is a 128-bit bulk cipher"),
        _probe("a-move-into-a-classically-weak-class-is-a-downgrade",
               [change for change in weak_class["changes"]
                if change["kind"] == "CIPHER_SUITE_CHANGED"][0]["direction"] == "DOWNGRADE",
               [change["detail"] for change in weak_class["changes"]
                if change["kind"] == "CIPHER_SUITE_CHANGED"][0]),
        _probe("an-upgrade-is-a-change-and-not-a-regression",
               upgraded["identical"] is True
               and nh.regression(nh.compare(
                   _snap(nh, [{**PARTNER, "tls_version": "1.2"}], "2026-11-01T00:00:00Z"),
                   _snap(nh, [{**PARTNER, "tls_version": "1.3"}], "2026-11-02T00:00:00Z")))
               ["findings"] == [],
               "TLS1.2 → TLS1.3 produces no finding"),
        _probe("collection-status-loss-is-a-gap-not-a-crypto-finding",
               "COLLECTION_STATUS_CHANGED" in _kinds(nh.compare(
                   _snap(nh, [PAYMENTS], "2026-11-01T00:00:00Z"),
                   _snap(nh, [{**PAYMENTS, "observed": False}], "2026-11-02T00:00:00Z")))
               and nh.regression(nh.compare(
                   _snap(nh, [PAYMENTS], "2026-11-01T00:00:00Z"),
                   _snap(nh, [{**PAYMENTS, "observed": False}],
                         "2026-11-02T00:00:00Z")))["findings"] == [],
               "an endpoint that stopped answering is reported as a collection gap"),
    ]
    return {"id": "downgrade_is_not_any_change",
            "question": "which changes are weakenings, and which are just changes?",
            "phase": "review 18", "probes": probes}


def row_the_finding(modules: dict[str, Any]) -> dict[str, Any]:
    nh = modules["nh"]
    comparison = nh.compare(_snap(nh, [PAYMENTS], "2026-11-01T00:00:00Z"),
                            _snap(nh, [REGRESSED], "2026-11-02T00:00:00Z"),
                            systems=SYSTEMS)
    regressed = nh.regression(comparison)
    finding = regressed["findings"][0]
    probes = [
        _probe("the-finding-is-one-row-per-endpoint-not-one-per-symptom",
               len(regressed["findings"]) == 1
               and finding["signals"] == ["TLS_VERSION_CHANGED", "CIPHER_SUITE_CHANGED",
                                          "CERTIFICATE_CHANGED", "TRUST_PATH_CHANGED"],
               ", ".join(finding["signals"])),
        _probe("the-severity-is-the-worst-of-its-signals",
               finding["severity"] == "HIGH", finding["severity"]),
        _probe("both-sides-of-the-evidence-are-kept",
               finding["evidence_before"] == ["NET-1"]
               and finding["evidence_after"] == ["NET-9"],
               "NET-1 → NET-9"),
        _probe("the-finding-is-timestamped-by-the-observation-that-found-it",
               finding["observed_at"] == "2026-11-02T00:00:00Z",
               finding["observed_at"]),
        _probe("affected-systems-travel-when-the-mapping-exists",
               finding["affected_systems"] == ["Payments API", "Payments System"],
               ", ".join(finding["affected_systems"])),
        _probe("the-finding-states-what-it-does-not-prove",
               "that the endpoint is compromised" in finding["not_proven"]
               and "not a conclusion" in finding["statement"],
               finding["statement"]),
        _probe("nothing-here-calls-it-an-attack",
               not any(word in json.dumps(finding).lower()
                       for word in ("attack detected", "compromise confirmed",
                                    "attacker identified")),
               "a downgrade is a reason to investigate"),
        _probe("the-next-action-is-specific-to-the-signal",
               "protocol policy" in finding["next_action"]
               or "cipher policy" in finding["next_action"],
               finding["next_action"]),
    ]
    return {"id": "the_finding",
            "question": "what does a NETWORK_CRYPTO_REGRESSION say, and refuse to say?",
            "phase": "review 18 / 19", "probes": probes}


def row_history(modules: dict[str, Any]) -> dict[str, Any]:
    nh = modules["nh"]
    day1 = _snap(nh, [PAYMENTS], "2026-11-01T00:00:00Z")
    day2 = _snap(nh, [SOFT], "2026-11-02T00:00:00Z")
    day3 = _snap(nh, [SOFT], "2026-11-03T00:00:00Z")
    day4 = _snap(nh, [PAYMENTS], "2026-11-04T00:00:00Z")
    body = nh.timeline([day1, day2, day3, day4])
    probes = [
        _probe("a-timeline-compares-each-consecutive-pair",
               body["snapshots"] == 4 and len(body["periods"]) == 3,
               body["statement"]),
        _probe("a-period-with-no-change-is-marked-identical",
               body["periods"][1]["identical"] is True
               and body["periods"][0]["identical"] is False,
               "day 2 → day 3 changed nothing"),
        _probe("regressions-are-counted-across-the-history",
               body["regressions"] == 1 and body["worst"] == "HIGH",
               f"{body['regressions']} finding(s), worst {body['worst']}"),
        _probe("a-restoration-is-not-silently-a-regression",
               body["periods"][2]["regression"]["findings"] == [],
               "day 3 → day 4 recovered the protocol and produced no finding"),
        _probe("the-summary-says-whether-anything-moved-the-wrong-way",
               "NETWORK_CRYPTO_REGRESSION" in nh.summary(
                   nh.compare(day1, day2))["statement"],
               nh.summary(nh.compare(day1, day2))["statement"]),
    ]
    return {"id": "history",
            "question": "does the NBOM keep enough history to answer what changed?",
            "phase": "review 21", "probes": probes}


ROWS = (row_snapshot_is_a_state, row_the_change_list, row_downgrade_is_not_any_change,
        row_the_finding, row_history)


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
    nh = modules["nh"]
    before = _snap(nh, [PAYMENTS, PARTNER], "2026-11-01T00:00:00Z")
    after = _snap(nh, [REGRESSED, PARTNER], "2026-11-02T00:00:00Z")
    comparison = nh.compare(before, after, systems=SYSTEMS)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "change_kinds": list(nh.CHANGE_KINDS),
        "regression_kinds": list(nh.REGRESSIONS),
        "before": {"taken_at": before["taken_at"], "hash": before["hash"]},
        "after": {"taken_at": after["taken_at"], "hash": after["hash"]},
        "comparison": {key: comparison[key] for key in
                       ("identical", "counts", "downgrades", "unchanged", "statement")},
        "regression": nh.regression(comparison),
        "rows": rows,
        "limits": [
            "a snapshot is what the collector saw. An endpoint that was not probed is "
            "absent from both snapshots, so its absence is not a change — the coverage "
            "matrix from guide 153 says whether the two runs are comparable",
            "the digest covers negotiated state, not the endpoint's capability set. A "
            "device that started offering TLS 1.0 while still negotiating TLS 1.3 "
            "produces no change here until something enumerates it (guide 154)",
            "a certificate change is reported as a change with medium severity, because "
            "rotations are ordinary. The finding says to confirm it with the PKI owner "
            "rather than deciding that it is suspicious",
            "affected systems come from a mapping somebody supplied. Without it the "
            "finding names the endpoint and nothing else, which is the honest bound",
            "two snapshots do not make a baseline. A change between the first two runs "
            "of a new collector is as likely to be collector configuration as device "
            "configuration",
            "the severity ladder is a heuristic over protocol order, bulk key size and a "
            "list of weak suite tokens. It is deliberately explainable rather than "
            "scored, so a reviewer can disagree with one row without distrusting the "
            "rest",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    comparison = report["comparison"]
    regression = report["regression"]
    lines = [
        "# NBOM history: snapshots, changes, and NETWORK_CRYPTO_REGRESSION",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review items 18 and 21: the NBOM is point-in-time, and a point has no memory. "
        "A normalised snapshot per run, hashed over **state**, makes *nothing changed* "
        "cheap to prove and *what changed* cheap to find.",
        "",
        "```",
        "OBSERVE → NORMALIZE → HASH → COMPARE → CHANGE?",
        "              state only          complete list → the weakening subset",
        "                                  → NETWORK_CRYPTO_REGRESSION",
        "```",
        "",
        f"Sample: {comparison['statement']}",
        "",
        f"{regression['statement']}",
        "",
        "| change kind | reported as |",
        "|---|---|",
        "| `ENDPOINT_ADDED` | a change that needs an owner (`INFO`) |",
        "| `ENDPOINT_REMOVED` | decommissioned *or* stopped answering (`MEDIUM`) |",
        "| `PORT_CHANGED` | one endpoint moving, not a disappearance plus an arrival |",
        "| `TLS_VERSION_CHANGED` | `HIGH` when it goes down, `INFO` when it goes up |",
        "| `CIPHER_SUITE_CHANGED` | `HIGH` when weaker (smaller bulk key or weak class) |",
        "| `CERTIFICATE_CHANGED` | `MEDIUM`: rotations are ordinary, replacements are not |",
        "| `TRUST_PATH_CHANGED` | `MEDIUM`: the anchor moved |",
        "| `SNI_CHANGED`, `ALPN_CHANGED` | `LOW`, because a change is still a change |",
        "| `COLLECTION_STATUS_CHANGED` | `MEDIUM`: a collection gap, not a crypto finding |",
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
