#!/usr/bin/env python3
"""Guide 157 — network crypto correlation: several changes, one pattern, no verdict.

Review item 19, in its own words:

    TLS downgrade + certificate mutation + new endpoint + new process is a
    `CORRELATED_PATTERN` at `SUSPICIOUS_ACTIVITY`, never "attack detected";
    compromise, attribution and intent stay unproven.

A single change is a fact. What makes a correlation possible is the graph around it:
a downgrade *and* a replaced certificate *and* a listener that was not there yesterday
*and* a process that started, inside one window, describe one event rather than four.
What the platform may say about that event is the whole subject of this guide.
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
SCHEMA = "cryptoscan.nbom-patterns-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

PAYMENTS = {
    "host": "payments.bank.example", "port": 443, "tls_version": "1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-1",
    "certificate": {"fingerprint_sha256": "aa11", "issuer": "BANK-ICA-01"},
}
DOWNGRADED = {**PAYMENTS, "tls_version": "1.2",
              "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "evidence_id": "NET-9",
              "certificate": {"fingerprint_sha256": "cc33", "issuer": "BANK-ICA-09"}}
PARTNER = {"host": "partner.bank.example", "port": 443, "tls_version": "1.2",
           "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "evidence_id": "NET-2"}
NEW = {"host": "new.bank.example", "port": 9443, "tls_version": "1.3",
       "evidence_id": "NET-10"}
PROCESS = {"process": "/usr/local/bin/openssl", "pid": 9182,
           "host": "payments.bank.example", "evidence_id": "RT-1",
           "observed_at": "2026-11-02T00:00:00Z"}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import nbom_history, network_patterns  # noqa: PLC0415
    from shared_models import attack_patterns  # noqa: PLC0415

    return {"nh": nbom_history, "np": network_patterns, "ap": attack_patterns}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _comparison(before, after):
    nh = _load()["nh"]

    return nh.compare(nh.snapshot(before, taken_at="2026-11-01T00:00:00Z"),
                      nh.snapshot(after, taken_at="2026-11-02T00:00:00Z"))


def _window(modules, before=None, after=None, processes=None):
    return modules["np"].signals(_comparison(before or [PAYMENTS],
                                             after or [DOWNGRADED]),
                                 processes=processes)


def _result(modules, before=None, after=None, processes=None):
    return modules["np"].correlate(_window(modules, before, after, processes))


def row_the_signals(modules: dict[str, Any]) -> dict[str, Any]:
    window = _window(modules, after=[DOWNGRADED, NEW], processes=[PROCESS])
    upgraded = modules["np"].signals(_comparison([{**PAYMENTS, "tls_version": "1.2",
                                                   "evidence_id": "NET-0"}],
                                                [PAYMENTS]))
    undated = _comparison([PAYMENTS], [DOWNGRADED])
    for change in undated["changes"]:
        change.pop("observed_at", None)
    undated["after"]["taken_at"] = None
    probes = [
        _probe("the-review-s-four-changes-become-four-signals",
               {"TLS_DOWNGRADE", "CERTIFICATE_MUTATION", "NEW_ENDPOINT",
                "NEW_PROCESS"} <= set(window["counts"]),
               ", ".join(sorted(window["counts"]))),
        _probe("the-window-is-stated-in-the-answer",
               window["window"]["seconds"] == 3600
               and window["window"]["to"].startswith("2026-11-02"),
               f"{window['window']['seconds']}s ending {window['window']['to']}"),
        _probe("an-upgrade-is-a-change-and-not-a-signal",
               upgraded["signals"] == []
               and any("upgrade" in item["reason"].lower()
                       for item in upgraded["skipped"]),
               "TLS1.2 → TLS1.3 produced no signal"),
        _probe("a-signal-with-no-timestamp-is-not-correlated",
               modules["np"].signals(undated)["undated"] == len(undated["changes"])
               and modules["np"].signals(undated)["signals"] == [],
               "an undated change cannot sit in a window"),
        _probe("a-new-process-is-bound-to-the-host-it-was-seen-on",
               [row["subject"] for row in window["signals"]
                if row["signal"] == "NEW_PROCESS"] == ["payments.bank.example"],
               "the process is attributed to its host, not to an application"),
    ]
    return {"id": "the_signals",
            "question": "which changes are signals, and in what window?",
            "phase": "review 19", "probes": probes}


def row_one_pattern(modules: dict[str, Any]) -> dict[str, Any]:
    result = _result(modules, after=[DOWNGRADED, NEW], processes=[PROCESS])
    combined = [pattern for pattern in result["patterns"]
                if pattern["name"] == "CORRELATED_PATTERN"][0]
    probes = [
        _probe("the-four-signals-become-one-correlated-pattern",
               combined["coinciding_signals"] == sorted(modules["np"].REVIEW_SIGNALS),
               ", ".join(combined["coinciding_signals"])),
        _probe("the-pattern-is-classified-suspicious-activity",
               combined["level"] == 2
               and combined["classification"] == "SUSPICIOUS_ACTIVITY",
               f"level {combined['level']} · {combined['classification']}"),
        _probe("the-pattern-names-its-subjects-and-both-sides-of-the-evidence",
               "payments.bank.example:443" in combined["subjects"]
               and {"NET-1", "NET-9"} <= {value for signal in combined["signals"]
                                          for value in signal["evidence_ids"]},
               ", ".join(combined["subjects"])),
        _probe("each-participating-signal-is-still-listed-separately",
               len(combined["signals"]) >= 4
               and len({signal["signal"] for signal in combined["signals"]}) >= 4,
               f"{len(combined['signals'])} signal(s) inside one pattern"),
        _probe("the-next-action-is-an-investigation-not-a-containment",
               "confirm or dismiss each signal separately" in combined["next_action"],
               combined["next_action"]),
        _probe("the-strongest-thing-said-is-suspicious-activity",
               result["worst"] == "SUSPICIOUS_ACTIVITY"
               and all(pattern["level"] <= modules["np"].MAX_LEVEL
                       for pattern in result["patterns"]),
               result["statement"]),
    ]
    return {"id": "one_pattern",
            "question": "what does the coincidence of these changes amount to?",
            "phase": "review 19", "probes": probes}


def row_what_it_refuses(modules: dict[str, Any]) -> dict[str, Any]:
    np = modules["np"]
    result = _result(modules, after=[DOWNGRADED, NEW], processes=[PROCESS])
    body = json.dumps(result["patterns"]).lower()
    phrases = ("attack detected", "compromise confirmed", "attacker identified")
    probes = [
        _probe("no-pattern-contains-a-verdict-phrase",
               not any(phrase in body for phrase in phrases),
               "a downgrade plus a new process is not an attack"),
        _probe("security-incident-is-named-as-something-this-never-returns",
               "SECURITY_INCIDENT" in result["never"],
               ", ".join(result["never"])),
        _probe("every-pattern-carries-what-it-does-not-prove",
               all(any("attacked" in line for line in pattern["not_proven"])
                   and any("compromised" in line for line in pattern["not_proven"])
                   for pattern in result["patterns"]),
               f"{len(result['patterns'])} pattern(s), all with not_proven"),
        _probe("attribution-and-intent-are-explicitly-absent",
               any("who did it" in line.lower() for line in result["not_proven"]),
               [line for line in result["not_proven"] if "who did it" in line][0]),
        _probe("the-statement-ends-with-not-a-finding-of-compromise",
               result["statement"].endswith("not a finding of compromise"),
               result["statement"][-60:]),
        _probe("a-collection-gap-is-carried-as-a-blind-spot",
               np.signals(_comparison([PAYMENTS], [{**PAYMENTS, "observed": False}]))
               ["blind_spots"] == ["payments.bank.example:443"],
               "an endpoint that stopped answering narrows what the window means"),
    ]
    return {"id": "what_it_refuses",
            "question": "what does the answer refuse to claim, and does it say so?",
            "phase": "review 19", "probes": probes}


def row_the_guards(modules: dict[str, Any]) -> dict[str, Any]:
    np = modules["np"]
    ordinary = np.correlate(np.signals(_comparison([PAYMENTS], [PAYMENTS, NEW]),
                                       processes=[PROCESS]))
    rotation = np.correlate(np.signals(_comparison(
        [PAYMENTS], [{**PAYMENTS, "certificate": {"fingerprint_sha256": "zz99",
                                                  "issuer": "BANK-ICA-01"}}])))
    probes = [
        _probe("a-new-endpoint-and-a-new-process-alone-stay-at-level-one",
               {pattern["name"] for pattern in ordinary["patterns"]} == {"NEW_EXPOSURE"}
               and ordinary["worst"] == "UNEXPECTED_CHANGE",
               ordinary["statement"]),
        _probe("a-lone-certificate-replacement-is-a-regression-not-a-combination",
               "CORRELATED_PATTERN" not in {pattern["name"]
                                            for pattern in rotation["patterns"]}
               and "TRUST_PATH_SHIFT" not in {pattern["name"]
                                              for pattern in rotation["patterns"]},
               ", ".join(pattern["name"] for pattern in rotation["patterns"])),
        _probe("a-disappeared-listener-is-reported-as-ambiguous",
               "decommission and a moved service look the same" in " ".join(
                   pattern["why"] for pattern in np.correlate(np.signals(
                       _comparison([PAYMENTS, PARTNER], [PAYMENTS])))["patterns"]),
               "DISAPPEARANCE at level 1"),
        _probe("a-window-that-is-not-a-window-is-refused",
               _refused(np), "a foreign document is rejected, not correlated"),
        _probe("the-signal-set-is-fixed-so-a-reviewer-can-see-what-is-modelled",
               set(np.SIGNALS) >= {"TLS_DOWNGRADE", "CERTIFICATE_MUTATION",
                                   "NEW_ENDPOINT", "NEW_PROCESS"}
               and np.MAX_LEVEL == 2,
               f"{len(np.SIGNALS)} signal(s), ceiling level {np.MAX_LEVEL}"),
    ]
    return {"id": "the_guards",
            "question": "what keeps a maintenance window out of the suspicious bucket?",
            "phase": "review 19", "probes": probes}


def row_the_shape(modules: dict[str, Any]) -> dict[str, Any]:
    np, ap = modules["np"], modules["ap"]
    result = _result(modules, after=[DOWNGRADED, NEW], processes=[PROCESS])
    pattern = result["patterns"][-1]
    body = np.summary(result)
    probes = [
        _probe("patterns-carry-the-shared-vocabulary-s-level-and-meaning",
               pattern["level_name"] == ap.LEVELS[pattern["level"]]["name"]
               and pattern["level_meaning"] == ap.LEVELS[pattern["level"]]["meaning"],
               f"{pattern['level_name']}: {pattern['level_meaning'][:48]}…"),
        _probe("the-pattern-id-is-stable-for-the-same-participants",
               pattern["pattern_id"] == _result(
                   modules, after=[NEW, DOWNGRADED], processes=[PROCESS]
               )["patterns"][-1]["pattern_id"],
               pattern["pattern_id"]),
        _probe("first-and-last-seen-bound-the-pattern",
               pattern["first_seen"] is not None
               and pattern["last_seen"] >= pattern["first_seen"],
               f"{pattern['first_seen']} → {pattern['last_seen']}"),
        _probe("the-summary-counts-patterns-by-name-and-carries-the-blind-spots",
               body["patterns"] == len(result["patterns"])
               and body["by_name"].get("CORRELATED_PATTERN") == 1
               and body["worst"] == "SUSPICIOUS_ACTIVITY",
               body["statement"][:88] + "…"),
        _probe("nothing-in-the-summary-invents-a-score",
               set(body) == {"schema", "patterns", "by_name", "worst", "blind_spots",
                             "statement", "not_proven"},
               ", ".join(sorted(body))),
    ]
    return {"id": "the_shape",
            "question": "does the pattern read like every other finding in the platform?",
            "phase": "review 19", "probes": probes}


def _refused(np: Any) -> bool:
    try:
        np.correlate({"signals": []})
    except ValueError:
        return True
    return False


ROWS = (row_the_signals, row_one_pattern, row_what_it_refuses, row_the_guards,
        row_the_shape)


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
    np = modules["np"]
    window = _window(modules, after=[DOWNGRADED, NEW], processes=[PROCESS])
    result = np.correlate(window)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "signals": list(np.SIGNALS),
        "patterns": list(np.PATTERNS),
        "max_level": np.MAX_LEVEL,
        "window": window,
        "result": result,
        "summary": np.summary(result),
        "rows": rows,
        "limits": [
            "one window is one comparison. An attacker who waits longer than the "
            "window, or who changes nothing a collector can see, produces no pattern — "
            "an empty result is not a clean estate",
            "the window is anchored on the newest signal in the set, so the same stored "
            "changes always correlate the same way; widening it finds more coincidence "
            "as well as more pattern",
            "a certificate replacement is indistinguishable from an interception "
            "without the PKI's own record, so the pattern points at the PKI owner "
            "instead of deciding",
            "a new process is attributed to the host it was observed on, not to the "
            "application that started it; process-level evidence is guide 146's job",
            "the ceiling is level 2. The platform reserves level 4 for combinations it "
            "can corroborate across independent planes, and one network window is one "
            "plane",
            "no external intelligence, no actor and no motive take part. The output is "
            "a review queue with evidence ids, not an incident",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    window = report["window"]
    result = report["result"]
    lines = [
        "# Network crypto correlation: several changes, one pattern, no verdict",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review item 19: a TLS downgrade plus a certificate mutation plus a new "
        "endpoint plus a new process is a `CORRELATED_PATTERN` at "
        "`SUSPICIOUS_ACTIVITY` — never \"attack detected\".",
        "",
        "```",
        "change ─┐",
        "change ─┼→ signals in one window → pattern (level ≤ 2) → review queue",
        "change ─┘                              └─ not_proven: compromise, actor, intent",
        "```",
        "",
        f"{window['statement']}",
        "",
        f"{result['statement']}",
        "",
        "| signal | derived from |",
        "|---|---|",
        "| `TLS_DOWNGRADE` | `TLS_VERSION_CHANGED` with direction `DOWNGRADE` |",
        "| `CIPHER_DOWNGRADE` | `CIPHER_SUITE_CHANGED` with direction `DOWNGRADE` |",
        "| `CERTIFICATE_MUTATION` | `CERTIFICATE_CHANGED` (rotation and replacement look alike) |",
        "| `TRUST_PATH_CHANGE` | `TRUST_PATH_CHANGED` |",
        "| `NEW_ENDPOINT` / `ENDPOINT_LOST` | `ENDPOINT_ADDED` / `ENDPOINT_REMOVED` |",
        "| `NEW_PROCESS` | a runtime trace on the host |",
        "",
        "| pattern | level | when |",
        "|---|---|---|",
        "| `NETWORK_CRYPTO_REGRESSION` | 2 `SUSPICIOUS_ACTIVITY` | any weakening in the window |",
        "| `TRUST_PATH_SHIFT` | 2 `SUSPICIOUS_ACTIVITY` | downgrade **and** certificate replacement on one endpoint |",
        "| `NEW_EXPOSURE` | 1 `UNEXPECTED_CHANGE` | a listener appeared |",
        "| `DISAPPEARANCE` | 1 `UNEXPECTED_CHANGE` | a listener went away |",
        "| `CORRELATED_PATTERN` | 2 `SUSPICIOUS_ACTIVITY` | ≥2 of the review's four signals, at least one a weakening |",
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
