#!/usr/bin/env python3
"""Guide 150 — component completeness: unmeasured is not clean, partial is not complete.

A component with no findings is only "a component without cryptography" when
something finished looking. Between those two sentences sit three questions:

    was the component inspected at all?
    did every task that ran finish?
    do the tasks agree?

``cbom.inventory_completeness`` answers them per component and refuses three
tempting collapses: unmeasured is not clean, one unfinished task makes the
component ``INCOMPLETE`` whatever the finished ones found, and tasks that
disagree produce ``CONTRADICTED`` with both evidence ids rather than the more
convenient answer.

The states are deliberately not ordered by severity — they are different
*readings* of an absence, and only ``COMPLETE`` and measured ``EMPTY`` may be
counted when a total is quoted.
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
SCHEMA = "cryptoscan.cbom-inventory-completeness-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

ic_module: Any = None

SEMGREP = {"task": "semgrep-crypto", "status": "COMPLETE"}
SYFT = {"task": "syft-sbom", "status": "COMPLETE"}
FINDING = {"task": "semgrep-crypto", "algorithm": "AES-128-CBC", "evidence_id": "EV-1"}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import inventory_completeness  # noqa: PLC0415

    global ic_module  # set once, so the short _c() helper can reach the module
    ic_module = inventory_completeness
    return {"ic": inventory_completeness}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _component(tasks, claims=(), name="payments"):
    return {"name": name, "tasks": list(tasks), "claims": list(claims)}


def _c(tasks, claims=(), name=None):
    """``inventory_completeness.component`` takes claims first; this keeps the calls
    below readable in the order the prose uses (tasks, then what they found)."""
    return ic_module.component(list(claims), list(tasks), name=name)




# --------------------------------------------------------------------------- #


def row_four_readings(modules: dict[str, Any]) -> dict[str, Any]:
    ic = modules["ic"]
    unmeasured = _c([], [], name="legacy-batch")
    incomplete = _c([SEMGREP, {"task": "syft-sbom", "status": "TIMEOUT"}],
                              [FINDING], name="payments")
    empty = _c([SYFT, SEMGREP], [], name="clean")
    complete = _c([SEMGREP], [FINDING], name="gateway")
    probes = [
        _probe("a-component-nobody-scanned-is-unmeasured",
               unmeasured["state"] == "UNMEASURED" and unmeasured["quotable"] is False,
               unmeasured["statement"]),
        _probe("an-unfinished-task-makes-the-component-incomplete",
               incomplete["state"] == "INCOMPLETE"
               and [row["task"] for row in incomplete["unfinished_tasks"]]
               == ["syft-sbom"],
               incomplete["statement"]),
        _probe("every-task-finished-finding-nothing-is-a-measurement",
               empty["state"] == "EMPTY" and empty["quotable"] is True,
               empty["statement"]),
        _probe("agreement-is-complete",
               complete["state"] == "COMPLETE" and complete["quotable"] is True,
               complete["statement"]),
        _probe("every-state-has-a-reading-of-what-an-absence-means",
               all(state in ic.READING for state in ic.STATES),
               "; ".join(f"{state}: {ic.READING[state][:40]}…" for state in ic.STATES)),
        _probe("the-four-states-stay-four-states",
               ic.STATES == ("UNMEASURED", "INCOMPLETE", "EMPTY", "CONTRADICTED",
                             "COMPLETE"),
               " → ".join(ic.STATES)),
    ]
    return {"id": "four_readings",
            "question": "are \"we did not look\" and \"we found nothing\" the same sentence?",
            "phase": "review 18 / 19", "probes": probes}


def row_contradiction(modules: dict[str, Any]) -> dict[str, Any]:
    clean = {"task": "syft-sbom", "status": "COMPLETE", "found": False}
    also_clean = {"task": "trivy", "status": "COMPLETE", "found": False}
    single = _c([clean, SEMGREP], [FINDING])
    majority = _c([clean, also_clean, SEMGREP], [FINDING])
    unfinished = _c([clean, SEMGREP, {"task": "trivy", "status": "FAILED"}],
                              [FINDING])
    agreeing = _c([SYFT, SEMGREP],
                            [FINDING, {"task": "syft-sbom", "algorithm": "AES-128-CBC",
                                       "evidence_id": "EV-2"}])
    probes = [
        _probe("one-task-saying-clean-against-another-finding-is-a-contradiction",
               single["state"] == "CONTRADICTED"
               and single["contradictions"][0]["empty_from"] == "syft-sbom",
               single["contradictions"][0]["statement"]),
        _probe("the-contradiction-carries-both-evidence-ids",
               single["contradictions"][0]["evidence_ids"] == ["EV-1"],
               ", ".join(single["contradictions"][0]["evidence_ids"])),
        _probe("a-contradiction-is-not-a-majority-vote",
               majority["state"] == "CONTRADICTED"
               and len(majority["contradictions"]) == 2,
               f"{len(majority['contradictions'])} contradiction(s) from three tasks"),
        _probe("an-unfinished-task-is-the-weaker-claim-and-wins",
               unfinished["state"] == "INCOMPLETE"
               and bool(unfinished["contradictions"]),
               "both are recorded; the state reports the one that limits what may be said"),
        _probe("two-tasks-agreeing-are-one-algorithm-with-both-evidences",
               agreeing["state"] == "COMPLETE"
               and agreeing["by_algorithm"][0]["evidence_ids"] == ["EV-1", "EV-2"],
               json.dumps(agreeing["by_algorithm"][0], sort_keys=True)),
    ]
    return {"id": "contradiction",
            "question": "what happens when two tools disagree about the same component?",
            "phase": "review 18 / 19", "probes": probes}


def row_unweighable(modules: dict[str, Any]) -> dict[str, Any]:
    unfinished = _c([{"task": "semgrep-crypto", "status": "TIMEOUT"}], [FINDING])
    never_ran = _c([SYFT], [{"task": "gitleaks", "algorithm": "RSA-2048",
                                       "evidence_id": "EV-3"}])
    no_evidence = _c([SEMGREP], [{"task": "semgrep-crypto",
                                            "algorithm": "AES-128-CBC"}])
    no_task = _c([SEMGREP], [{"algorithm": "AES-128-CBC",
                                        "evidence_id": "EV-1"}])
    not_object = _c([SEMGREP], ["AES-128-CBC"])
    no_status = _c([{"task": "half-run"}], [])
    probes = [
        _probe("a-finding-from-an-unfinished-task-is-a-candidate",
               unfinished["findings"] == []
               and "not quotable" in unfinished["candidates"][0]["reason"],
               unfinished["candidates"][0]["reason"]),
        _probe("a-finding-from-a-task-that-never-ran-is-refused",
               "never ran" in never_ran["refused"][0]["reason"],
               never_ran["refused"][0]["reason"]),
        _probe("a-finding-with-no-evidence-id-is-refused",
               "no evidence id" in no_evidence["refused"][0]["reason"],
               no_evidence["refused"][0]["reason"]),
        _probe("a-finding-that-names-no-task-cannot-be-weighed",
               "names no task" in no_task["refused"][0]["reason"],
               no_task["refused"][0]["reason"]),
        _probe("a-claim-that-is-not-an-object-is-refused",
               not_object["refused"][0]["reason"] == "a claim must be an object",
               not_object["refused"][0]["reason"]),
        _probe("a-task-with-no-status-is-unfinished",
               no_status["state"] == "INCOMPLETE"
               and no_status["unfinished_tasks"][0]["status"] == "UNKNOWN",
               "silence about a task's outcome is not an outcome"),
    ]
    return {"id": "unweighable",
            "question": "which claims cannot be counted, and why?",
            "phase": "review 18 / 12", "probes": probes}


def row_the_total(modules: dict[str, Any]) -> dict[str, Any]:
    ic = modules["ic"]
    def built(*rows):
        return ic.inventory([_c(item["tasks"], item["claims"], name=item["name"])
                             for item in rows])
    settled = built({"name": "a", "tasks": [SEMGREP], "claims": [FINDING]},
                    {"name": "b", "tasks": [SEMGREP], "claims": []})
    unmeasured = built({"name": "a", "tasks": [SEMGREP], "claims": [FINDING]},
                       {"name": "b", "tasks": [], "claims": []})
    incomplete = built({"name": "a", "tasks": [SEMGREP], "claims": [FINDING]},
                       {"name": "b", "tasks": [{"task": "t", "status": "TIMEOUT"}],
                        "claims": []})
    nothing = ic.inventory([])
    probes = [
        _probe("a-measured-empty-component-makes-a-total-quotable",
               settled["may_report_total"] is True and settled["complete_share"] == 50.0,
               settled["statement"]),
        _probe("an-unmeasured-component-stops-the-total",
               unmeasured["may_report_total"] is False
               and unmeasured["unmeasurable"] == ["b"],
               unmeasured["statement"]),
        _probe("an-incomplete-component-stops-the-total-too",
               incomplete["may_report_total"] is False
               and incomplete["counts"]["INCOMPLETE"] == 1,
               incomplete["statement"]),
        _probe("the-counts-are-per-state-not-a-percentage",
               incomplete["counts"] == {"COMPLETE": 1, "CONTRADICTED": 0, "EMPTY": 0,
                                        "INCOMPLETE": 1, "UNMEASURED": 0},
               json.dumps(incomplete["counts"], sort_keys=True)),
        _probe("an-empty-inventory-quotes-nothing",
               nothing["components"] == 0 and nothing["may_report_total"] is False
               and nothing["complete_share"] == 0.0,
               nothing["statement"]),
    ]
    return {"id": "the_total",
            "question": "which total may be quoted, and from which rows?",
            "phase": "review 18", "probes": probes}


ROWS = (row_four_readings, row_contradiction, row_unweighable, row_the_total)


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
    sample = ic.inventory([
        _c([SEMGREP], [FINDING], name="payments"),
        _c([SYFT, SEMGREP], [], name="clean-gateway"),
        _c([SEMGREP, {"task": "syft-sbom", "status": "TIMEOUT"}],
                     [FINDING], name="legacy-batch"),
        _c([], [], name="unscanned-batch"),
    ])
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "sample": sample,
        "states": list(ic.STATES),
        "readings": dict(ic.READING),
        "rows": rows,
        "limits": [
            "the module weighs the tasks it is told about. A component whose collector "
            "was never registered looks UNMEASURED, which is honest, but a component whose "
            "collector was registered and silently skipped looks COMPLETE or EMPTY",
            "'found: false' is a claim the tool must make. A tool that finishes without "
            "saying whether it looked at everything can only ever produce INCOMPLETE or "
            "COMPLETE, never a contradiction, and the contradiction is the useful row",
            "a contradiction is reported per algorithm, not per location. Two tools "
            "disagreeing about AES-128-CBC in the same file produce one row, and the "
            "reviewer still has to read the evidence",
            "the state is per component, not per file or per directory. A component that "
            "was 99% scanned is INCOMPLETE, which is the right answer and also loses the "
            "information about which 1% is missing — the task's own reason field carries "
            "that, if the collector fills it",
            "EMPTY is quotable, but it says only that the tasks that ran found nothing. It "
            "does not say the tasks were the right ones, and no completeness model can "
            "answer that",
            "the inventory total is a statement about components, not about systems. "
            "Joining it to the estate coverage rollup is the coverage renderer's job, and "
            "the two totals must not be added together",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    sample = report["sample"]
    lines = [
        "# Component completeness: unmeasured is not clean",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Three questions sit between *no findings* and *no cryptography*:",
        "",
        "```",
        "was the component inspected at all?",
        "did every task that ran finish?",
        "do the tasks agree?",
        "```",
        "",
        "| state | what an absence of findings means | quotable |",
        "|---|---|---|",
    ]
    for state in report["states"]:
        quotable = "yes" if state in ("COMPLETE", "EMPTY") else "no"
        lines.append(f"| `{state}` | {report['readings'][state]} | {quotable} |")
    lines += [
        "",
        f"Sample inventory: {sample['statement']}.",
        "",
        "1. **unmeasured is not clean** — a component with no task says nothing about "
        "cryptography, not that it has none;",
        "2. **one unfinished task is enough** — the component is `INCOMPLETE` whatever the "
        "finished tasks found, because the part nobody looked at is where old crypto lives;",
        "3. **a contradiction is not a majority** — one task reporting clean while another "
        "reports a finding is `CONTRADICTED`, carrying both evidence ids;",
        "4. **a claim that cannot be weighed is named** — from an unfinished task it is a "
        "*candidate*, from a task that never ran, with no evidence id, or with no task at "
        "all it is *refused*;",
        "5. **the total is derived, not asserted** — only `COMPLETE` and measured `EMPTY` "
        "components may be counted, and `may_report_total` says whether any total is "
        "quotable at all.",
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
