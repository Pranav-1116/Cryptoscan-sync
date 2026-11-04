#!/usr/bin/env python3
"""Score the platform against a planted answer key, with UNKNOWN kept out of the wrong column.

What this measures, exactly
---------------------------
A synthetic bank (`cbom.accuracy_corpus`) whose answer key the pipeline cannot see, and two
pipelines scored against it:

* **the platform's rule** — observation → fact, capability kept apart from usage, absence in four
  states, disagreement preserved;
* **the shortcut** the review warned about — ``collector → CBOM``, where every algorithm a library
  *can* do is reported as one the application *does*.

The second exists so the cost of the shortcut is a number on a dashboard instead of an argument in
a design review.

**What it does not measure:** the device collectors. Every observation here is a recorded artefact,
so this measures the derivation rules against a key — not that a real bank scans at 95%. The JSON
carries a ``scope`` field that says so, and the dashboard repeats it under the title.

    python scripts/accuracy_ground_truth.py                       # the table
    python scripts/accuracy_ground_truth.py --json out.json --md dashboard.md
    python scripts/accuracy_ground_truth.py --gate                # non-zero if a target is missed
    python scripts/accuracy_ground_truth.py --gate --baseline previous.json

``--gate --baseline`` is the ratchet: a metric that dropped by more than ``--tolerance`` (or a
ceiling that rose) fails, so this guide's numbers cannot quietly become last quarter's.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for area in ("services", "shared"):
    for path in sorted((ROOT / area).iterdir()):
        if path.is_dir() and str(path) not in sys.path:
            sys.path.insert(0, str(path))

from cbom import accuracy  # noqa: E402
from cbom import accuracy_corpus as corpus_module  # noqa: E402

SCHEMA = "cryptoscan.accuracy-report/1"

SCOPE = (
    "the fact-derivation rules, scored against a planted answer key. The device collectors are "
    "not exercised here: every observation is a recorded artefact. A pass means the rules keep "
    "capability apart from usage, preserve disagreement, and refuse to turn a gap into an "
    "absence — not that a real bank's estate scans at this precision."
)


def measure() -> dict:
    """Both pipelines, on the same corpus, against the same key."""
    corpus = corpus_module.build()

    rigorous_predictions = corpus_module.rigorous_predictions(corpus)
    rigorous = accuracy.evaluate(rigorous_predictions,
                                 corpus_module.truth_for(rigorous_predictions, corpus))

    naive_predictions = corpus_module.naive_predictions(corpus)
    naive = accuracy.evaluate(naive_predictions,
                              corpus_module.truth_for(naive_predictions, corpus))

    return {
        "schema": SCHEMA,
        "scope": SCOPE,
        "corpus": corpus_module.counts_summary(corpus),
        "rigorous": rigorous,
        "naive": naive,
        "comparison": {
            "algorithm_precision_delta": _delta(rigorous, naive, "algorithm_precision"),
            "false_positive_rate_delta": _delta(rigorous, naive, "false_positive_rate"),
            "statement": ("the shortcut is not slightly worse: it reports capability as usage, so "
                          "its precision falls and its false-positive rate becomes the rate at "
                          "which libraries merely exist"),
        },
    }


def _delta(rigorous: dict, naive: dict, metric: str):
    left = rigorous["measured"].get(metric)
    right = naive["measured"].get(metric)
    if left is None or right is None:
        return None
    return round(right - left, 6)


def table(report: dict) -> str:
    lines = ["pipeline   metric                          value   verdict",
             "---------- ------------------------------- ------- -------"]
    for name in ("rigorous", "naive"):
        block = report[name]
        for metric, value in block["measured"].items():
            if value is None:
                shown, verdict = "—", "n/a"
            else:
                shown = f"{value:.1%}"
                target = block["targets"][metric]
                ok = value <= target if metric in accuracy.CEILINGS else value >= target
                verdict = "PASS" if ok else "FAIL"
            lines.append(f"{name:<10} {metric:<31} {shown:>7} {verdict}")
    return "\n".join(lines)


def dashboard(report: dict) -> str:
    rigorous, naive = report["rigorous"], report["naive"]
    lines = [
        "# Accuracy against a planted ground truth",
        "",
        "> " + report["scope"].replace(". ", ".\n> "),
        "",
        "## The two pipelines",
        "",
        "| Metric | Target | Fact rule | Shortcut (`collector → CBOM`) |",
        "|---|---|---|---|",
    ]
    for metric, target in rigorous["targets"].items():
        bound = (f"≤ {target:.0%}" if metric in accuracy.CEILINGS else f"≥ {target:.0%}")
        lines.append(f"| {metric.replace('_', ' ')} | {bound} | "
                     f"{_pct(rigorous['measured'].get(metric))} | "
                     f"{_pct(naive['measured'].get(metric))} |")

    lines += ["", "## Per dimension (fact rule)", "",
              "| Dimension | Precision | Recall | Answered | Unresolved | TP | FP | TN | FN |",
              "|---|---|---|---|---|---|---|---|---|"]
    for dimension, summary in sorted(rigorous["dimensions"].items()):
        counts = summary["counts"]
        lines.append(
            f"| {dimension} | {_pct(summary['precision'])} | {_pct(summary['recall'])} | "
            f"{_pct(summary['answered'])} | {_pct(summary['unresolved_rate'])} | "
            f"{counts['tp']} | {counts['fp']} | {counts['tn']} | {counts['fn']} |")

    lines += ["", "## What the shortcut costs", "",
              f"* algorithm precision {_pct(naive['measured'].get('algorithm_precision'))} against "
              f"{_pct(rigorous['measured'].get('algorithm_precision'))}",
              f"* false-positive rate {_pct(naive['measured'].get('false_positive_rate'))} against "
              f"{_pct(rigorous['measured'].get('false_positive_rate'))}",
              f"* {len(naive['failures'])} gate(s) fail for the shortcut, "
              f"{len(rigorous['failures'])} for the rule",
              "", "## Counting rules", ""]
    for name, explanation in rigorous["counting_rules"].items():
        lines.append(f"* **{name.replace('_', ' ')}** — {explanation}")

    lines += ["", "## Hard cases in the corpus", ""]
    lines += [f"* {case}" for case in report["corpus"]["hard_cases"]]
    return "\n".join(lines) + "\n"


def _pct(value) -> str:
    return "—" if value is None else f"{value:.1%}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", default=None, help="write the report here")
    parser.add_argument("--md", default=None, help="write the dashboard here")
    parser.add_argument("--baseline", default=None,
                        help="a previous report; a metric worse by more than --tolerance fails")
    parser.add_argument("--tolerance", type=float, default=0.005)
    parser.add_argument("--gate", action="store_true",
                        help="exit non-zero when a target is missed or a metric regressed")
    parser.add_argument("--naive", action="store_true",
                        help="score the shortcut pipeline instead of the platform's rule")
    args = parser.parse_args(argv)

    report = measure()
    selected = "naive" if args.naive else "rigorous"
    report["selected"] = selected
    block = report[selected]

    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        previous = baseline.get(selected) or baseline.get("rigorous") or {}
        report["regression"] = accuracy.compare(previous, block, tolerance=args.tolerance)

    print(table(report))
    print()
    print(f"rigorous: {'PASS' if report['rigorous']['ok'] else 'FAIL'} · "
          f"naive: {'PASS' if report['naive']['ok'] else 'FAIL'} · "
          f"failure(s) rigorous={len(report['rigorous']['failures'])} "
          f"naive={len(report['naive']['failures'])}")
    regression = report.get("regression")
    if regression:
        print(f"regression vs baseline: {regression['statement']}")

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n",
                       encoding="utf-8")
    if args.md:
        out = Path(args.md)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(dashboard(report), encoding="utf-8")

    if not args.gate:
        return 0
    failed = not block["ok"] or (regression is not None and regression["ok"] is False)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
