"""Labeled ground-truth detector calibration (audits 49 P0#4 + 52, round 34).

The production scorecards (`GET /findings/detectors/scorecards`) calibrate
detectors through honest *proxies* — retractions and authority losses —
because production data carries no labels. The accuracy corpus does:
every case is hand-labeled with the exact algorithm families a correct
scanner must report, and hard negatives label outright false positives
(``expected`` empty = anything reported is wrong).

This module turns a corpus benchmark run (``scripts/accuracy_benchmark.py``,
extended in round 34 to carry per-finding detector reports) into per-
detector labeled metrics:

* **TP** — detector *d* reported family *f* in a case whose labels include *f*.
* **FP** — detector *d* reported *f* in a case whose labels exclude *f*
  (including every report on a hard negative).
* **FN** — a labeled family NO detector reported for the case. A miss
  cannot be attributed to one detector (which detector *should* have seen
  it is a coverage question), so FN stays scanner-level and is reported
  honestly as such — per-detector recall is not fabricated.
* **precision** = TP / (TP + FP) per detector. Thin data is thin:
  under ``min_reports`` the detector is reported INSUFFICIENT_DATA with
  raw counts, never a scored tier.

This is labeled calibration over a fixed corpus — it says how detectors
behave on ground truth, while the production scorecards say how they
behave on real traffic. Both surfaces stay separate on purpose.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping

MIN_REPORTS = 20


def labeled_detector_metrics(cases: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Per-detector labeled TP/FP + scanner-level FN over benchmark cases.

    ``cases`` are the per-case rows of the benchmark report (each with
    ``expected`` family list, ``category``, ``reports`` = list of
    {scanner, family}).
    """
    cases = list(cases)
    per_detector: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "files": set(), "negative_fp": 0})
    scanner_fn_families: list[dict] = []
    totals = {"cases": 0, "labeled_families": 0, "reported_families": 0,
              "negative_cases": 0}

    for case in cases:
        expected = set(case.get("expected") or [])
        category = case.get("category") or "positive"
        reports = case.get("reports") or []
        label = f"{case.get('language')}/{case.get('file')}"
        totals["cases"] += 1
        if not expected:
            totals["negative_cases"] += 1
        totals["labeled_families"] += len(expected)

        seen_families: set[str] = set()
        for report in reports:
            detector = str(report.get("scanner") or "unknown")
            family = report.get("family")
            if not family:
                continue
            seen_families.add(family)
            entry = per_detector[detector]
            entry["files"].add(label)
            if family in expected:
                entry["tp"] += 1
                totals["reported_families"] += 1
            else:
                entry["fp"] += 1
                if not expected:
                    entry["negative_fp"] += 1

        for family in sorted(expected - seen_families):
            scanner_fn_families.append({
                "family": family, "case": label, "category": category,
            })

    detectors: list[dict[str, Any]] = []
    for detector in sorted(per_detector):
        entry = per_detector[detector]
        tp, fp = entry["tp"], entry["fp"]
        precision = round(tp / (tp + fp), 4) if (tp + fp) else None
        detectors.append({
            "detector": detector,
            "tp": tp,
            "fp": fp,
            "precision": precision,
            "sufficient_data": (tp + fp) >= MIN_REPORTS,
            "negative_fp": entry["negative_fp"],
            "files_touched": len(entry["files"]),
        })

    fn_total = len(scanner_fn_families)
    return {
        "model": "labeled-ground-truth/detector-calibration-v1",
        "ground_truth": "hand-labeled accuracy corpus (labels are truth, "
                        "not scanner echoes)",
        "detector_metrics": detectors,
        "scanner_level": {
            "fn_families": fn_total,
            "fn_detail": scanner_fn_families[:50],
            "fn_truncated": fn_total > 50,
            "note": "a miss is attributed to the scanner, not to a single "
                    "detector — which detector should have reported a family "
                    "is a coverage question, so per-detector recall is not "
                    "fabricated",
        },
        "corpus": totals,
        "min_reports": MIN_REPORTS,
        "relation_to_scorecards": "labeled metrics measure detectors on "
                                  "ground truth; GET /findings/detectors/"
                                  "scorecards measures them on production "
                                  "traffic via retraction/authority-loss "
                                  "proxies — separate surfaces on purpose",
    }
