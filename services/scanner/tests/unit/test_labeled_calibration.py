"""Labeled ground-truth detector calibration (audits 49 P0#4 + 52, round 34)."""

from __future__ import annotations

from scanner.labeled_calibration import labeled_detector_metrics


def _case(file, expected, reports, category="positive", language="python"):
    return {"language": language, "file": file, "category": category,
            "expected": sorted(expected), "reports": reports}


def test_per_detector_tp_fp_and_precision():
    cases = [
        _case("a.py", ["AES", "RSA"], [
            {"scanner": "ast", "family": "AES"},
            {"scanner": "ast", "family": "RSA"},
            {"scanner": "regex", "family": "AES"},
        ]),
        _case("b.py", ["AES"], [
            {"scanner": "ast", "family": "AES"},
            {"scanner": "regex", "family": "DES"},  # regex FP
        ]),
    ]
    out = labeled_detector_metrics(cases)
    detectors = {d["detector"]: d for d in out["detector_metrics"]}
    assert detectors["ast"]["tp"] == 3 and detectors["ast"]["fp"] == 0
    assert detectors["ast"]["precision"] == 1.0
    assert detectors["regex"]["tp"] == 1 and detectors["regex"]["fp"] == 1
    assert detectors["regex"]["precision"] == 0.5
    # corpus rollup
    assert out["corpus"]["cases"] == 2
    assert out["corpus"]["labeled_families"] == 3


def test_hard_negatives_label_every_report_false():
    cases = [
        _case("neg.py", [], [{"scanner": "ast", "family": "MD5"}],
              category="negative"),
    ]
    out = labeled_detector_metrics(cases)
    det = out["detector_metrics"][0]
    assert det["detector"] == "ast" and det["fp"] == 1
    assert det["negative_fp"] == 1
    assert det["precision"] == 0.0
    assert out["corpus"]["negative_cases"] == 1


def test_misses_stay_scanner_level():
    cases = [
        _case("a.py", ["AES", "RSA", "MD5"], [
            {"scanner": "ast", "family": "AES"},  # RSA + MD5 missed entirely
        ]),
    ]
    out = labeled_detector_metrics(cases)
    assert out["scanner_level"]["fn_families"] == 2
    assert {f["family"] for f in out["scanner_level"]["fn_detail"]} == {"RSA", "MD5"}
    # the miss is NOT attributed to a detector
    det = out["detector_metrics"][0]
    assert "fn" not in det and "recall" not in det
    assert "coverage question" in out["scanner_level"]["note"]


def test_thin_data_is_thin_not_scored():
    # a detector with a single report is INSUFFICIENT_DATA with raw counts
    cases = [_case("a.py", ["AES"], [{"scanner": "once", "family": "AES"}])]
    out = labeled_detector_metrics(cases)
    det = out["detector_metrics"][0]
    assert det["tp"] == 1 and det["precision"] == 1.0
    assert det["sufficient_data"] is False
    assert out["min_reports"] >= 20


def test_empty_corpus_is_empty():
    out = labeled_detector_metrics([])
    assert out["detector_metrics"] == []
    assert out["scanner_level"]["fn_families"] == 0
    assert out["corpus"]["cases"] == 0
