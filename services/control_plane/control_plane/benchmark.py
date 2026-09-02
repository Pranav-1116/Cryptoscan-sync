"""Detection benchmarking — measure real accuracy against labelled ground truth.

This backs the "95%+ accuracy" claim with repeatable datasets instead of a
dashboard number. Cases carry a ground-truth label (or "benign") and the
scanner's prediction; we compute the confusion matrix and standard metrics:
precision, recall, F1, false-positive rate and accuracy.
"""

from __future__ import annotations

from typing import Any


def score_predictions(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute detection metrics.

    Each case: {"expected_detection": bool, "predicted_detection": bool,
    "ground_truth": str, "predicted_label": str|None}.

    A prediction is:
      * TP — expected detection and scanner flagged it (label match optional)
      * FP — scanner flagged a benign / non-detectable case
      * TN — benign case correctly not flagged
      * FN — expected detection but scanner missed it
    """
    tp = fp = tn = fn = 0
    mislabeled = 0
    for c in cases:
        expected = bool(c.get("expected_detection", False))
        predicted = bool(c.get("predicted_detection", False))
        if expected and predicted:
            tp += 1
            # even when flagged, a wrong label is a partial error
            if c.get("ground_truth") and c.get("predicted_label") \
                    and str(c["predicted_label"]).lower() not in {"", "unknown"} \
                    and str(c["predicted_label"]).lower() != str(c["ground_truth"]).lower():
                mislabeled += 1
        elif expected and not predicted:
            fn += 1
        elif not expected and predicted:
            fp += 1
        else:
            tn += 1

    def _safe(n: float, d: float) -> float | None:
        return round(n / d, 4) if d else None

    precision = _safe(tp, tp + fp)
    recall = _safe(tp, tp + fn)
    f1 = _safe(2 * tp, 2 * tp + fp + fn)
    fpr = _safe(fp, fp + tn)
    accuracy = _safe(tp + tn, tp + tn + fp + fn)
    total = tp + tn + fp + fn

    return {
        "true_positive": tp, "false_positive": fp,
        "true_negative": tn, "false_negative": fn,
        "mislabeled": mislabeled, "total": total,
        "precision": precision, "recall": recall, "f1": f1,
        "false_positive_rate": fpr, "accuracy": accuracy,
        "meets_95_target": bool(accuracy is not None and accuracy >= 0.95
                                and (recall or 0) >= 0.95),
    }


def meets_target(metrics: dict[str, Any], target: float = 0.95) -> bool:
    acc = metrics.get("accuracy")
    rec = metrics.get("recall")
    return bool(acc is not None and rec is not None and acc >= target and rec >= target)
