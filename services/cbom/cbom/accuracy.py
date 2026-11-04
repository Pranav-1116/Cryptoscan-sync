"""Scoring accuracy without rewarding a scanner for keeping quiet.

The review asked for 95% precision and 95% recall. It did not ask for the thing that usually
happens next: a product that learns to answer only the questions it can already win. Two failure
modes sit either side of this module and both look like progress on a dashboard:

* **UNKNOWN counted as wrong.** Then honesty costs the same as a wrong answer, and the cheapest
  way to raise the number is to guess. The confident false positive — *"this application uses
  AES-256-GCM"*, derived from a library's capability list — is exactly the guess this teaches.
* **UNKNOWN counted as nothing.** Then a scanner reaches 100% precision by answering three
  questions out of a thousand and marking the rest unexamined.

So the model here has one rule with two halves, and both halves are gated:

1. ``UNKNOWN`` (and ``COLLECTION_FAILED`` / ``NOT_OBSERVABLE``) is never a false positive and
   never a false negative. It is counted as **unresolved** and reported beside the metric, never
   inside it. Declining an item the truth does not hold is a **true negative**; asserting a value
   for an item no collector can see is a **false positive**.
2. **Silence is visible.** ``answered`` and ``unresolved_rate`` are first-class metrics, the gate
   caps how much of a dimension may go unanswered (:data:`MAX_UNRESOLVED`) and how little may be
   answered (:data:`MIN_ANSWERED`), and a dimension with nothing to measure fails as
   *not measured* rather than passing as 0/0.

The dimensions are the review's list — assets, algorithms, key sizes, certificates, network
paths, dependencies, system ownership, evidence attribution — and :func:`compare` is the ratchet
that keeps a release from trading one of them for another.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.accuracy/1"

FOUND = "FOUND"
CONFLICT = "CONFLICT"
UNKNOWN = "UNKNOWN"
NOT_OBSERVABLE = "NOT_OBSERVABLE"
NOT_FOUND_WITHIN_SCOPE = "NOT_FOUND_WITHIN_SCOPE"
COLLECTION_FAILED = "COLLECTION_FAILED"

#: States that decline to answer. They are unresolved, not wrong — and not free, see MIN_ANSWERED.
UNRESOLVED_STATES = frozenset({UNKNOWN, NOT_OBSERVABLE, COLLECTION_FAILED})

#: The value a ground truth uses when the right answer is "these sources disagree".
TRUTH_CONFLICT = "CONFLICT"

# --------------------------------------------------------------------------- #
# dimensions and targets
# --------------------------------------------------------------------------- #

DIMENSIONS: tuple[str, ...] = (
    "asset", "algorithm", "key_size", "certificate", "network", "dependency", "system_owner",
    "evidence_attribution",
)

#: Dimensions scored with precision *and* recall, because both halves are separately meaningful.
_PRECISION_RECALL = ("asset", "algorithm")

#: Dimensions scored as one accuracy number: for these, a wrong "absent" and a wrong "present" are
#: equally bad, and there is no class imbalance to hide behind.
_ACCURACY = ("key_size", "certificate", "network", "dependency", "system_owner",
             "evidence_attribution")

#: The review's numbers, as shipped: correctness targets are floors, rates are ceilings.
TARGETS: dict[str, float] = {
    "asset_precision": 0.95,
    "asset_recall": 0.95,
    "algorithm_precision": 0.95,
    "algorithm_recall": 0.95,
    "key_size_accuracy": 0.98,
    "certificate_accuracy": 0.98,
    "network_accuracy": 0.98,
    "dependency_accuracy": 0.95,
    "system_owner_accuracy": 0.95,
    "evidence_attribution_accuracy": 0.98,
    "false_positive_rate": 0.05,
    "false_negative_rate": 0.05,
}

#: Metrics read in the other direction: lower is better, and a rise is a regression.
CEILINGS = frozenset({"false_positive_rate", "false_negative_rate"})

#: A dimension answered less than this fails the gate however good its precision is.
MIN_ANSWERED = 0.80

#: A dimension left unresolved more than this fails the gate however good its precision looks.
MAX_UNRESOLVED = 0.25

#: The metric that an accuracy dimension is scored on, and the dimension behind each metric.
_METRIC_SOURCE: dict[str, str] = {
    **{f"{name}_precision": name for name in _PRECISION_RECALL},
    **{f"{name}_recall": name for name in _PRECISION_RECALL},
    **{f"{name}_accuracy": name for name in _ACCURACY},
}

COUNTING_RULES: Mapping[str, str] = {
    "unknown": "UNKNOWN is not a false positive and not a false negative: it is counted as "
               "unresolved and reported in `unresolved_rate`, beside the metric and never inside "
               "it",
    "unobservable": "declining an item the ground truth marks unobservable is a true negative; "
                    "asserting a value for it is a false positive",
    "absent": "declining an item the ground truth does not hold is a true negative; asserting a "
              "value for it is a false positive",
    "wrong_value": "a confidently wrong value costs one false positive and one false negative",
    "unpredicted": "an observable truth item with no prediction is a false negative, and is "
                   "counted separately as `unpredicted`",
    "attribution": "evidence attribution asks whether the cited ids are real and belong to this "
                   "subject — citing more than one is corroboration, not an error; citing an id "
                   "that does not exist is a false positive and a false negative",
    "answered": "`answered` = (TP + FP + TN) / (TP + FP + TN + FN + unresolved): every point of "
                f"precision bought by answering less shows up here, and the gate requires "
                f"{MIN_ANSWERED:.0%}",
    "silence": f"a dimension left unresolved above {MAX_UNRESOLVED:.0%} fails the gate: "
               "'UNKNOWN is not wrong' and 'UNKNOWN is not an escape hatch' are the same rule",
    "accuracy": "an accuracy dimension counts (TP + TN) / (TP + TN + FP + FN): a wrong 'absent' "
                "costs the same as a wrong 'present'",
    "not_measured": "a dimension with nothing observable fails as NOT MEASURED rather than "
                    "passing as 0/0",
}


# --------------------------------------------------------------------------- #
# inputs
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class Truth:
    """One item of the answer key the pipeline never sees."""

    dimension: str
    subject: str
    attribute: str
    value: Any
    observable: bool = True

    def __post_init__(self) -> None:
        if self.dimension not in DIMENSIONS:
            raise ValueError(f"unknown dimension {self.dimension!r}; one of {DIMENSIONS}")

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.dimension, self.subject, self.attribute)

    @property
    def holds_absence(self) -> bool:
        return self.value is None

    @property
    def holds_conflict(self) -> bool:
        return isinstance(self.value, str) and self.value.upper() == TRUTH_CONFLICT


@dataclass(frozen=True, slots=True)
class Prediction:
    """What the pipeline says, with the evidence it says it on."""

    dimension: str
    subject: str
    attribute: str
    value: Any
    state: str = FOUND
    evidence_ids: tuple[str, ...] = ()
    scope: str = ""

    def __post_init__(self) -> None:
        if self.dimension not in DIMENSIONS:
            raise ValueError(f"unknown dimension {self.dimension!r}; one of {DIMENSIONS}")
        if self.state not in {FOUND, CONFLICT, UNKNOWN, NOT_OBSERVABLE, NOT_FOUND_WITHIN_SCOPE,
                              COLLECTION_FAILED}:
            raise ValueError(f"unknown prediction state {self.state!r}")

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.dimension, self.subject, self.attribute)

    @property
    def answered(self) -> bool:
        return self.state in {FOUND, CONFLICT, NOT_FOUND_WITHIN_SCOPE}


@dataclass(slots=True)
class Counts:
    """The only place true and false are decided."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    unresolved: int = 0
    not_observable: int = 0
    unpredicted: int = 0

    @property
    def observable(self) -> int:
        """Items that got a verdict: ``answered`` is computed over these."""
        return self.tp + self.fp + self.tn + self.fn

    @property
    def total(self) -> int:
        """Every item a verdict was possible for: correct, incorrect, or declined."""
        return self.observable + self.unresolved

    def as_dict(self) -> dict[str, int]:
        return {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
                "unresolved": self.unresolved, "not_observable": self.not_observable,
                "unpredicted": self.unpredicted}

    def __add__(self, other: "Counts") -> "Counts":
        return Counts(*(getattr(self, name) + getattr(other, name) for name in
                        ("tp", "fp", "tn", "fn", "unresolved", "not_observable", "unpredicted")))


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #

def _same(left: Any, right: Any) -> bool:
    if isinstance(left, str) and isinstance(right, str):
        return left.strip().casefold() == right.strip().casefold()
    return left == right


def _cited_evidence(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, (tuple, list, set, frozenset)):
        return {str(item).strip() for item in value if str(item).strip()}
    return {part.strip() for part in str(value).split(",") if part.strip()}


def _attribution_correct(prediction: "Prediction", truth: "Truth") -> bool:
    """Attribution is not string equality: it asks whether the cited ids are real.

    An answer may cite one evidence id or five — corroboration is not a mistake. What it may not
    do is cite an id that does not exist, or one that belongs to another subject. That is exactly
    the shortcut's failure: it cites one fabricated id for everything.
    """
    cited = _cited_evidence(prediction.value) or set(prediction.evidence_ids)
    legitimate = _cited_evidence(truth.value)
    return bool(cited) and bool(legitimate) and cited <= legitimate


def _score_one(prediction: Prediction | None, truth: Truth, counts: Counts) -> None:
    """The counting rules, in the order that matters.

    The order is load-bearing: absence and unobservability are judged *before* the prediction's
    state, because a correct decline on an item the truth does not hold is a true negative and not
    an "unresolved" — reading it the other way would make honesty look like a gap.
    """
    if not truth.observable:
        counts.not_observable += 1
        if prediction is None or not prediction.answered or prediction.state == NOT_OBSERVABLE:
            counts.tn += 1
            return
        # asserting something about an item nobody can see
        counts.fp += 1
        return

    if truth.holds_absence:
        if prediction is None or prediction.state == UNKNOWN:
            counts.tn += 1
        elif prediction.value is None:
            counts.tn += 1                      # NOT_FOUND_WITHIN_SCOPE is an answer
        else:
            counts.fp += 1
        return

    if truth.holds_conflict:
        if prediction is None:
            counts.fn += 1
            counts.unpredicted += 1
            return
        if not prediction.answered:
            counts.unresolved += 1              # declining to adjudicate is not an error
            return
        if prediction.state == CONFLICT:
            counts.tp += 1
            return
        counts.fp += 1                          # picked a side of a disagreement
        counts.fn += 1
        return

    if prediction is None:
        counts.fn += 1
        counts.unpredicted += 1
        return
    if not prediction.answered:
        counts.unresolved += 1
        return
    if prediction.state == NOT_FOUND_WITHIN_SCOPE and prediction.value is None:
        counts.fn += 1                          # the truth holds a value; "absent" is wrong
        return
    if prediction.state == CONFLICT:
        counts.fn += 1                          # a contradiction where the key has one answer
        return
    if truth.dimension == "evidence_attribution":
        if _attribution_correct(prediction, truth):
            counts.tp += 1
        else:
            counts.fp += 1
            counts.fn += 1
        return
    if _same(prediction.value, truth.value):
        counts.tp += 1
    else:
        counts.fp += 1
        counts.fn += 1


def score(predictions: Iterable[Prediction], truths: Iterable[Truth]) -> dict[str, Counts]:
    """TP/FP/TN/FN per dimension, over the union of both sides' keys."""
    truth_by_key = {truth.key: truth for truth in truths}
    prediction_by_key = {prediction.key: prediction for prediction in predictions}
    counts: dict[str, Counts] = {}
    for key in sorted(set(truth_by_key) | set(prediction_by_key)):
        truth = truth_by_key.get(key)
        prediction = prediction_by_key.get(key)
        dimension = key[0]
        bucket = counts.setdefault(dimension, Counts())
        if truth is None:
            # A prediction for an item the key does not hold: correct only if it declines.
            if prediction is not None and prediction.value is not None:
                bucket.fp += 1
            else:
                bucket.tn += 1
            continue
        _score_one(prediction, truth, bucket)
    return dict(sorted(counts.items()))


# --------------------------------------------------------------------------- #
# metrics
# --------------------------------------------------------------------------- #

def metrics(counts: Counts) -> dict[str, float | None]:
    """Every ratio, with 0/0 answered as ``None`` — a gap, not a perfect score."""
    precision = _ratio(counts.tp, counts.tp + counts.fp)
    recall = _ratio(counts.tp, counts.tp + counts.fn)
    return {
        "precision": precision,
        "recall": recall,
        "accuracy": _ratio(counts.tp + counts.tn, counts.observable),
        # Answered counts every verdict the scanner actually gave — including the correct
        # "absent" — against every question it could have answered. A dimension that declines
        # half its items therefore reads 50% answered however good its precision is.
        "answered": _ratio(counts.tp + counts.fp + counts.tn, counts.total),
        "unresolved_rate": _ratio(counts.unresolved, counts.total),
        "false_positive_rate": _ratio(counts.fp, counts.fp + counts.tn),
        "false_negative_rate": _ratio(counts.fn, counts.fn + counts.tp),
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator


def _summarise(dimension: str, counts: Counts) -> dict[str, Any]:
    numbers = metrics(counts)
    if dimension in _PRECISION_RECALL:
        measured = {"precision": numbers["precision"], "recall": numbers["recall"]}
    else:
        measured = {"accuracy": numbers["accuracy"]}
    return {
        "dimension": dimension,
        **{key: numbers[key] for key in ("precision", "recall", "accuracy", "answered",
                                         "unresolved_rate")},
        "measured": measured,
        "counts": counts.as_dict(),
        "rules": dict(COUNTING_RULES),
    }


def totals(dimensions: Mapping[str, Mapping[str, Any]]) -> Counts:
    total = Counts()
    for summary in dimensions.values():
        counts = summary.get("counts") or {}
        total = total + Counts(**{key: int(counts.get(key, 0)) for key in
                                  ("tp", "fp", "tn", "fn", "unresolved", "not_observable",
                                   "unpredicted")})
    return total


# --------------------------------------------------------------------------- #
# the gate
# --------------------------------------------------------------------------- #

def evaluate(predictions: Iterable[Prediction], truths: Iterable[Truth], *,
             targets: Mapping[str, float] | None = None,
             min_answered: float = MIN_ANSWERED,
             max_unresolved: float = MAX_UNRESOLVED) -> dict[str, Any]:
    """Score, then decide whether the result may ship.

    Every target in ``targets`` is judged: a metric that could not be computed is a failure, not a
    pass. The answer-rate and unresolved-rate gates then apply per dimension, because a global
    answer rate hides one dimension that is 20% answered behind seven that are perfect.
    """
    truth_items = list(truths)
    prediction_items = list(predictions)
    counts = score(prediction_items, truth_items)
    chosen = dict(TARGETS if targets is None else targets)

    dimensions = {dimension: _summarise(dimension, bucket) for dimension, bucket in counts.items()}
    total = totals(dimensions)

    measured: dict[str, float | None] = {}
    for metric in chosen:
        measured[metric] = _metric_value(metric, dimensions, total)

    failures: list[dict[str, Any]] = []
    for metric, target in chosen.items():
        observed = measured[metric]
        if observed is None:
            failures.append({"metric": metric, "target": target, "observed": None,
                             "why": "not measured: no observable items in this dimension"})
            continue
        if metric in CEILINGS:
            if observed > target:
                failures.append({"metric": metric, "target": target, "observed": observed,
                                 "why": f"{observed:.1%} is above the {target:.0%} ceiling"})
        elif observed < target:
            failures.append({"metric": metric, "target": target, "observed": observed,
                             "why": f"{observed:.1%} is below the {target:.0%} target"})

    for dimension, summary in dimensions.items():
        answered = summary.get("answered")
        if answered is not None and answered < min_answered:
            failures.append({"metric": f"{dimension}_answered", "dimension": dimension,
                             "target": min_answered, "observed": answered,
                             "why": f"only {answered:.1%} of this dimension was answered; the "
                                    "rest is UNKNOWN, and precision measured on the answered "
                                    "part alone would be a partial claim"})
        unresolved = summary.get("unresolved_rate")
        if unresolved is not None and unresolved > max_unresolved:
            failures.append({"metric": f"{dimension}_unresolved_rate", "dimension": dimension,
                             "target": max_unresolved, "observed": unresolved,
                             "why": f"{unresolved:.1%} of this dimension is unresolved, above the "
                                    f"{max_unresolved:.0%} ceiling — precision computed over the "
                                    "rest must not be quoted as the dimension's precision"})

    return {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "ok": not failures,
        "failures": failures,
        "targets": chosen,
        "measured": measured,
        "dimensions": dimensions,
        "totals": total.as_dict(),
        "counting_rules": dict(COUNTING_RULES),
        "thresholds": {"min_answered": min_answered, "max_unresolved": max_unresolved},
    }


def _metric_value(metric: str, dimensions: Mapping[str, Mapping[str, Any]],
                  total: Counts) -> float | None:
    if metric in CEILINGS:
        numbers = metrics(total)
        return numbers["false_positive_rate" if metric == "false_positive_rate"
                        else "false_negative_rate"]
    dimension = _METRIC_SOURCE.get(metric)
    if dimension is None:
        return None
    summary = dimensions.get(dimension)
    if not summary:
        return None
    kind = metric.rsplit("_", 1)[1]
    value = summary.get(kind)
    if value is None:
        return None
    return float(value)


# --------------------------------------------------------------------------- #
# regression
# --------------------------------------------------------------------------- #

def compare(baseline: Mapping[str, Any], current: Mapping[str, Any], *,
            tolerance: float = 0.005) -> dict[str, Any]:
    """Did anything get worse? A ceiling that rose counts as worse, even though the number grew."""
    before = (baseline or {}).get("measured") or {}
    after = (current or {}).get("measured") or {}
    regressions: list[dict[str, Any]] = []
    for metric, previous in sorted(before.items()):
        if previous is None:
            continue
        latest = after.get(metric)
        if latest is None:
            regressions.append({"metric": metric, "baseline": previous, "current": None,
                                "delta": None,
                                "why": "measured before, not measured now — a dimension stopped "
                                       "being scored"})
            continue
        delta = latest - previous
        if metric in CEILINGS:
            worse = delta > tolerance
        else:
            worse = delta < -tolerance
        if worse:
            regressions.append({
                "metric": metric, "baseline": previous, "current": latest, "delta": delta,
                "why": (f"{latest:.1%} against {previous:.1%} "
                        f"({'above' if metric in CEILINGS else 'below'} the "
                        f"{tolerance:.1%} tolerance)"),
            })
    return {
        "ok": not regressions,
        "regressions": regressions,
        "tolerance": tolerance,
        "baseline_generated_at": (baseline or {}).get("generated_at"),
        "statement": ("no metric regressed beyond tolerance" if not regressions else
                      "; ".join(item["metric"] for item in regressions) + " regressed beyond "
                      "tolerance"),
    }


# --------------------------------------------------------------------------- #
# the dashboard
# --------------------------------------------------------------------------- #

def dashboard(result: Mapping[str, Any], *, title: str = "Accuracy gate") -> str:
    """Markdown, because the number that is quoted in a review is the one somebody pasted."""
    lines = [f"# {title}", "", f"_schema {result.get('schema', SCHEMA)} · "
                               f"generated {result.get('generated_at', 'unknown')}_", "",
             "## Every published target", "", "| Metric | Target | Measured | Verdict |",
             "|---|---|---|---|"]
    for metric, target in result["targets"].items():
        ceiling = metric in CEILINGS
        bound = f"≤ {target:.0%}" if ceiling else f"≥ {target:.0%}"
        observed = result["measured"].get(metric)
        if observed is None:
            lines.append(f"| {metric.replace('_', ' ')} | {bound} | — | NOT MEASURED |")
            continue
        ok = observed <= target if ceiling else observed >= target
        lines.append(f"| {metric.replace('_', ' ')} | {bound} | {observed:.1%} | "
                     f"{'PASS' if ok else 'FAIL'} |")

    lines += ["", "## Per dimension", "",
              "| Dimension | Precision | Recall | Accuracy | Answered | Unresolved | TP | FP | TN "
              "| FN |", "|---|---|---|---|---|---|---|---|---|---|"]
    for dimension, summary in sorted(result["dimensions"].items()):
        counts = summary["counts"]
        lines.append(
            f"| {dimension} | {_pct(summary['precision'])} | {_pct(summary['recall'])} | "
            f"{_pct(summary['accuracy'])} | {_pct(summary['answered'])} | "
            f"{_pct(summary['unresolved_rate'])} | {counts['tp']} | {counts['fp']} | "
            f"{counts['tn']} | {counts['fn']} |")

    lines += ["", "## Counting rules", "",
              "* **UNKNOWN is not counted as wrong.** It is counted as unresolved and reported "
              "beside the metric, never inside it, so honesty is never the expensive answer.",
              "* Asserting a value for an item nobody can observe is a **false positive**, so a "
              "gap cannot be turned into recall.",
              "* A confidently wrong value costs one false positive and one false negative.",
              "* `answered` and `unresolved` are gated per dimension: "
              f"`answered ≥ {result['thresholds']['min_answered']:.0%}`, "
              f"`unresolved ≤ {result['thresholds']['max_unresolved']:.0%}`.", ""]

    failures = result.get("failures") or []
    lines += ["## Gate", ""]
    if not failures:
        lines.append("**PASS** — every measured target met, and every dimension answered "
                     "enough to make its number mean something.")
    else:
        lines.append(f"**FAIL** — {len(failures)} finding(s):")
        lines.append("")
        for failure in failures:
            lines.append(f"* `{failure['metric']}` — {failure['why']}")
    return "\n".join(lines) + "\n"


def _pct(value: Any) -> str:
    return "—" if value is None else f"{value:.1%}"


__all__ = [
    "CEILINGS", "COLLECTION_FAILED", "CONFLICT", "COUNTING_RULES", "Counts", "DIMENSIONS",
    "FOUND", "MAX_UNRESOLVED", "MIN_ANSWERED", "NOT_FOUND_WITHIN_SCOPE", "NOT_OBSERVABLE",
    "Prediction", "SCHEMA", "TARGETS", "TRUTH_CONFLICT", "Truth", "UNKNOWN", "UNRESOLVED_STATES",
    "compare", "dashboard", "evaluate", "metrics", "score", "totals",
]
