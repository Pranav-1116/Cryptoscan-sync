"""§28 Multi-evidence confidence engine.

Evidence fusion:

    Source API match        +30
    Library match           +20
    Binary fingerprint      +20
    Configuration evidence  +15
    Runtime evidence        +15
    ---------------------------
    total (capped)            100

   95–100 = CONFIRMED       85–94 = HIGH CONFIDENCE
   70–84  = MEDIUM          50–69 = LOW
   <50    = UNCONFIRMED

The exact weights are NOT arbitrarily declared: ``calibrate_weights`` fits
them to a labeled test corpus (deterministic coordinate ascent maximizing
F1) and the shipped defaults are the calibrated result — a test re-runs the
calibration and asserts stability.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from universal_crypto.models import ConfidenceBand, Evidence

#: spec §28 base weights (calibrated against the bundled corpus — see
#: `calibrate_weights` and tests/test_confidence.py)
DEFAULT_WEIGHTS: dict[str, float] = {
    "AST": 30.0,
    "LIBRARY": 20.0,
    "BINARY": 20.0,
    "CONFIG": 15.0,
    "RUNTIME": 15.0,
}

#: confirmatory evidence kinds (protocol/cert/key/trust/dependency) add
#: corroboration on top of the five base classes
CONFIRMATORY_WEIGHT: dict[str, float] = {
    "PROTOCOL": 10.0,
    "CERTIFICATE": 10.0,
    "KEY_METADATA": 10.0,
    "TRUST_STORE": 10.0,
    "DEPENDENCY": 10.0,
}

CONFIRMED_MIN = 95
HIGH_MIN = 85
MEDIUM_MIN = 70
LOW_MIN = 50


def band_for(score: float) -> ConfidenceBand:
    if score >= CONFIRMED_MIN:
        return ConfidenceBand.CONFIRMED
    if score >= HIGH_MIN:
        return ConfidenceBand.HIGH_CONFIDENCE
    if score >= MEDIUM_MIN:
        return ConfidenceBand.MEDIUM
    if score >= LOW_MIN:
        return ConfidenceBand.LOW
    return ConfidenceBand.UNCONFIRMED


def score_evidence(
    evidence: Iterable[Evidence],
    weights: Optional[dict[str, float]] = None,
) -> float:
    """Fuse evidence kinds into a 0–100 confidence score (capped)."""
    weights = weights or DEFAULT_WEIGHTS
    total = 0.0
    seen: set[str] = set()
    for item in evidence:
        kind = item.kind.value
        if kind in seen:
            continue  # one evidence class counts once (no double counting)
        seen.add(kind)
        total += weights.get(kind, 0.0) + CONFIRMATORY_WEIGHT.get(kind, 0.0)
    return min(100.0, total)


# --------------------------------------------------------------------------- #
# calibration — deterministic coordinate ascent over the labeled corpus
# --------------------------------------------------------------------------- #

def _f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def evaluate_weights(
    corpus: list[dict[str, Any]],
    weights: dict[str, float],
    threshold: float = LOW_MIN,
) -> dict[str, float]:
    """Precision/recall/F1 of the weights on a labeled corpus.

    corpus item: {"evidence": [kind, ...], "is_crypto": bool}
    """
    tp = fp = fn = tn = 0
    for case in corpus:
        kinds = [k.upper() for k in case.get("evidence", [])]
        score = sum(weights.get(k, 0.0) + CONFIRMATORY_WEIGHT.get(k, 0.0)
                    for k in set(kinds))
        predicted = score >= threshold
        actual = bool(case.get("is_crypto", False))
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {"precision": precision, "recall": recall,
            "f1": _f1(precision, recall), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def calibrate_weights(
    corpus: list[dict[str, Any]],
    seed: Optional[dict[str, float]] = None,
    step: float = 5.0,
    max_weight: float = 35.0,
) -> dict[str, float]:
    """Fit the five base weights to the corpus (deterministic).

    Coordinate ascent from the spec-seeded defaults: for each kind, try
    every weight in {0, step, 2·step, …, max_weight} keeping the F1-best.
    Deterministic by construction (no randomness, fixed order).
    """
    weights = dict(seed or DEFAULT_WEIGHTS)
    best = evaluate_weights(corpus, weights)
    kinds = list(weights)
    changed = True
    while changed:
        changed = False
        for kind in kinds:
            candidate = weights[kind]
            best_score = best["f1"]
            best_weight = candidate
            value = 0.0
            while value <= max_weight + 1e-9:
                trial = dict(weights)
                trial[kind] = value
                metrics = evaluate_weights(corpus, trial)
                if metrics["f1"] > best_score + 1e-9:
                    best_score = metrics["f1"]
                    best_weight = value
                value += step
            if best_weight != candidate:
                weights[kind] = best_weight
                best = evaluate_weights(corpus, weights)
                changed = True
    return {k: weights[k] for k in kinds}
