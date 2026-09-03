"""Deterministic anomaly detection for security/crypto telemetry.

No AI/ML: these are classic, explainable statistical tests over time series:

* **z-score**        — a point far from the rolling mean/stddev;
* **EWMA control**   — exponentially weighted mean with control limits
                       (Shewhart-style 3-sigma), sensitive to level shifts;
* **rate-of-change** — a jump bigger than a multiple of typical variation;
* **frequency rule** — a value appearing far more often than its baseline
                       proportion (e.g. one algorithm dominating new findings).

Every finding has a concrete rule name, a score, and a human explanation, so
results are auditable. A minimum history is required before any anomaly is
raised (avoid false positives on cold start). Results are confidence-banded.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum

MIN_HISTORY = 5


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Anomaly:
    rule: str
    timestamp: float | None
    value: float
    score: float
    severity: Severity
    explanation: str
    context: dict = field(default_factory=dict)


def _mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _stddev(xs: Sequence[float], mean: float) -> float:
    if len(xs) < 2:
        return 0.0
    var = sum((x - mean) ** 2 for x in xs) / (len(xs) - 1)
    return math.sqrt(var)


def _severity(z: float) -> Severity:
    az = abs(z)
    if az >= 4:
        return Severity.HIGH
    if az >= 3:
        return Severity.MEDIUM
    return Severity.LOW


def zscore_anomaly(
    history: Sequence[float],
    value: float,
    *,
    timestamp: float | None = None,
    threshold: float = 3.0,
    min_history: int = MIN_HISTORY,
) -> Anomaly | None:
    """Flag ``value`` if it is > ``threshold`` standard deviations from history."""
    if len(history) < min_history:
        return None
    mean = _mean(history)
    sd = _stddev(history, mean)
    if sd == 0.0:
        # constant history: any change at all is anomalous, scaled by magnitude
        if value == mean:
            return None
        z = math.copysign(4.0, value - mean)
    else:
        z = (value - mean) / sd
    if abs(z) < threshold:
        return None
    return Anomaly(
        rule="zscore",
        timestamp=timestamp,
        value=value,
        score=round(abs(z), 3),
        severity=_severity(z),
        explanation=(
            f"value {value:g} is {abs(z):.1f} stddev from the recent mean "
            f"({mean:g}, sd {sd:g})"
        ),
        context={"mean": round(mean, 4), "stddev": round(sd, 4)},
    )


def ewma_control(
    series: Sequence[float],
    *,
    timestamps: Sequence[float] | None = None,
    alpha: float = 0.3,
    control_sigma: float = 3.0,
    min_history: int = MIN_HISTORY,
) -> list[Anomaly]:
    """EWMA control chart: flag points outside the exponentially weighted limits.

    Tracks the EWMA level and the variation of raw points; raises when a point
    sits beyond ``control_sigma`` * (EWMA-based dispersion). This catches a
    sustained level shift that a single-point z-score might miss early.
    """
    anomalies: list[Anomaly] = []
    if len(series) < min_history + 1:
        return anomalies

    # Establish the baseline mean/stddev from the first min_history points
    # (the "in control" period). The EWMA control chart then tests whether the
    # smoothed level drifts outside control_sigma * (baseline sigma * EWMA
    # cumulative-weight factor). This detects sustained level shifts while a
    # single in-range point leaves the smoothed level well inside the band.
    baseline = series[:min_history]
    mu0 = _mean(baseline)
    sigma0 = _stddev(baseline, mu0)
    if sigma0 <= 0:
        sigma0 = _stddev(series[: max(min_history + 2, len(series) // 2)] or series, mu0)
    if sigma0 <= 0:
        sigma0 = 1e-9  # constant history handled by the z-score rule

    ewma = mu0
    for i in range(1, len(series)):
        x = series[i]
        ewma = alpha * x + (1 - alpha) * ewma
        ts = timestamps[i] if timestamps and i < len(timestamps) else None
        if i < min_history:
            continue
        # cumulative weight factor for step i (Montgomery EWMA chart):
        #   sqrt( alpha/(2-alpha) * (1 - (1-alpha)^(2i)) )
        weight = math.sqrt((alpha / (2.0 - alpha)) * (1.0 - (1.0 - alpha) ** (2 * i)))
        limit = control_sigma * sigma0 * weight
        deviation = ewma - mu0
        if abs(deviation) > limit:
            z = deviation / (sigma0 * weight) if weight > 0 else 0.0
            anomalies.append(
                Anomaly(
                    rule="ewma_control",
                    timestamp=ts,
                    value=x,
                    score=round(abs(z), 3),
                    severity=_severity(z),
                    explanation=(
                        f"smoothed level {ewma:g} breached the EWMA control "
                        f"limit around baseline {mu0:g} (limit +-{limit:g})"
                    ),
                    context={"ewma_level": round(ewma, 4), "baseline_mean": round(mu0, 4),
                             "control_limit": round(limit, 4)},
                )
            )
    return anomalies


def rate_of_change_anomaly(
    series: Sequence[float],
    *,
    timestamps: Sequence[float] | None = None,
    spike_multiple: float = 3.0,
    min_history: int = MIN_HISTORY,
) -> list[Anomaly]:
    """Flag a single-step change far larger than the typical step size."""
    anomalies: list[Anomaly] = []
    if len(series) < min_history + 1:
        return anomalies
    deltas = [series[i] - series[i - 1] for i in range(1, len(series))]
    for idx in range(min_history, len(series)):
        step = series[idx] - series[idx - 1]
        past_deltas = deltas[: idx - 1]
        mean_abs = _mean([abs(d) for d in past_deltas]) or 1e-9
        if abs(step) >= spike_multiple * mean_abs and abs(step) > 0:
            ratio = abs(step) / mean_abs
            ts = timestamps[idx] if timestamps and idx < len(timestamps) else None
            anomalies.append(
                Anomaly(
                    rule="rate_of_change",
                    timestamp=ts,
                    value=series[idx],
                    score=round(ratio, 3),
                    severity=_severity(ratio),
                    explanation=(
                        f"step change {step:+g} is {ratio:.1f}x the typical "
                        f"per-interval variation ({mean_abs:g})"
                    ),
                    context={"step": round(step, 4), "typical_delta": round(mean_abs, 4)},
                )
            )
    return anomalies


def frequency_shift(
    labels: Sequence[str],
    *,
    target: str,
    baseline_proportion: float,
    tolerance: float = 0.15,
    min_count: int = MIN_HISTORY,
) -> Anomaly | None:
    """Flag when ``target`` appears at a proportion far above its baseline.

    e.g. a deprecated algorithm suddenly dominating new findings. Deterministic
    proportion test with an additive tolerance band.
    """
    if len(labels) < min_count:
        return None
    observed = sum(1 for l in labels if l == target) / len(labels)
    upper = baseline_proportion + tolerance
    if observed <= upper:
        return None
    excess = observed - baseline_proportion
    sev = Severity.HIGH if excess >= 0.30 else (Severity.MEDIUM if excess >= 0.15 else Severity.LOW)
    return Anomaly(
        rule="frequency_shift",
        timestamp=None,
        value=round(observed, 4),
        score=round(excess, 4),
        severity=sev,
        explanation=(
            f"'{target}' is {observed:.0%} of observations vs a baseline of "
            f"{baseline_proportion:.0%} (band {upper:.0%})"
        ),
        context={
            "observed_proportion": round(observed, 4),
            "baseline_proportion": baseline_proportion,
            "count": len(labels),
        },
    )


def detect_series(
    series: Sequence[float],
    *,
    timestamps: Sequence[float] | None = None,
    zscore_threshold: float = 3.0,
    enable_ewma: bool = True,
    enable_rate: bool = True,
    min_history: int = MIN_HISTORY,
) -> list[Anomaly]:
    """Run all point/series rules and return anomalies sorted by severity."""
    findings: list[Anomaly] = []
    if len(series) > min_history:
        z = zscore_anomaly(
            series[:-1], series[-1],
            timestamp=(timestamps[-1] if timestamps else None),
            threshold=zscore_threshold, min_history=min_history,
        )
        if z:
            findings.append(z)
    if enable_ewma:
        findings.extend(ewma_control(series, timestamps=timestamps, min_history=min_history))
    if enable_rate:
        findings.extend(rate_of_change_anomaly(series, timestamps=timestamps, min_history=min_history))
    order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    return sorted(findings, key=lambda a: (order[a.severity], -(a.score)))
