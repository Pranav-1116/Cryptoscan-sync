"""Deterministic, explainable forecasting (no ML).

For capacity/quantum-readiness projections we use two classical, deterministic
models with a simple in-sample fit selection — every projection is reproducible
and the method is reported alongside it:

* **linear trend**  — ordinary least squares on (t, value);
* **simple exponential smoothing (SES)** — weighted average of recent points.

We pick the model with the lower in-sample mean absolute error (MAE) and report
a growth envelope as a fixed multiple of observed per-step variation. This is a
planning aid, not a prediction oracle; uncertainty is expressed as a band.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field


def _ols_slope_intercept(xs: Sequence[float], ys: Sequence[float]) -> tuple[float, float]:
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    if denom == 0:
        return 0.0, my
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom
    return slope, my - slope * mx


def _mae(actual: Sequence[float], predicted: Sequence[float]) -> float:
    if not actual:
        return math.inf
    return sum(abs(a - p) for a, p in zip(actual, predicted)) / len(actual)


@dataclass
class Forecast:
    method: str
    horizon: int
    projected: list[float]
    upper_band: list[float]
    lower_band: list[float]
    slope: float
    in_sample_mae: float
    method_maes: dict = field(default_factory=dict)


def forecast_series(
    series: Sequence[float],
    *,
    horizon: int = 6,
    alpha: float = 0.4,
    band_multiplier: float = 2.0,
    min_history: int = 4,
) -> Forecast:
    """Project ``horizon`` steps ahead using the best-fitting deterministic model."""
    n = len(series)
    if n < min_history:
        last = series[-1] if series else 0.0
        flat = [last] * horizon
        return Forecast(
            method="flat(insufficient-history)",
            horizon=horizon,
            projected=flat,
            upper_band=flat,
            lower_band=flat,
            slope=0.0,
            in_sample_mae=0.0,
            method_maes={"linear": math.inf, "ses": math.inf},
        )

    xs = list(range(n))
    slope, intercept = _ols_slope_intercept(xs, series)
    linear_fit = [slope * x + intercept for x in xs]
    linear_mae = _mae(series, linear_fit)

    # SES in-sample (one-step-ahead)
    ses_level = series[0]
    ses_fit = [ses_level]
    for i in range(1, n):
        ses_fit.append(ses_level)
        ses_level = alpha * series[i] + (1 - alpha) * ses_level
    ses_mae = _mae(series[1:], ses_fit[1:])

    # residual dispersion for the envelope
    if linear_mae <= ses_mae:
        method = "linear"
        resid = [a - p for a, p in zip(series, linear_fit)]
    else:
        method = "ses"
        resid = [a - p for a, p in zip(series[1:], ses_fit[1:])]
    sigma = math.sqrt(sum(r * r for r in resid) / max(1, len(resid))) or 0.0

    projected: list[float] = []
    upper: list[float] = []
    lower: list[float] = []
    for h in range(1, horizon + 1):
        if method == "linear":
            point = slope * (n + h - 1) + intercept
        else:
            point = ses_level  # SES is flat beyond the last level
        projected.append(round(point, 4))
        spread = band_multiplier * sigma * math.sqrt(h)  # widening uncertainty
        upper.append(round(point + spread, 4))
        lower.append(round(max(0.0, point - spread), 4))

    return Forecast(
        method=method,
        horizon=horizon,
        projected=projected,
        upper_band=upper,
        lower_band=lower,
        slope=round(slope, 4),
        in_sample_mae=round(min(linear_mae, ses_mae), 4),
        method_maes={"linear": round(linear_mae, 4), "ses": round(ses_mae, 4)},
    )
