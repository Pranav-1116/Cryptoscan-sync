"""Performance intelligence (docs/performance/01_PRODUCT_SPEC.md, §2.H,
roadmap Phase 6) and the Digital Twin correlation investigation (§8).

Everything computed here is deterministic and explainable: the same
inputs produce the same outputs, every number carries the window and the
samples it came from, and the honesty rules are structural —

- a baseline is a named method over a named window, not a vibe;
- a regression names its supporting measurements (before AND after);
- an alert states what is proven AND what is not proven;
- severity is computed from factors, never asserted;
- a capacity forecast is labelled "forecast, not fact", names its
  method, and refuses to forecast without enough samples;
- a time correlation alone never proves causation — the §8
  investigation ends with "Correlation detected — causation unproven".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import median
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from shared_models.performance_metrics import (
    NO_VALUE_QUALITIES, PerformanceMetric,
)
from shared_models.performance_views import _percentile, summarize_metric

BASELINE_METHOD = "median-absolute-deviation-window"
FORECAST_METHOD = "linear-extrapolation"
MIN_FORECAST_SAMPLES = 3
MIN_BASELINE_SAMPLES = 5


@dataclass
class Baseline:
    metric_name: str
    asset_id: Optional[str]
    window_start: datetime
    window_end: datetime
    method: str
    sample_count: int
    median: Optional[float]
    p95: Optional[float]
    mad: Optional[float]  # median absolute deviation

    def as_dict(self) -> Dict[str, Any]:
        return {
            "metric_name": self.metric_name,
            "asset_id": self.asset_id,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "method": self.method,
            "sample_count": self.sample_count,
            "median": self.median,
            "p95": self.p95,
            "mad": self.mad,
        }


def compute_baseline(rows: Sequence[PerformanceMetric], *,
                     window_start: datetime,
                     window_end: datetime) -> Baseline:
    """A baseline is reproducible: same delivered samples, same numbers,
    every time. Fewer than MIN_BASELINE_SAMPLES delivered values and the
    baseline is computed anyway but names its thin sample count — the
    numbers never pretend to be more than they are."""
    in_window = [r for r in rows
                 if window_start <= r.observed_at <= window_end
                 and r.quality_status not in NO_VALUE_QUALITIES
                 and r.metric_value is not None]
    values = [r.metric_value for r in in_window]
    metric_name = rows[0].metric_name if rows else ""
    asset_id = rows[0].asset_id if rows else None
    if not values:
        return Baseline(metric_name=metric_name, asset_id=asset_id,
                        window_start=window_start, window_end=window_end,
                        method=BASELINE_METHOD, sample_count=0,
                        median=None, p95=None, mad=None)
    med = median(values)
    deviations = sorted(abs(v - med) for v in values)
    return Baseline(
        metric_name=metric_name, asset_id=asset_id,
        window_start=window_start, window_end=window_end,
        method=BASELINE_METHOD, sample_count=len(values),
        median=med,
        p95=_percentile(values, 0.95),
        mad=deviations[len(deviations) // 2],
    )


def detect_regression(baseline: Baseline, *,
                      window_start: datetime,
                      window_end: datetime,
                      rows: Sequence[PerformanceMetric],
                      threshold_pct: float = 25.0) -> Optional[Dict[str, Any]]:
    """Regression detection: a measured difference beyond threshold with
    BOTH windows named as supporting measurements. A regression finding
    never claims a cause — the cause is exactly what is not proven."""
    current = [r for r in rows
               if window_start <= r.observed_at <= window_end
               and r.quality_status not in NO_VALUE_QUALITIES
               and r.metric_value is not None]
    if baseline.median is None or baseline.sample_count < MIN_BASELINE_SAMPLES:
        return None
    if len(current) < MIN_BASELINE_SAMPLES:
        return None
    values = [r.metric_value for r in current]
    current_p95 = _percentile(values, 0.95)
    assert current_p95 is not None and baseline.p95 is not None
    if baseline.p95 == 0:
        return None
    change_pct = (current_p95 - baseline.p95) / baseline.p95 * 100
    if change_pct < threshold_pct:
        return None
    return {
        "metric_name": baseline.metric_name,
        "asset_id": baseline.asset_id,
        "finding": "performance regression measured",
        "baseline_p95": baseline.p95,
        "current_p95": current_p95,
        "change_pct": round(change_pct, 1),
        "threshold_pct": threshold_pct,
        "proven": [
            f"baseline p95 {baseline.p95} over {baseline.sample_count} "
            f"samples ({baseline.window_start} .. {baseline.window_end})",
            f"current p95 {current_p95} over {len(current)} samples "
            f"({window_start} .. {window_end})",
            f"measured increase {round(change_pct, 1)}% exceeds threshold "
            f"{threshold_pct}%",
        ],
        "not_proven": [
            "the cause of the regression is not proven — a measured "
            "difference is not an attribution",
            "other possible causes still need investigation",
        ],
    }


def evaluate_alert(metric_name: str, *,
                   rows: Sequence[PerformanceMetric],
                   baseline: Optional[Baseline],
                   window_start: datetime,
                   window_end: datetime,
                   threshold_pct: float = 25.0,
                   absolute_thresholds: Optional[Mapping[str, float]] = None
                   ) -> Optional[Dict[str, Any]]:
    """An alert states what is proven AND what is not proven, and its
    severity is COMPUTED from factors — never named by fiat.

    Factors: magnitude beyond threshold (measured), duration (sample
    count over threshold), and evidence completeness (delivered vs
    unknown samples). Severity = computed rank of the factors.
    """
    summary = summarize_metric([r for r in rows
                                if r.metric_name == metric_name
                                and window_start <= r.observed_at <= window_end])
    if summary["value_count"] == 0:
        return None  # unknown telemetry is not an alert condition
    proven: List[str] = []
    not_proven: List[str] = []
    factors: Dict[str, Any] = {
        "magnitude_pct": 0.0,
        "samples_over_threshold": 0,
        "evidence_completeness": summary["coverage"],
    }
    triggered = False

    absolute = (absolute_thresholds or {}).get(metric_name)
    if absolute is not None and summary["maximum"] is not None:
        if summary["maximum"] > absolute:
            triggered = True
            factors["magnitude_pct"] = round(
                (summary["maximum"] - absolute) / absolute * 100, 1)
            proven.append(
                f"maximum {summary['maximum']} exceeds absolute threshold "
                f"{absolute} ({summary['value_count']} delivered samples)")
        else:
            proven.append(
                f"maximum {summary['maximum']} within absolute threshold "
                f"{absolute}")
    elif baseline is not None and baseline.p95 is not None and baseline.p95:
        current_p95 = summary["p95"]
        if current_p95 is not None:
            change = (current_p95 - baseline.p95) / baseline.p95 * 100
            factors["magnitude_pct"] = round(change, 1)
            if change >= threshold_pct:
                triggered = True
                proven.append(
                    f"p95 {current_p95} vs baseline {baseline.p95} "
                    f"= +{round(change, 1)}% (threshold {threshold_pct}%)")
                factors["samples_over_threshold"] = summary["value_count"]
    if summary["unknown_count"]:
        not_proven.append(
            f"{summary['unknown_count']} samples carry no value "
            "(missing/stale) — what they would show is not proven")
    if not triggered:
        return None
    not_proven.append(
        "the cause of the threshold crossing is not proven")
    severity = _computed_severity(factors)
    return {
        "metric_name": metric_name,
        "severity": severity,
        "severity_factors": factors,
        "proven": proven,
        "not_proven": not_proven,
        "supporting_measurements": summary,
        "window_start": window_start,
        "window_end": window_end,
    }


def _computed_severity(factors: Mapping[str, Any]) -> str:
    """Severity is computed from factors: magnitude beyond threshold,
    breadth (samples over threshold), and evidence completeness."""
    magnitude = float(factors.get("magnitude_pct") or 0.0)
    samples = int(factors.get("samples_over_threshold") or 0)
    coverage = str(factors.get("evidence_completeness") or "")
    score = 0
    if magnitude >= 100:
        score += 2
    elif magnitude >= 50:
        score += 1
    if samples >= 10:
        score += 1
    if coverage == "complete":
        score += 1
    if score >= 3:
        return "CRITICAL"
    if score >= 2:
        return "WARNING"
    return "INFO"


def forecast_capacity(rows: Sequence[PerformanceMetric], *,
                      window_start: datetime,
                      window_end: datetime,
                      capacity_value: Optional[float] = None
                      ) -> Dict[str, Any]:
    """Capacity forecast (§2.H): linear extrapolation over the window's
    delivered samples, labelled "forecast, not fact", refusing to
    forecast without enough samples or without movement."""
    values = [(r.observed_at, r.metric_value) for r in rows
              if window_start <= r.observed_at <= window_end
              and r.quality_status not in NO_VALUE_QUALITIES
              and r.metric_value is not None]
    values.sort()
    if len(values) < MIN_FORECAST_SAMPLES:
        return {
            "status": "insufficient-data",
            "method": FORECAST_METHOD,
            "note": f"at least {MIN_FORECAST_SAMPLES} delivered samples are "
                    "required to forecast; fewer samples are not a trend",
            "sample_count": len(values),
            "forecast": None,
        }
    (t0, v0), (t1, v1) = values[0], values[-1]
    span_seconds = (t1 - t0).total_seconds()
    if span_seconds <= 0:
        return {
            "status": "insufficient-data", "method": FORECAST_METHOD,
            "note": "samples share one timestamp — no growth rate exists",
            "sample_count": len(values), "forecast": None,
        }
    growth_per_second = (v1 - v0) / span_seconds
    if growth_per_second <= 0:
        return {
            "status": "no-growth",
            "method": FORECAST_METHOD,
            "note": "the series is flat or declining in the window — no "
                    "exhaustion can be forecast from a decline",
            "sample_count": len(values),
            "growth_per_second": growth_per_second,
            "forecast": None,
        }
    if capacity_value is None:
        return {
            "status": "no-capacity",
            "method": FORECAST_METHOD,
            "note": "capacity is unknown — an exhaustion time needs the "
                    "ceiling it approaches",
            "sample_count": len(values),
            "growth_per_second": growth_per_second,
            "forecast": None,
        }
    remaining = capacity_value - v1
    seconds_to_exhaustion = remaining / growth_per_second
    return {
        "status": "forecast",
        "method": FORECAST_METHOD,
        "disclaimer": "forecast, not fact — a linear extrapolation of the "
                      "window's growth rate, not a promise about the future",
        "sample_count": len(values),
        "growth_per_second": growth_per_second,
        "current_value": v1,
        "capacity_value": capacity_value,
        "estimated_seconds_to_exhaustion": seconds_to_exhaustion,
    }


def correlate_change_with_metrics(
        change: Mapping[str, Any],
        rows: Sequence[PerformanceMetric], *,
        before_start: datetime, before_end: datetime,
        after_start: datetime, after_end: datetime,
        affected_assets: Sequence[str] = ()) -> Dict[str, Any]:
    """The §8 investigation: a recorded change and a measured window
    before and after it. The output presents the measured difference and
    every honesty rule in the spec —

    "Correlation detected — causation unproven."
    "A time correlation alone does not prove that the change caused the
    latency increase."
    "Other possible causes still need investigation."

    ``change`` carries at least: time, description, evidence_ids.
    ``affected_assets`` come from the Digital Twin — asset identity is
    referenced, never invented.
    """
    before = summarize_metric([r for r in rows
                               if before_start <= r.observed_at <= before_end])
    after = summarize_metric([r for r in rows
                              if after_start <= r.observed_at <= after_end])
    difference = None
    if before["p95"] is not None and after["p95"] is not None:
        difference = after["p95"] - before["p95"]
    evidence = list(change.get("evidence_ids") or [])
    return {
        "investigation": "performance regression investigation",
        "conclusion": "Correlation detected — causation unproven",
        "change": {
            "time": change.get("time"),
            "description": change.get("description"),
            "evidence_ids": evidence,
        },
        "before": before,
        "after": after,
        "difference_p95": difference,
        "affected_assets": list(affected_assets),
        "evidence": {
            "proven": [
                f"the recorded change carries {len(evidence)} evidence "
                "reference(s)" if evidence else
                "the recorded change carries no evidence reference",
                "a measurement window before and after the change was "
                "compared on the same metric",
                f"affected assets identified by Digital Twin identity: "
                f"{', '.join(affected_assets)}" if affected_assets else
                "no affected assets were identified",
            ],
            "not_proven": [
                "A time correlation alone does not prove that the change "
                "caused the latency increase",
                "Other possible causes still need investigation",
                "the before/after windows may contain unrelated load, "
                "deployment, or infrastructure changes",
            ],
        },
        "note": "illustrative or real, this report never upgrades "
                "correlation to causation",
    }
