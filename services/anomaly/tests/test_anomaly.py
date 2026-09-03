"""Deterministic statistical anomaly/forecast tests (no ML)."""

from __future__ import annotations

from anomaly.detect import (
    Severity,
    detect_series,
    ewma_control,
    frequency_shift,
    rate_of_change_anomaly,
    zscore_anomaly,
)
from anomaly.forecast import forecast_series


# --------------------------------------------------------------- z-score
def test_zscore_flags_spike():
    history = [10, 11, 9, 10, 12, 10, 11, 9]
    a = zscore_anomaly(history, 80, threshold=3)
    assert a is not None
    assert a.rule == "zscore"
    assert a.severity in (Severity.MEDIUM, Severity.HIGH)


def test_zscore_quiet_when_normal():
    history = [10, 11, 9, 10, 12, 10, 11]
    assert zscore_anomaly(history, 10.5, threshold=3) is None


def test_zscore_no_false_positive_on_cold_start():
    # below min history -> never flags
    assert zscore_anomaly([10, 11], 999) is None


def test_constant_history_change_is_anomaly():
    a = zscore_anomaly([5, 5, 5, 5, 5, 5], 6)
    assert a is not None and a.severity is Severity.HIGH


# --------------------------------------------------------------- EWMA
def test_ewma_detects_level_shift():
    series = [10] * 8 + [40, 42, 41]
    found = ewma_control(series, alpha=0.3, control_sigma=3)
    assert len(found) >= 1
    assert all(f.rule == "ewma_control" for f in found)


def test_ewma_silent_on_stable_series():
    series = [10, 10, 10, 10, 10, 10, 10]
    assert ewma_control(series) == []


# --------------------------------------------------------------- rate of change
def test_rate_of_change_flags_sudden_jump():
    series = [10, 11, 10, 11, 10, 11, 200]
    found = rate_of_change_anomaly(series, spike_multiple=3)
    assert any(f.rule == "rate_of_change" for f in found)


# --------------------------------------------------------------- frequency
def test_frequency_shift_flags_dominant_algorithm():
    labels = ["AES", "AES", "DES", "AES", "DES", "DES", "DES", "DES"]
    # baseline DES proportion ~0.2, tolerance 0.15 -> upper 0.35; observed 0.625
    a = frequency_shift(labels, target="DES", baseline_proportion=0.2, tolerance=0.15)
    assert a is not None
    # excess 0.625-0.20 = 0.425 >= 0.30 -> HIGH
    assert a.severity in (Severity.HIGH, Severity.MEDIUM)


def test_frequency_shift_quiet_within_band():
    labels = ["AES"] * 7 + ["DES"]
    assert frequency_shift(labels, target="DES", baseline_proportion=0.05, tolerance=0.2) is None


# --------------------------------------------------------------- aggregate
def test_detect_series_orders_by_severity():
    series = [10, 11, 9, 10, 12, 10, 11, 9, 500]
    found = detect_series(series)
    assert found
    assert found[0].severity is Severity.HIGH


# --------------------------------------------------------------- forecast
def test_forecast_linear_trend_projection():
    series = [10, 20, 30, 40, 50, 60]  # slope +10
    f = forecast_series(series, horizon=3)
    assert f.method == "linear"
    assert f.slope == 10
    # next projections ~70, 80, 90
    assert abs(f.projected[0] - 70) < 1.0
    assert f.upper_band[0] >= f.projected[0] >= f.lower_band[0]


def test_forecast_flat_when_insufficient_history():
    f = forecast_series([5, 6], horizon=2)
    assert "insufficient" in f.method
    assert f.projected == [6, 6]


def test_forecast_uncertainty_band_widens():
    series = [10, 12, 9, 11, 13, 10, 12, 11]
    f = forecast_series(series, horizon=4)
    widths = [u - lo for u, lo in zip(f.upper_band, f.lower_band)]
    assert widths[-1] >= widths[0]  # uncertainty grows with horizon
