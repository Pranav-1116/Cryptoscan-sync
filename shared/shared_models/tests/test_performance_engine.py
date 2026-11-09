"""Performance engine tests (docs/performance/01_PRODUCT_SPEC.md).

Phases 2–6 and §8, test-proven against the spec's rules: translators
refuse instead of inventing; views name every gap; baselines are
reproducible; alerts state proven AND not-proven with computed severity;
forecasts are labelled "forecast, not fact"; benchmark results are never
production performance; and a time correlation alone never proves
causation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from shared_models.performance_collectors import (
    translate_node_exporter, translate_otlp, translate_postgres_exporter,
)
from shared_models.performance_benchmarks import (
    EXTERNAL_ACTS, MEASUREMENT_KIND, BenchmarkMethod, BenchmarkRun,
    build_run, local_method, run_local_benchmark,
)
from shared_models.performance_intelligence import (
    compute_baseline, correlate_change_with_metrics, detect_regression,
    evaluate_alert, forecast_capacity,
)
from shared_models.performance_metrics import PerformanceMetric, QualityStatus
from shared_models.performance_views import (
    application_view, cryptography_view, network_view,
    overview, summarize_metric, window_check,
)

NOW = datetime.now(timezone.utc)


def _m(i, name="crypto.tls_handshake_ms", value=30.0, quality="valid",
       minutes_ago=60, unit=None, asset="asset-1", tenant="tenant_a"):
    from shared_models.performance_taxonomy import definition_for
    if quality in ("stale", "missing") and value is not None:
        value = None  # unknown telemetry carries no value
    return PerformanceMetric(
        metric_id=f"m-{i}", tenant_id=tenant, asset_id=asset,
        metric_name=name, metric_type="gauge", metric_value=value,
        unit=unit or definition_for(name).unit, source_id="collector-1",
        observed_at=NOW - timedelta(minutes=minutes_ago),
        quality_status=QualityStatus(quality))


# -- collectors (Phases 2-4) ------------------------------------------------

def test_translators_refuse_unknown_families_instead_of_inventing():
    result = translate_node_exporter(
        {"metrics": {"node_mystery": [{"value": 1, "labels": {}}]}},
        asset_id="a", tenant_id="t", source_id="s", observed_at=NOW)
    assert result.metrics == []
    assert result.refused_count == 1
    assert "never guessed" in result.refused[0]["reason"]


def test_rate_derived_utilization_needs_two_snapshots():
    payload = {"metrics": {"node_cpu_seconds_total": [
        {"value": 100.0, "labels": {"cpu": "0", "mode": "idle"}},
        {"value": 40.0, "labels": {"cpu": "0", "mode": "user"}}]}}
    alone = translate_node_exporter(
        payload, asset_id="a", tenant_id="t", source_id="s", observed_at=NOW)
    cpu = alone.metrics[-1]
    assert cpu.quality_status == QualityStatus.MISSING
    assert cpu.value_or_unknown() is None, \
        "one sample is unknown telemetry — a percentage would be invented"
    previous = {"metrics": {"node_cpu_seconds_total": [
        {"value": 50.0, "labels": {"cpu": "0", "mode": "idle"}},
        {"value": 20.0, "labels": {"cpu": "0", "mode": "user"}}]}}
    both = translate_node_exporter(
        payload, asset_id="a", tenant_id="t", source_id="s", observed_at=NOW,
        previous=previous, interval_seconds=60)
    cpu2 = both.metrics[-1]
    assert cpu2.quality_status == QualityStatus.VALID
    # idle delta 50 of total delta 80 -> 37.5% idle -> 62.5% utilized
    # idle delta 50 of total delta 70 -> 28.57% utilized
    assert cpu2.metric_value == 28.57


def test_postgres_and_otlp_translators_keep_the_verified_maps():
    pg = translate_postgres_exporter(
        {"metrics": {"pg_stat_activity_count": [{"value": 7, "labels": {}}],
                     "pg_customer_rows": [{"value": 1, "labels": {}}]}},
        asset_id="a", tenant_id="t", source_id="s", observed_at=NOW)
    assert [m.metric_name for m in pg.metrics] == ["db.connections_active"]
    assert pg.refused_count == 1
    otlp = translate_otlp(
        {"metrics": {"http.server.active_requests": [{"value": 3, "labels": {}}],
                     "custom.thing": [{"value": 1, "labels": {}}]}},
        asset_id="a", tenant_id="t", source_id="s", observed_at=NOW)
    assert [m.metric_name for m in otlp.metrics] == ["api.concurrent_requests"]
    assert otlp.refused_count == 1


# -- views (Phases 2-5 read side) ------------------------------------------

def test_views_never_fill_gaps_with_zeros():
    rows = [_m(1, "network.rtt_ms", 42.0, minutes_ago=5)]
    net = network_view(rows)
    assert net["observed_throughput_mbps"]["state"] == "unknown"
    assert net["observed_throughput_mbps"]["value"] is None
    assert "never zero" in net["observed_throughput_mbps"]["note"]
    ov = overview(rows)
    assert ov["storage_usage_pct"]["state"] == "unknown"
    assert "bandwidth capacity and actual throughput are different" in net["note"]


def test_summaries_cover_delivered_values_and_name_their_unknowns():
    rows = [_m(1, "api.latency_p95_ms", 100.0, minutes_ago=5),
            _m(2, "api.latency_p95_ms", 200.0, minutes_ago=4),
            _m(3, "api.latency_p95_ms", quality="stale", minutes_ago=3)]
    summary = summarize_metric(rows)
    assert summary["average"] == 150.0
    assert summary["unknown_count"] == 1
    assert summary["coverage"].startswith("partial — 2/3")
    app = application_view(rows)
    assert "missing telemetry is unknown, never zero" in app["note"]
    crypto = cryptography_view([_m(4, "crypto.tls_handshake_ms", 35.0)])
    assert crypto["measurement_kind"] == "observed-production"
    assert "never presented as production" in crypto["note"]


def test_query_windows_are_bounded():
    with pytest.raises(ValueError, match="window_start and window_end"):
        window_check(None, None)
    with pytest.raises(ValueError, match="exceeds 31 days"):
        window_check(NOW - timedelta(days=40), NOW)
    window_check(NOW - timedelta(days=1), NOW)


# -- intelligence (Phase 6) -------------------------------------------------

def test_baselines_are_reproducible():
    rows = [_m(i, "network.rtt_ms", 30.0 + i, minutes_ago=60 - i)
            for i in range(10)]
    kwargs = dict(window_start=NOW - timedelta(hours=2), window_end=NOW)
    first = compute_baseline(rows, **kwargs)
    second = compute_baseline(rows, **kwargs)
    assert first == second
    assert first.method == "median-absolute-deviation-window"
    assert first.sample_count == 10


def test_regressions_carry_supporting_measurements_never_a_cause():
    base_rows = [_m(i, "network.rtt_ms", 30.0 + i, minutes_ago=120 - i)
                 for i in range(10)]
    baseline = compute_baseline(base_rows,
                                window_start=NOW - timedelta(hours=2),
                                window_end=NOW)
    current = [_m(100 + i, "network.rtt_ms", 80.0 + i, minutes_ago=20 - i)
               for i in range(10)]
    regression = detect_regression(baseline,
                                   window_start=NOW - timedelta(minutes=21),
                                   window_end=NOW, rows=current)
    assert regression is not None
    assert regression["proven"], "supporting measurements are required"
    assert any("not proven" in s for s in regression["not_proven"])
    assert any("other possible causes" in s.lower()
               for s in regression["not_proven"])


def test_alerts_state_proven_and_not_proven_with_computed_severity():
    base_rows = [_m(i, "network.rtt_ms", 30.0, minutes_ago=120 - i)
                 for i in range(10)]
    baseline = compute_baseline(base_rows,
                                window_start=NOW - timedelta(hours=2),
                                window_end=NOW)
    current = [_m(200 + i, "network.rtt_ms", 90.0, minutes_ago=20 - i)
               for i in range(12)]
    alert = evaluate_alert("network.rtt_ms", rows=current, baseline=baseline,
                           window_start=NOW - timedelta(minutes=21),
                           window_end=NOW)
    assert alert["proven"] and alert["not_proven"]
    assert alert["severity"] == "CRITICAL"
    assert alert["severity_factors"]["magnitude_pct"] > 50
    assert alert["supporting_measurements"]["value_count"] == 12
    quiet = evaluate_alert("network.rtt_ms",
                           rows=[_m(300, "network.rtt_ms", 31.0)],
                           baseline=baseline,
                           window_start=NOW - timedelta(minutes=21),
                           window_end=NOW)
    assert quiet is None, "within-threshold telemetry raises nothing"


def test_forecasts_are_labelled_and_refuse_thin_data():
    growing = [_m(i, "storage.used_bytes", 100.0 + i * 10,
                  minutes_ago=50 - i * 10) for i in range(5)]
    forecast = forecast_capacity(growing,
                                 window_start=NOW - timedelta(hours=2),
                                 window_end=NOW, capacity_value=1000.0)
    assert forecast["status"] == "forecast"
    assert "forecast, not fact" in forecast["disclaimer"]
    assert forecast["estimated_seconds_to_exhaustion"] > 0
    thin = forecast_capacity([_m(9, "storage.used_bytes", 5.0)],
                             window_start=NOW - timedelta(hours=2),
                             window_end=NOW, capacity_value=1000.0)
    assert thin["status"] == "insufficient-data"
    assert thin["forecast"] is None
    declining = [_m(i, "storage.used_bytes", 100.0 - i * 10,
                    minutes_ago=50 - i * 10) for i in range(5)]
    down = forecast_capacity(declining,
                             window_start=NOW - timedelta(hours=2),
                             window_end=NOW, capacity_value=1000.0)
    assert down["status"] == "no-growth", \
        "a decline is not an exhaustion trend"


# -- benchmarks (Phase 5) ---------------------------------------------------

def test_benchmark_reproducibility_fields_are_mandatory():
    with pytest.raises(Exception, match="hardware|sample_count"):
        BenchmarkMethod(
            hardware="", software="s", provider="p", algorithm="a",
            algorithm_parameters={}, methodology="m", concurrency=1,
            sample_count=5)
    method = local_method("Ed25519", sample_count=5)
    for field in ("hardware", "software", "provider", "algorithm",
                  "algorithm_parameters", "methodology", "concurrency",
                  "sample_count"):
        assert getattr(method, field), f"{field} is required for reproducibility"


def test_a_benchmark_result_is_never_production_performance():
    run = run_local_benchmark(tenant_id="t", algorithm="Ed25519",
                              sample_count=5)
    assert run.measurement_kind == MEASUREMENT_KIND
    assert run.results and all(r.samples == 5 for r in run.results)
    with pytest.raises(ValueError, match="never production performance"):
        BenchmarkRun(
            run_id="bench-x", tenant_id="t", approved=True,
            method=local_method("Ed25519", sample_count=3),
            results=run.results,
            measurement_kind="production-observed")
    with pytest.raises(ValueError, match="unapproved benchmark is refused"):
        build_run(tenant_id="t", method=local_method("Ed25519", sample_count=3),
                  results=run.results, approved=False)


def test_unsupported_algorithms_are_external_acts_never_invented():
    with pytest.raises(ValueError, match="external act"):
        run_local_benchmark(tenant_id="t", algorithm="ML-DSA-65",
                            sample_count=5)
    assert any("ML-DSA" in act for act in EXTERNAL_ACTS)


# -- §8 Digital Twin correlation -------------------------------------------

def test_a_time_correlation_alone_never_proves_causation():
    before = [_m(i, "crypto.tls_handshake_ms", 35.0, minutes_ago=120 - i)
              for i in range(6)]
    after = [_m(100 + i, "crypto.tls_handshake_ms", 82.0, minutes_ago=30 - i)
             for i in range(6)]
    report = correlate_change_with_metrics(
        {"time": NOW - timedelta(minutes=45),
         "description": "TLS configuration changed",
         "evidence_ids": ["ev-001"]},
        before + after,
        before_start=NOW - timedelta(hours=2),
        before_end=NOW - timedelta(minutes=50),
        after_start=NOW - timedelta(minutes=40),
        after_end=NOW,
        affected_assets=["asset-1"])
    assert report["conclusion"] == "Correlation detected — causation unproven"
    not_proven = " ".join(report["evidence"]["not_proven"])
    assert "A time correlation alone does not prove" in not_proven
    assert "Other possible causes still need investigation" in not_proven
    assert report["difference_p95"] == 47.0
    assert report["evidence"]["proven"], "what is proven is still stated"
