"""Performance measurements remain context inside hypothetical simulations."""
from datetime import datetime, timedelta, timezone

from shared_models.performance_metrics import PerformanceMetric
from shared_models.performance_simulation import (
    compare_bank_windows, compare_controlled_benchmarks,
)

NOW = datetime.now(timezone.utc) - timedelta(hours=1)
WINDOWS = {"before_start": "b0", "before_end": "b1",
           "after_start": "a0", "after_end": "a1"}


def metric(index, value, quality="valid", signed=False):
    return PerformanceMetric(
        metric_id=f"sample-{index}", tenant_id="bank-a", asset_id="app:pay",
        metric_name="crypto.tls_handshake_ms", metric_type="gauge",
        metric_value=value, unit="ms", source_id="bank-exporter-1",
        observed_at=NOW + timedelta(seconds=index), quality_status=quality,
        evidence_id="signed-capture:" + "a" * 64 if signed else None,
    )


def report(before, after):
    return compare_bank_windows(
        before, after, asset_ref="app:pay", metric_name="crypto.tls_handshake_ms",
        unit="ms", source_id="bank-exporter-1", change_event_id="change-1",
        windows=WINDOWS)


def test_insufficient_or_partial_telemetry_stays_simulation_context():
    insufficient = report([metric(1, 20)], [metric(2, 30)])
    assert insufficient["status"] == "NOT_EVALUABLE"
    assert insufficient["delta_p95"] is None
    assert insufficient["purpose"] == "SIMULATION_INPUT"
    assert "migration_plan" not in insufficient
    before = [metric(i, 20, signed=True) for i in range(5)]
    after = [metric(i + 10, 30, signed=True) for i in range(5)] + [
        metric(99, None, "missing", signed=True)]
    partial = report(before, after)
    assert partial["status"] == "MEASURED_COMPARISON_PARTIAL"
    unsigned = report([metric(i + 100, 20) for i in range(5)], after)
    assert unsigned["status"] == "PROVISIONAL_UNATTESTED"
    assert "unverified" in unsigned["input_state"]
    assert partial["before"]["p95"] == 20
    assert partial["after"]["p95"] == 30
    assert partial["delta_percent"] == 50
    assert partial["after"]["missing_or_stale"] == 1
    assert partial["causation"] == "UNPROVEN"
    assert "predict post-migration performance" in partial["not_proven"][0]


def test_benchmark_context_mismatch_never_produces_ratio():
    method = {"hardware": "lab-1", "software": "provider-v1", "provider": "bank-HSM",
              "algorithm": "RSA-2048", "methodology": "approved-lab", "concurrency": 2,
              "sample_count": 5}
    baseline = {"run_id": "old", "approved": True,
                "measurement_kind": "controlled_benchmark", "method": method,
                "results": [{"operation": "sign", "mean_ms": 2.0, "samples": 5}]}
    candidate = {**baseline, "run_id": "new",
                 "method": {**method, "algorithm": "ML-DSA"},
                 "results": [{"operation": "sign", "mean_ms": 3.0, "samples": 5}]}
    compared = compare_controlled_benchmarks(baseline, candidate)
    assert compared["status"] == "CONTROLLED_COMPARISON"
    assert compared["operations"][0]["delta_percent"] == 50
    assert "never production traffic" in compared["note"]
    different = {**candidate, "method": {**candidate["method"], "hardware": "other-HSM"}}
    assert compare_controlled_benchmarks(baseline, different)["status"] == "NOT_COMPARABLE"
    assert compare_controlled_benchmarks(baseline, None)["status"] == "NOT_SUPPLIED"
