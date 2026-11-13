"""Read-only measured performance context for a hypothetical Twin simulation.

A measured before/after difference is not a causal verdict or a release gate.
Controlled benchmarks stay in their own lane: their means are never mixed with
production p95, and two runs are comparable only under the same recorded method.
"""
from __future__ import annotations

from math import isfinite
from typing import Any, Mapping, Sequence

from shared_models.performance_metrics import PerformanceMetric, QualityStatus
from shared_models.performance_views import summarize_metric

MIN_VALID_SAMPLES = 5


def _window(rows: Sequence[PerformanceMetric]) -> dict[str, Any]:
    valid = [row for row in rows if row.quality_status == QualityStatus.VALID
             and row.metric_value is not None and isfinite(row.metric_value)]
    summary = summarize_metric(valid)
    return {
        "received": len(rows), "valid": len(valid),
        "signed_capture_samples": sum(
            (row.evidence_id or "").startswith("signed-capture:")
            for row in valid),
        "partial_quality": sum(row.quality_status == QualityStatus.PARTIAL for row in rows),
        "missing_or_stale": sum(row.quality_status in (QualityStatus.MISSING, QualityStatus.STALE)
                                for row in rows),
        "p95": summary["p95"],
        "metric_ids": [row.metric_id for row in valid[:20]],
        "metric_ids_truncated": len(valid) > 20,
        "evidence_refs_unverified": sorted({row.evidence_id for row in rows if row.evidence_id})[:20],
    }


def compare_bank_windows(before: Sequence[PerformanceMetric],
                         after: Sequence[PerformanceMetric], *,
                         asset_ref: str, metric_name: str, unit: str,
                         source_id: str, change_event_id: str,
                         windows: Mapping[str, str]) -> dict[str, Any]:
    """Compare exact tenant/asset/source/metric windows for a Twin question."""
    prior, candidate = _window(before), _window(after)
    enough = prior["valid"] >= MIN_VALID_SAMPLES and candidate["valid"] >= MIN_VALID_SAMPLES
    delta = None
    percent = None
    if enough:
        delta = round(candidate["p95"] - prior["p95"], 6)
        if prior["p95"] != 0:
            percent = round(delta / abs(prior["p95"]) * 100, 2)
    signed = all(window["signed_capture_samples"] == window["valid"]
                 for window in (prior, candidate))
    status = ("NOT_EVALUABLE" if not enough else
              "PROVISIONAL_UNATTESTED" if not signed else
              "MEASURED_COMPARISON_PARTIAL" if any(
                  window["partial_quality"] or window["missing_or_stale"]
                  for window in (prior, candidate)) else "MEASURED_COMPARISON")
    return {
        "schema": "cryptoscan.performance-simulation-context/1",
        "purpose": "SIMULATION_INPUT",
        "status": status, "asset_ref": asset_ref,
        "metric_name": metric_name, "unit": unit, "source_id": source_id,
        "change_event_id": change_event_id,
        "windows": dict(windows), "before": prior, "after": candidate,
        "delta_p95": delta, "delta_percent": percent,
        "causation": "UNPROVEN",
        "input_state": ("insufficient valid measurements" if not enough else
                        "capture origin unverified" if not signed else
                        "measured context only — no hypothetical performance predicted"),
        "not_proven": [
            "the simulation does not predict post-migration performance from these historical samples",
            "time correlation does not prove the cryptographic change caused the difference",
            "this source and interval do not prove peak-load, cross-service or fleet coverage",
            "metric evidence references are unverified until checked against their source",
        ],
    }


def compare_controlled_benchmarks(baseline: Mapping[str, Any] | None,
                                  candidate: Mapping[str, Any] | None) -> dict[str, Any]:
    """Keep two approved lab runs separate from observed bank telemetry."""
    if baseline is None or candidate is None:
        return {"status": "NOT_SUPPLIED", "measurement_kind": "controlled_benchmark",
                "note": "no paired approved controlled runs were supplied"}
    methods = [row.get("method") if isinstance(row.get("method"), Mapping) else {}
               for row in (baseline, candidate)]
    common = ("hardware", "software", "provider", "methodology", "concurrency", "sample_count")
    if (not all(row.get("approved") is True
                and row.get("measurement_kind") == "controlled_benchmark"
                for row in (baseline, candidate))
            or any(methods[0].get(key) != methods[1].get(key)
                   or not methods[0].get(key) for key in common)):
        return {"status": "NOT_COMPARABLE", "measurement_kind": "controlled_benchmark",
                "note": "approval or reproducibility fields differ; no performance ratio is reported"}
    a = {row["operation"]: row for row in baseline.get("results") or []
         if isinstance(row, Mapping) and isinstance(row.get("operation"), str)}
    b = {row["operation"]: row for row in candidate.get("results") or []
         if isinstance(row, Mapping) and isinstance(row.get("operation"), str)}
    operations = sorted(a.keys() & b.keys())
    comparisons = []
    for operation in operations:
        old, new = a[operation].get("mean_ms"), b[operation].get("mean_ms")
        if not isinstance(old, (int, float)) or not isinstance(new, (int, float)) \
                or not isfinite(old) or not isfinite(new) or old <= 0 \
                or a[operation].get("samples") != methods[0]["sample_count"] \
                or b[operation].get("samples") != methods[1]["sample_count"]:
            continue
        comparisons.append({"operation": operation, "baseline_mean_ms": old,
                            "candidate_mean_ms": new,
                            "delta_percent": round((new - old) / old * 100, 2)})
    if not comparisons:
        return {"status": "NOT_COMPARABLE", "measurement_kind": "controlled_benchmark",
                "note": "no equally sampled, finite, shared operations were measured"}
    return {
        "status": "CONTROLLED_COMPARISON", "measurement_kind": "controlled_benchmark",
        "run_ids": [baseline["run_id"], candidate["run_id"]],
        "algorithms": [methods[0].get("algorithm"), methods[1].get("algorithm")],
        "method": {key: methods[0][key] for key in common},
        "operations": comparisons,
        "note": "approved controlled results only; never production traffic or a bank migration verdict",
    }
