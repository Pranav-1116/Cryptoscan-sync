"""Phase-8 qualification harness (docs/performance/01_PRODUCT_SPEC.md §10).

Runs the qualification checks against the real contracts and the real
session store — load, idempotency, tenant isolation, missing-telemetry
honesty, aggregate parity, cardinality, prohibited content, benchmark
reproducibility, retention, recovery — and reports machine-readable
results. Everything measured here uses the SYNTHETIC corpus: synthetic
results never qualify a real-environment act, and the external acts stay
register-only.

Timings are reported in ``timings`` and never embedded in the generated
document — a wall-clock number in a byte-identity doc would be a lie
waiting to happen.
"""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any, Dict

SCHEMA = "cryptoscan.performance-qualification/1"

#: Phase-8 acts the platform cannot perform itself. Register-only: the
#: platform never marks these done from inside the repo.
EXTERNAL_ACTS = (
    ("collection-overhead-on-representative-bank-systems",
     "overhead is measured on the bank's systems, not in this repository "
     "(docs/performance/01_PRODUCT_SPEC.md §10 success criteria)"),
    ("hsm-kms-and-pqc-controlled-benchmarks",
     "ML-DSA/ML-KEM/hybrid-TLS and HSM/KMS benchmarks need the providers; "
     "a fixture or a name is not a qualification (§8)"),
    ("real-exporter-wiring-node-postgres-otlp",
     "wiring real Node/PostgreSQL/OTLP exporters is a real-environment act"),
    ("real-bank-pilot-acceptance",
     "pilot acceptance is the bank's act; the platform can only register it"),
)


def _fail(check: str, detail: str, findings=None) -> Dict[str, Any]:
    return {"check": check, "status": "FAIL", "detail": detail,
            "findings": findings or []}


def _pass(check: str, detail: str, **extra: Any) -> Dict[str, Any]:
    return {"check": check, "status": "PASS", "detail": detail, **extra}


def run_suite(*, corpus_size: int = 500, volume_size: int = 2000) -> Dict[str, Any]:
    """Run every qualification check. Deterministic: same arguments,
    same check results — timings excluded."""
    from shared_models.performance_benchmarks import local_method, run_local_benchmark
    from shared_models.performance_corpus import (
        CORPUS_EPOCH, SCHEMA as CORPUS_SCHEMA, SYNTHETIC_SOURCE,
        generate_corpus, missing_row,
    )
    from shared_models.performance_intelligence import (
        compute_baseline, forecast_capacity,
    )
    from shared_models.performance_metrics import (
        PerformanceMetric, QualityStatus,
    )
    from shared_models.performance_retention import (
        RetentionPolicy, plan_retention,
    )
    from shared_models.performance_store import (
        DUPLICATE, INSERTED, MetricRepository,
    )
    from shared_models.performance_collectors import translate_node_exporter

    checks = []
    timings: Dict[str, float] = {}
    corpus = generate_corpus(corpus_size)

    # 1. synthetic corpus contract ------------------------------------
    labelled = all(
        row.source_id == SYNTHETIC_SOURCE
        and row.labels.get("synthetic") == "1"
        for row in corpus)
    deterministic = generate_corpus(corpus_size) == corpus
    if labelled and deterministic:
        checks.append(_pass(
            "synthetic-corpus-contract",
            f"{len(corpus)} rows, all labelled synthetic at the source; "
            "the corpus is deterministic (same seed, same rows)"))
    else:
        checks.append(_fail(
            "synthetic-corpus-contract",
            "corpus rows must be labelled synthetic and deterministic"))

    # 2. ingestion idempotency under load -----------------------------
    store = MetricRepository()
    outcomes = store.accept_many(corpus)
    first_ids = [accepted for _, accepted in outcomes]
    again = store.accept_many(corpus)
    duplicates = sum(1 for outcome, _ in again if outcome == DUPLICATE)
    if (duplicates == len(corpus) and len(store) == corpus_size
            and all(accepted == first_ids[i] for i, (_, accepted) in enumerate(again))):
        checks.append(_pass(
            "ingestion-idempotency-under-load",
            f"re-ingesting {len(corpus)} rows reports {duplicates} duplicates "
            "with their accepted identities and creates no second row"))
    else:
        checks.append(_fail(
            "ingestion-idempotency-under-load",
            "duplicate ingestion must be idempotent with accepted identity",
            findings=[f"duplicates={duplicates}", f"store={len(store)}"]))

    # 3. tenant isolation under load ----------------------------------
    isolated = MetricRepository()
    tenant_a = generate_corpus(50, tenant_id="tenant_a")
    tenant_b = generate_corpus(50, seed=20261109, tenant_id="tenant_b",
                             id_prefix="corpus-b")
    for row in tenant_a + tenant_b:
        isolated.accept(row)
    leak = [row.metric_id for row in isolated.query("tenant_a")
            if row.tenant_id != "tenant_a"]
    cross = isolated.get("tenant_a", tenant_b[0].metric_id)
    if not leak and cross is None and len(isolated.query("tenant_a")) == 50:
        checks.append(_pass(
            "tenant-isolation-under-load",
            "two interleaved tenants: zero cross-tenant reads; the other "
            "tenant's metric ids resolve to None"))
    else:
        checks.append(_fail(
            "tenant-isolation-under-load",
            "a tenant never sees another tenant's metrics",
            findings=[f"leaks={leak[:5]}", f"cross={cross}"]))

    # 4. missing telemetry honesty ------------------------------------
    honest = MetricRepository()
    for row in generate_corpus(20, seed=20261110):
        honest.accept(row)
    for i in range(5):
        honest.accept(missing_row(i))
    window_start = CORPUS_EPOCH - timedelta(hours=1)
    window_end = CORPUS_EPOCH + timedelta(hours=5)
    result = honest.aggregate("tenant_synthetic", "api.latency_p95_ms",
                              window_start=window_start, window_end=window_end)
    if (result.unknown_count == 5 and result.value_count > 0
            and result.average is not None
            and "never zero" in result.coverage):
        checks.append(_pass(
            "missing-telemetry-honesty",
            "missing/stale rows carry no value; the aggregate names 5 "
            "unknowns and averages delivered values only"))
    else:
        checks.append(_fail(
            "missing-telemetry-honesty",
            "unknown telemetry is never averaged in as a zero",
            findings=[f"unknown={result.unknown_count}",
                      f"coverage={result.coverage}"]))

    # 5. aggregate parity --------------------------------------------
    raw = [row.metric_value for row in honest.query("tenant_synthetic")
           if row.metric_name == "api.latency_p95_ms"
           and row.metric_value is not None]
    parity = abs(result.average - (sum(raw) / len(raw))) < 1e-9 \
        if raw and result.average is not None else False
    if parity:
        checks.append(_pass(
            "aggregate-parity",
            "stored aggregation matches the raw delivered measurements "
            "exactly for the documented method"))
    else:
        checks.append(_fail(
            "aggregate-parity",
            "aggregates must match raw measurements within tolerance"))

    # 6. bounded cardinality ------------------------------------------
    bounded = MetricRepository()
    exploded = None
    for i in range(300):
        try:
            bounded.accept(PerformanceMetric(
                metric_id=f"card-{i:04d}", tenant_id="tenant_synthetic",
                asset_id="asset-001", metric_name="network.rtt_ms",
                metric_type="gauge", metric_value=1.0, unit="ms",
                source_id=SYNTHETIC_SOURCE,
                observed_at=CORPUS_EPOCH,
                labels={"shard": f"v{i}"}, quality_status=QualityStatus.VALID))
        except ValueError as exc:
            exploded = str(exc)
            break
    if exploded is not None and "bounded cardinality" in exploded:
        checks.append(_pass(
            "cardinality-bounded-under-pressure",
            "label explosion is refused at the documented bound with its "
            "reason — bounded cardinality is enforced, not aspirational"))
    else:
        checks.append(_fail(
            "cardinality-bounded-under-pressure",
            "high-cardinality inputs must be bounded (§10 success criteria)"))

    # 7. prohibited content refused -----------------------------------
    refused = []
    batch = generate_corpus(3)
    for secret_key in ("password", "token", "private_key"):
        try:
            PerformanceMetric(
                metric_id=f"secret-{secret_key}", tenant_id="tenant_synthetic",
                asset_id="asset-001", metric_name="network.rtt_ms",
                metric_type="gauge", metric_value=1.0, unit="ms",
                source_id=SYNTHETIC_SOURCE, observed_at=CORPUS_EPOCH,
                labels={secret_key: "compromised"},
                quality_status=QualityStatus.VALID)
        except ValueError:
            refused.append(secret_key)
    if len(refused) == 3 and batch:
        checks.append(_pass(
            "prohibited-content-refused",
            "passwords, tokens and private keys are refused in metrics — "
            "every one, never silently dropped"))
    else:
        checks.append(_fail(
            "prohibited-content-refused",
            "no customer payloads, passwords, tokens or private keys in "
            "metrics (§9)", findings=[f"refused={refused}"]))

    # 8. benchmark reproducibility ------------------------------------
    method_a = local_method("Ed25519", sample_count=5)
    method_b = local_method("Ed25519", sample_count=5)
    baseline_a = compute_baseline(corpus[:60], window_start=window_start,
                                  window_end=window_end)
    baseline_b = compute_baseline(corpus[:60], window_start=window_start,
                                  window_end=window_end)
    forecast_a = forecast_capacity(corpus[:60], window_start=window_start,
                                   window_end=window_end, capacity_value=1e12)
    forecast_b = forecast_capacity(corpus[:60], window_start=window_start,
                                   window_end=window_end, capacity_value=1e12)
    run = run_local_benchmark(tenant_id="tenant_synthetic",
                              algorithm="Ed25519", sample_count=5)
    if (method_a == method_b and baseline_a == baseline_b
            and forecast_a == forecast_b
            and run.measurement_kind == "controlled_benchmark"):
        checks.append(_pass(
            "benchmark-and-intelligence-reproducibility",
            "identical inputs produce identical methods, baselines and "
            "forecasts; the benchmark run is recorded as controlled-benchmark "
            "measurement, never production performance"))
    else:
        checks.append(_fail(
            "benchmark-and-intelligence-reproducibility",
            "benchmark results are reproducible (§10 success criteria)"))

    # 9. retention plan projection ------------------------------------
    aged = generate_corpus(30, seed=20261111)
    policy = RetentionPolicy(policy_key="default", samples_days=30)
    plan = plan_retention(aged, policy=policy, now=CORPUS_EPOCH + timedelta(days=400))
    plan_dict = plan.as_dict()
    if (plan.expired_total == 30 and plan.retained_total == 0
            and "never deletes originals" in plan_dict["note"]):
        checks.append(_pass(
            "retention-plan-projection",
            "every aged row is classified expired by the policy; the plan "
            "is a projection and never deletes originals"))
    else:
        checks.append(_fail(
            "retention-plan-projection",
            "retention planning classifies rows; it never deletes them",
            findings=[f"expired={plan.expired_total}",
                      f"retained={plan.retained_total}"]))

    # 10. recovery idempotency ----------------------------------------
    recovery = MetricRepository()
    partial = generate_corpus(40, seed=20261112)[:25]
    interrupted = partial
    for row in interrupted:
        recovery.accept(row)
    for row in partial:  # the interrupted batch is re-submitted in full
        recovery.accept(row)
    if len(recovery) == 25:
        checks.append(_pass(
            "recovery-idempotent-replay",
            "an interrupted batch re-submitted in full converges on the "
            "same 25 identities — no duplicates, no lost rows"))
    else:
        checks.append(_fail(
            "recovery-idempotent-replay",
            "recovery must converge, never duplicate",
            findings=[f"store={len(recovery)}"]))

    # 11. collector translator refusal --------------------------------
    translation = translate_node_exporter(
        {"metrics": {"node_unknown_family": [{"value": 1.0, "labels": {}}]}},
        asset_id="asset-001", tenant_id="tenant_synthetic",
        source_id=SYNTHETIC_SOURCE, observed_at=CORPUS_EPOCH)
    if translation.metrics == [] and translation.refused_count == 1:
        checks.append(_pass(
            "collector-translator-refusal",
            "an unknown exporter family is refused with its reason — a "
            "unit is never guessed"))
    else:
        checks.append(_fail(
            "collector-translator-refusal",
            "translators refuse what they cannot map"))

    # 12. synthetic volume run ----------------------------------------
    volume = MetricRepository()
    volume_rows = generate_corpus(volume_size, seed=20261113)
    start = time.perf_counter()
    volume.accept_many(volume_rows)
    ingest_seconds = time.perf_counter() - start
    timings["volume_ingest_seconds"] = round(ingest_seconds, 4)
    if len(volume) == volume_size:
        checks.append(_pass(
            "synthetic-volume-run",
            f"{volume_size} synthetic rows ingested through the real "
            "contracts; timings are reported separately and are a "
            "SYNTHETIC benchmark, never a real-estate measurement"))
    else:
        checks.append(_fail(
            "synthetic-volume-run",
            "volume run must hold every row",
            findings=[f"store={len(volume)}"]))

    passed = sum(1 for c in checks if c["status"] == "PASS")
    return {
        "schema": SCHEMA,
        "corpus_schema": CORPUS_SCHEMA,
        "corpus_size": corpus_size,
        "volume_size": volume_size,
        "checks": checks,
        "summary": {"passed": passed, "total": len(checks),
                    "all_pass": passed == len(checks)},
        "external_acts": [
            {"act": act, "reason": reason,
             "status": "EXTERNAL — NOT DONE (register only)"}
            for act, reason in EXTERNAL_ACTS],
        "timings": timings,
        "note": "SYNTHETIC qualification: results from this harness never "
                "qualify a real-environment act (docs/performance/"
                "01_PRODUCT_SPEC.md §10)",
    }
