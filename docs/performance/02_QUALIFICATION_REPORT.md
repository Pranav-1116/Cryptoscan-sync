# ZELNX Performance Intelligence — Qualification Report

> **GENERATED — do not edit.** Source: `services/performance/performance/qualification_suite.py`.
> Regenerate: `python scripts/gen_performance_qualification.py --write docs/performance/02_QUALIFICATION_REPORT.md`.

> **Status: SYNTHETIC QUALIFICATION.** Schema `cryptoscan.performance-qualification/1`. Every
> figure here comes from the deterministic SYNTHETIC corpus —
> synthetic results never qualify a real-environment act. Timings
> are reported separately and are never embedded in this document.

## Checks

- **synthetic-corpus-contract** — PASS: 500 rows, all labelled synthetic at the source; the corpus is deterministic (same seed, same rows)
- **ingestion-idempotency-under-load** — PASS: re-ingesting 500 rows reports 500 duplicates with their accepted identities and creates no second row
- **tenant-isolation-under-load** — PASS: two interleaved tenants: zero cross-tenant reads; the other tenant's metric ids resolve to None
- **missing-telemetry-honesty** — PASS: missing/stale rows carry no value; the aggregate names 5 unknowns and averages delivered values only
- **aggregate-parity** — PASS: stored aggregation matches the raw delivered measurements exactly for the documented method
- **cardinality-bounded-under-pressure** — PASS: label explosion is refused at the documented bound with its reason — bounded cardinality is enforced, not aspirational
- **prohibited-content-refused** — PASS: passwords, tokens and private keys are refused in metrics — every one, never silently dropped
- **benchmark-and-intelligence-reproducibility** — PASS: identical inputs produce identical methods, baselines and forecasts; the benchmark run is recorded as controlled-benchmark measurement, never production performance
- **retention-plan-projection** — PASS: every aged row is classified expired by the policy; the plan is a projection and never deletes originals
- **recovery-idempotent-replay** — PASS: an interrupted batch re-submitted in full converges on the same 25 identities — no duplicates, no lost rows
- **collector-translator-refusal** — PASS: an unknown exporter family is refused with its reason — a unit is never guessed
- **synthetic-volume-run** — PASS: 2000 synthetic rows ingested through the real contracts; timings are reported separately and are a SYNTHETIC benchmark, never a real-estate measurement

**Summary: 12/12 checks pass.**

## External acts

These are real-environment acts. The platform never marks them done
from inside the repository:

- **collection-overhead-on-representative-bank-systems** — EXTERNAL — NOT DONE (register only): overhead is measured on the bank's systems, not in this repository (docs/performance/01_PRODUCT_SPEC.md §10 success criteria)
- **hsm-kms-and-pqc-controlled-benchmarks** — EXTERNAL — NOT DONE (register only): ML-DSA/ML-KEM/hybrid-TLS and HSM/KMS benchmarks need the providers; a fixture or a name is not a qualification (§8)
- **real-exporter-wiring-node-postgres-otlp** — EXTERNAL — NOT DONE (register only): wiring real Node/PostgreSQL/OTLP exporters is a real-environment act
- **real-bank-pilot-acceptance** — EXTERNAL — NOT DONE (register only): pilot acceptance is the bank's act; the platform can only register it

## Rules this harness holds

- Missing telemetry is marked unknown or stale, never zero.
- Metric ingestion is idempotent; recovery replays converge.
- No cross-tenant metric access.
- High-cardinality inputs are bounded.
- Historical aggregates match raw measurements exactly for the
  documented method.
- Benchmark results are reproducible and never presented as
  production traffic performance.
- A retention plan is a projection — it never deletes originals.
- Passwords, tokens and private keys are never metrics.

SYNTHETIC qualification: results from this harness never qualify a real-environment act (docs/performance/01_PRODUCT_SPEC.md §10)
