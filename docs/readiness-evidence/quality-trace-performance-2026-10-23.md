# Measured trace performance — 2026-10-23

## Agreed target, before measuring

The user approved identical synthetic before/after workloads; no correctness
regression or p95/p99 slowdown; at least **20% improvement** for the selected
bottleneck; existing resource limits and cleanup. These are relative engineering
targets, **not a bank SLA**. Persistent caching and architecture-first changes
were excluded. This record qualifies **one measured trace workload**, not the
whole supported workload or a production capacity/RTO promise.

## Method and why this fix

Actual native PostgreSQL16.2, schema0106, UTF8 disposable databases, private Unix
socket; Python3.11 with `requirements.txt` constrained by `requirements.lock.txt`.
Authentic cookie-backed API requests use the same exact estate/database, one
retained original SBOM, one deployment,50 components and50 reviewed package
links. The published baseline module from `c48f667e3dee70b0ffc48f338004382b6543f94f`
and candidate execute against **the identical seeded corpus within each run**.
No restore/reseed between their requests. Full response JSON is compared on
every measured response, with50 paths and runtime/complete flags still false.

Concurrency1;3 warmups then25 measured requests per implementation, baseline
first. Latencies include auth/API/SQL, measured with `perf_counter`; query counts
use SQLAlchemy events. p50/p95/p99 use nearest-rank sample order statistics;
p99 here is the maximum of25 observations, **not a statistically stable bank
p99 estimate**. Baseline-first order, small corpus, warm filesystem and local
single-host conditions limit generalization. An actual `EXPLAIN (ANALYZE,
BUFFERS, FORMAT JSON)` is retained for the exact-owner evidence lookup. No index
change was made or claimed necessary from this small-corpus plan.

Before optimizing, the first recorded run demonstrated **169 SQL statements**
per request. The correctness-only candidate still issued169 queries and its
latency tails increased. This diagnostic was retained rather than accepted as
meeting the target. See [pre-optimization raw data](quality-six-bom-perf-recovery-2026-10-23/preoptimization.json).

Only then was the proven N+1 fixed: one request-local exact-tenant supporting-
evidence batch per binding; reuse already loaded binding/canonical identities
inside that request. No TTL/cross-request cache, architecture rewrite, new
service or generalized index was added. Current observation integrity,
withdrawal, assertion envelopes and per-link freshness remain checked.

## Final paired run

| Metric | Published baseline | Current candidate |
|---|---:|---:|
| p50 milliseconds | 365.529 | 38.848 |
| p95 milliseconds | 381.334 | 41.527 |
| p99 milliseconds | 385.481 | 41.861 |
| SQL statements/request | 169 | 20 |
| Response bytes | 51147 | 51147 |

**p95 improved 89.11%**; query count fell **88.17%**. The selected
workload passes the20% improvement and no p95/p99 slowdown assertions.
Successful response bodies were exactly equal; separate correctness regression
is248/248 and native suite19/19. Existing limits remain, including fail-closed
trace budgets. These results do not establish unchanged latency of other routes.

[All25 raw samples, query counts and SQL plan](quality-six-bom-perf-recovery-2026-10-23/performance.json),
[commands/results/input hashes](quality-six-bom-perf-recovery-results-2026-10-23.json),
[correctness scope](quality-six-bom-correctness-2026-10-23.md).

## Reproduction and safety

Use a Python3.11 virtual environment with `pip install -r requirements.txt -c
requirements.lock.txt`. The external bootstrap used in this run calls
`scripts/_bootstrap.py`, adds service/shared package roots and the API unit-test
helper directory to `PYTHONPATH`, then invokes pytest. An equivalent shell setup
from the repository root is:

```bash
export PYTHONPATH="$(python -c 'from pathlib import Path; import os; r=Path.cwd(); print(os.pathsep.join([str(r), str(r/"scripts"), str(r/"services/api/tests/unit")] + [str(p) for parent in [r/"services",r/"shared"] for p in parent.iterdir() if p.is_dir()]))')"
```

Start **only a freshly provisioned authorized disposable** native PostgreSQL
server on a private Unix socket. Never substitute a deployment URL. The fixture
creates/migrates/drops only fresh `cs_quality_<uuid>` databases, refuses remote
URLs and requires the explicit opt-in. The lab used socket
`/home/user/quality-full-pg-socket`, port55439, PostgreSQL16.2, local trust with TCP
disabled. This is **not production authentication/TLS or patch qualification**.
Set `CRYPTOSCAN_QUALITY_PG_URL` to that lab's administrative `postgres` URL,
`CRYPTOSCAN_QUALITY_PG_BIN` and `PATH` to its native client bin directory.
Set a synthetic `CRYPTOSCAN_ARTIFACT_KEY` before fixture seeding; never put a
real key in a command log. The actual final run used:

```bash
export CRYPTOSCAN_QUALITY_PG_OPT_IN=disposable-local-only
export CRYPTOSCAN_REQUIRE_IMPROVEMENT=1
export CRYPTOSCAN_MEASURE_OUT=/home/user/quality-trace-final.json
export CRYPTOSCAN_COHORT_OUT=/home/user/quality-cohort-final.json
python -m pytest services/api/tests/unit/test_workflow_postgres.py \
  services/api/tests/unit/test_restore_failure_postgres.py \
  services/api/tests/unit/test_trace_workload_postgres.py \
  services/api/tests/unit/test_isolated_cohort_recovery.py \
  -m live -q
```

The measurement test does not need `pg_dump`; the recovery tests require native
`pg_dump`, `pg_restore` and `psql`. The opt-in baseline plugin is a separate
negative comparison, **never** used for this final candidate run.

## Explicit remaining performance work

- Representative multi-route API concurrency/tails and larger BOM/evidence
  payload distributions; this50-edge response is51147 bytes, not a maximum-size
  payload qualification.
- Parser CPU, peak memory and temporary-storage/cleanup under matched large
  input and failure cases. Existing tests are not replacement measurements.
- SQL plans on production-shaped distributions; no claim that a small-corpus
  sequential scan predicts estate-scale behavior.
- Real consumer queue backlog/recovery and full role isolation. The Redis drill
  measured a16-item scratch hint backlog and duplicate hint, not worker capacity.
- Browser memory, pending-request and navigation performance versus the same
  baseline. Tenth-increment browser correctness remains historical, not a new
  memory/performance run.

Therefore **item5 is partially delivered**, with the selected demonstrated
bottleneck improved. The whole supported workload has not met its acceptance
criterion. No CI success, bank SLA or readiness promotion is inferred.
