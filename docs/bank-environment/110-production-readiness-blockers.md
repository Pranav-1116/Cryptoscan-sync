# 110 — Production blockers, graded against evidence

This is a response to a review that said, correctly, **the branch is not yet
bank-production-ready**, and listed eight blockers. The review is right. What
follows is not a rebuttal and not a roadmap of intentions: each blocker is
graded against something in this repository that either exists and was run, or
does not.

**Grades used here**

| Grade | Meaning |
|---|---|
| **PROVEN** | the property is measured by an artifact or a drill in this repo, and the artifact states its own limit |
| **PARTIAL** | part of the blocker is proven and the rest is named; the gap is specific, not "needs work" |
| **BLOCKED** | not proven here — no measurement, no deployment, or the scale at which it was measured is an order of magnitude short |

**Verdict: not bank-production-ready.** Nothing in this document changes that.
What it does is make the distance concrete, so the next increment is a decision
rather than an opinion.

| # | Blocker | Grade | What proves what is proven | The gap that keeps it open |
|---|---|---|---|---|
| 1 | End-to-end production qualification | **BLOCKED** | 1,255 operations executed on uvicorn + PostgreSQL (guide 100 §5b); 20/20 collector families have code (105) | no data-path test per collector: collector → agent → API → evidence → DB → Twin → BOM → UI |
| 2 | Worker / job architecture | **PARTIAL** | `111-job-contract.md`: 9/9 properties proven by drill | no retry-after-failure or backoff; cancellation is a checkpoint boundary; concurrency is per process |
| 3 | PostgreSQL production qualification | **PARTIAL** | 125 migrations at tip, applied and swept on real PG; PITR/backup/failover drills exist as scripts | no partitioning, no 1M-row or concurrent-write measurement, drills not executed here |
| 4 | Evidence durability | **PARTIAL** | content hash + append-only chain hash, verified at ingest, at pack export and on datalake/stream reads | nothing enforces chain verification when the Twin or a BOM reads rows; no corruption-injection test |
| 5 | Complete authorization model | **PARTIAL** | 1,225 operations in the authorization register; approvals carry a typed contract | per-collector target authority is not uniform; the five questions are answered by different mechanisms per family |
| 6 | Performance at bank scale | **BLOCKED** | 150 banks / 2,161 assets / 2,782 edges, ingest 0.029 s (108) | 100k assets, 1M observations, millions of relationships, continuous ingestion: not measured |
| 7 | Observability | **PARTIAL** | `/metrics` (dependency, scanner-family, scan-duration), healthz/readyz, Prometheus alerts, Grafana dashboards | no tracing; no evidence-health, coverage-health or agent-health metric; alerts not exercised |
| 8 | Frontend production hardening | **PARTIAL** | 600 of 1,255 endpoints reachable from the console; 96 frontend test files | authorization-aware views, large-graph handling, realtime consistency: not audited at page level |

Each blocker is taken in turn below: what is proven, what is not, and the one
increment that would move its grade.

---

## 1. End-to-end production qualification — **BLOCKED**

**Proven.** Every one of the **1,255** operations is executed against uvicorn on
a migrated PostgreSQL with **0 × 5xx** and 0 transport failures (guide 100,
check 8), and **581** mutation-safe writes are executed with synthesised,
schema-valid bodies (check 10). The collector register (guide 105) lists **20/20
families with code**, 14 of them production adapters.

**Not proven.** That any of that composes into a *data path*. What the sweep
shows is that each endpoint answers; it says nothing about whether a runtime
observation from the agent lands in the evidence table, becomes a graph fact,
reaches the Twin, and changes the BOM's component count — for each collector
family. The synthetic estate (108) exercises the graph→evidence→BOM half of that
chain, and the estate observation sync (`estate_observations.fact_rows`) is the
join between the two; neither is driven from a real collector's payload in a
test.

**What closes it.** A per-family golden-path test: a captured collector payload →
ingest → evidence rows with a verified chain → graph → Twin projection → BOM
component, asserting the *count and identity* of what arrives, for at least the
five families a bank starts with (network TLS, static code, cloud, PKI, runtime).

## 2. Worker / job architecture — **PARTIAL**

**Proven** (guide 111, nine properties, each by an executed drill):

| Property | Observed |
|---|---|
| job queue | one claim, job moves under a lease, second pop gets nothing, ack releases |
| worker | peak concurrency = `max_workers`; a raising handler is reported `False`, slot released |
| retry | orphan requeued, redelivered with `attempts=1`, bounded by `max_redeliveries` |
| timeout | lease expiry recovers; RUNNING row past 90 m → `FAILED`; expired deadline → `ExecutionDenied` at the next checkpoint |
| cancellation | cancelled row denied at the next checkpoint; the same call on a RUNNING row gets past it |
| idempotency | outbox publishes once; duplicate row refused by unique key; duplicate delivery refused at SQL claim |
| dead-letter | past the retry budget → dead-letter with a reason, queue empty |
| recovery | killed consumer's job requeued and completed by the next consumer |
| concurrency | `max_workers=1, queue_limit=1` → third submit blocks until a slot frees |

**Not proven, and this is the honest part.**

- **There is no retry-after-failure.** A handler that raises is logged, reported
  `False` and **acked**; the queue retries only when a *worker* is lost. A
  transient collector error is therefore a failed job, not a retried one, and
  there is no backoff, jitter or retry budget on the job itself.
- **Cancellation is a checkpoint, not a signal.** A stage already running runs to
  the end of that stage; nothing interrupts a stage that never returns.
- **Concurrency is per process.** `WorkerPool` bounds admittance in one worker;
  there is no cluster-wide admission budget in these drills (the execution
  budgets exist for approvals, which is a different axis).
- Nothing here was measured with a backlog of thousands, or two workers racing on
  the same row.

**What closes it.** Retry-with-backoff for retryable failures (a classifier on the
error, a per-job retry budget, jitter, and a row state that says "will retry at
T"), then the same drills re-run against a real Redis with a backlog.

## 3. PostgreSQL production qualification — **PARTIAL**

**Proven.** **125** Alembic migrations, applied at the tip, with the whole API
swept over the result (guide 100 §5b, check 8). Schema parity is checked between
all **155** mapped tables/columns and the migrated schema in both directions.
Backup/restore is integrity-gated: signature, ciphertext hash, archive hash and
dump hash are all verified before the backend is touched (guide 109, `database`
row — four altered artifacts refused). PITR, failover, region and disposable
Redis drills exist as scripts (`pitr_drill.py`, `postgres_drill.py`,
`region_drills.py`, `drill_disposable_redis.py`).

**Not proven.** Nothing in this repository demonstrates, at bank volume:
transaction isolation under concurrent writers, lock contention on the hot
tables, connection-pool behaviour at saturation, partitioning (there is none
here for evidence/observations), retention enforcement against real row counts,
or recovery from a *corrupted* database as opposed to a missing one. The drills
that would show failover and PITR need a host and were **not executed here**.

**What closes it.** A PostgreSQL qualification run: concurrent-write and
lock-wait measurement on the hot tables, pool exhaustion behaviour, a 1M-row
evidence table with the retention job, and the PITR/failover drills executed on
a host with the output attached.

## 4. Evidence durability — **PARTIAL**

**Proven.** Evidence rows carry `content_hash`, `chain_position`, `chain_hash`
and `previous_hash`; the chain is computed at ingest and verified at chain
creation (`evidence/core/pipeline.py`), at evidence-pack export
(`evidence/pack/evidence_pack.py`) and on datalake and stream reads. Duplicate
content is collapsed **before** positions are assigned, so positions stay
gapless and the chain is verifiable from genesis — the comment in the pipeline
explains why the obvious alternative (a unique index) would abort a load
mid-chain.

**Not proven.** That a *tampered or corrupted row* is refused on every read path.
The Twin, the BOM projections and the graph facts read evidence columns directly;
none of them verifies the chain. So the failure the review describes — evidence
corruption propagating into Twin/BOM/intelligence — is prevented **at write and
export time**, not at every read. There is also no corruption-injection test: no
drill flips a stored hash and shows the system refusing to project from it.

**What closes it.** A `tamper` drill (flip a chain row → show
`verify_chain` returns False → show the Twin/BOM path refuses or marks the
evidence unverified) plus a verification report on the read paths. This is the
cheapest of the eight to close and the most consequential.

## 5. Complete authorization model — **PARTIAL**

**Proven.** All **1,225** served operations are classified by the authority their
dependency closure actually demands (guide 101): **306** role, **71** permission,
**12** tenant-role, **836** session-only. Every session-only write is listed with
a policy reason (102), and the two sets partition the write surface. For scan
execution specifically, the controlled-execution path answers the review's five
questions **in data, not in prose**: the pinned authority (`progress.execution_authority`,
typed v2), the target (`target_repo` plus `scan_admission.sweep_is_authorized`
against authorised CIDRs/targets), the revision (`policy_revision` pinned at
enqueue and re-checked at every checkpoint), the window (`expires_at`,
`not_before`), the budget (`max_requests`, `max_runtime_seconds`), and the
permission (`PERMISSION_MATRIX["scan.trigger"]`) — each re-verified **inside**
the running job by `execution_control.checkpoint`, which is what the guide 111
`cancellation` row exercises.

**Not proven.** That this is uniform **per collector**. The source-control path is
fully typed and pinned; other families (cloud, PKI, hardware, agent) carry
permission checks at the route and target checks where the adapter implements
them, and there is no single register that says, for each collector family, which
of the five questions is enforced where. 836 operations still hold nothing
beyond a session, and the register records intent ("operator surface: estate
curation") rather than per-route proof.

**What closes it.** A per-collector authority table — one row per family × the
five questions × the mechanism that enforces it — generated from the code, with
any cell that is not enforced printed as `NOT ENFORCED`.

## 6. Performance at bank scale — **BLOCKED**

**Proven.** 10/50/100/150 synthetic banks: 2,161 assets, 1,098 evidence rows,
2,782 relationships, ingest **0.029 s**, peak RSS **104 MB**, accuracy 1.000
against a planted key, refusals 300/300, correlation 150/150 (guide 108). Ingest
is linear across the 15× range.

**Not proven — and this is the blocker.** The largest measured estate is
**2,161 assets**. The review asks for **100k+ assets, 1M+ observations,
millions of relationships, under continuous ingestion**. That is roughly **46×**
the assets and **3 orders of magnitude** the observation count; the linear
extrapolation (≈1.3 s ingest, ≈5 GB) is arithmetic, not a measurement, and the
graph queries, the Twin projection and the BOM builds are not linear by
construction. `scripts/load_test.py`, `perf_benchmark.py` and
`operator_loop_drill.py` exist but were not run at that scale here.

**What closes it.** One measured run at 100k assets / 1M observations /
5M relationships — ingest time, peak RSS, p95 of the Twin and BOM builds, and the
query plans for the hot reads — with the numbers in an artifact like 108, and the
first place it stops being linear named rather than smoothed.

## 7. Observability — **PARTIAL**

**Proven.** `GET /metrics` in Prometheus text format (token-gated in production),
exporting dependency up/latency, degraded-dependency count, operational counters,
scan-duration histograms, scanner-family job counts and telecom counters
(`api/routers/metrics.py`). `/healthz` is liveness only and stays 200 through a
database stall; `/readyz` answers 503 inside a **4 s** budget when the database
stops answering rather than hanging (guide 109, `api` row). Prometheus
`alerts.yml` and Grafana dashboards exist under `infra/monitoring`.

**Not proven.** No distributed tracing anywhere in the tree. The metrics cover
dependencies, scans and scanner families — not **evidence health** (chain
verification failures), **coverage health** (planes that stopped being collected),
**queue health** (depth, age, dead-letter growth) or **agent health** (last
check-in). The alert rules have not been fired against a live stack, so their
thresholds are unvalidated.

**What closes it.** The four missing metric families (evidence chain failures,
collection coverage per plane, queue depth/age/dead-letter, agent last-seen), and
a drill that fires each alert once and records the notification.

## 8. Frontend production hardening — **PARTIAL**

**Proven.** **600 of 1,255** endpoints have a console caller (47.8%), **786**
appear in a test, and 96 frontend test files exist. The surface numbers are
regenerated by `scripts/audit_build_status.py` from source, so they cannot drift
silently.

**Not proven.** This list has not been audited page by page in this pass. What is
known and measurable: 655 endpoints have **no** console caller, so "complete API
contract coverage" is false as stated; authorization-aware views, degraded-coverage
visualisation, large-graph handling, pagination and realtime consistency are not
covered by any test I can point at.

**What closes it.** A page-level audit with the same discipline as guide 100: for
each page, the state it shows when its data is empty, degraded, unauthorised and
large — with a screenshot or a test per state, and the missing 655 endpoints
either given a screen or explicitly declared API-only.

---

## The order I would take them

1. **Evidence durability (#4)** — the cheapest to close and the one the review
   calls the source of truth. A tamper drill plus read-path verification turns a
   `PARTIAL` into a `PROVEN` and protects every layer above it.
2. **Worker retry (#2)** — one gap inside an otherwise proven contract, and it is
   the difference between "a transient failure is a failed job" and "a transient
   failure is retried".
3. **End-to-end per family (#1)** — the first five collector families, because
   everything else is a component claim until a payload travels the whole chain.
4. **Bank-scale measurement (#6)** — one measured run at 100k/1M/5M; it will find
   the first non-linearity, and that finding is worth more than the table.
5. **PostgreSQL qualification (#3)**, **per-collector authority (#5)**,
   **observability gaps (#7)**, **frontend audit (#8)** — in that order, each
   with the artifact named above.
