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
| 1 | End-to-end production qualification | **PARTIAL** (five families added this pass) | `113-golden-path.md`: 5/5 families, 35/35 hops, one payload walked collector → API → evidence → DB → Twin → BOM → console with counts and identities asserted at each hop | 15 of the 20 collector families still have no data-path test; the collectors' *inputs* are fixtures, not a bank's network |
| 2 | Worker / job architecture | **PARTIAL** | `111-job-contract.md`: 9/9 properties proven by drill, now including retry-after-failure with backoff, jitter and a dead-letter ceiling | cancellation is a checkpoint boundary (a running stage is not interrupted); concurrency is per process; no backlog measurement |
| 3 | PostgreSQL production qualification | **PARTIAL** (qualified this pass) | `115-postgres-qualification.md`: **127** migrations, index parity **494 indexes / 0 missing**, 200,000-row migration read at 17.1 → 0.2 ms, 0 of 50 writes escaped a transaction boundary | **retention has no delete path** (1M facts = 645.8 MB), **no partitioning**, 239 non-concurrent index builds, and concurrent writes / backup-restore / corruption recovery / HA are `UNPROVEN` — they need a server |
| 4 | Evidence durability | **PARTIAL** | guide 112: 8 of 9 tampering attacks detected on a real stored scan; the Twin now verifies before projecting; export/audit/rescan/host-evidence already enforced | the scan manifest is unsigned — a full rewrite (payload + chain + manifest) verifies PASS; that needs a signing key or an off-site anchor |
| 5 | Complete authorization model | **PARTIAL** | `116-collector-authority.md`: six questions × eleven collector planes, generated from the code, with two **executed probes** (CIDR and loopback refused 422; a second collection refused `BudgetExhausted`) | the matrix grades **0 planes PROVEN, 1 PARTIAL, 10 GAP**: permission, revision and window are not enforced uniformly per family |
| 6 | Performance at bank scale | **PARTIAL** (measured this pass) | `114-scale-qualification.md`: 100k assets / 1M facts measured; 479 assets/s to the 20k request cap; five of seven reads under 1 s at 100k/1M | ingest is capped at 20,000 assets per request, slicing an estate retires the earlier slices, and the observation summary still takes 1.2 s at 1M facts |
| 7 | Observability | **PASS** (re-drilled this pass) | `117-observability-coverage.md`: **10 pass / 0 partial / 0 fail** over ten surfaces, 46 series from `/metrics`, 2 alert groups / 15 rules, and the three former gaps executed: `/healthz/workers`, an OTLP span export watched against a real sink, and a notification delivered from a rule through Alertmanager's config into a counted series | no Prometheus or Alertmanager process ran here: evaluation, grouping and retries are the bank's, and log shipping to a SIEM stays a deployment question |
| 8 | Frontend production hardening | **PASS, one row partial** (re-audited this pass) | `118-frontend-hardening.md`: **8 pass / 1 partial / 0 fail** across nine behaviours, negative control strips the console and every PASS disappears | typing, not reach, is what is left: 141 typed call sites against 329 `Record<string, unknown>` returns; 604 endpoints have no console caller by design |

Each blocker is taken in turn below: what is proven, what is not, and the one
increment that would move its grade.

---

## 1. End-to-end production qualification — **PARTIAL** (five families added this pass)

**Proven.** Every one of the **1,255** operations is executed against uvicorn on
a migrated PostgreSQL with **0 × 5xx** and 0 transport failures (guide 100,
check 8), and **581** mutation-safe writes are executed with synthesised,
schema-valid bodies (check 10). The collector register (guide 105) lists **20/20
families with code**, 14 of them production adapters.

That was, as the review said, a set of component claims. This pass adds the
composition: `scripts/golden_path.py`, regenerating `113-golden-path.{json,md}`,
walks one payload per family through **seven hops** —

| Hop | What is asserted |
|---|---|
| `collect` | the collector's own output: asset count, evidence count, every evidence record naming an asset it emitted |
| `api` | `run_discovery` persists a run and the graph holds **exactly** the assets and evidence records the collector sent, plus each family's "must not become OBSERVED" rule |
| `evidence` | rows are content-addressed, distinct, non-empty, carry facts, and the collector's targets resolve to catalogue identities one-for-one |
| `db` | catalogue asset rows equal the collector's count; the family's planted fact is `CURRENT` in the observation store |
| `twin` | the catalogue lists the assets, each with detail, and the twin's history carries the family's fact type |
| `bom` | the family's BOM contains a component matching the planted identity, and all six BOMs share one projection id |
| `ui` | the console has a client function, a caller and a rendered test for each endpoint the earlier hops read |

**Result: 5 / 5 families, 35 / 35 hops**, for runtime, static, network TLS, PKI
and cloud. The collector code is real in every row — `collect_runtime` runs the
agent's process/library/endpoint collector against a `/proc` fixture,
`collect_cloud` runs against an injected AWS control plane, and the other three
run the API's `collect_static` / `collect_network` / `collect_pki` over rows
written in the scanners' own payload shape.

The suite that guards it (`scripts/tests/test_golden_path.py`, 21 tests) is half
negative controls, because a path that cannot fail proves nothing: dropping one
asset, promising four assets, replacing the collector with an empty one, and
removing the planted identity from the BOM are each asserted to turn the family
red. `SKIPPED` is not a pass — an empty collector fails the family even though
six hops were never reached.

**A defect the path found, reported not hidden.** Both static-code assets reach
the catalogue named by a raw UUID (`bcd8a12f-…`) while their location is
`src/pay/Sign.java`. Identity resolution is unaffected — the BOM component and
the evidence row are correct — but a reader of the Twin or the console sees a
row identifier where an application name belongs. `113-golden-path.md` lists it
under "Defects this path exposes".

**Not proven — the gap that keeps this open.** Five families are not twenty. The
inputs are fixtures rather than a bank's network: no live TLS handshake, no
injected agent on a real host, no real AWS account. Each family runs on its own
empty database, so cross-plane identity merging, conflict resolution and change
detection are still covered only by their own suites, not by this path. The UI
hop proves a caller and a rendered test exist for the endpoints — it does not
render this payload in a browser. And the path runs on SQLite in-memory, so it
proves composition, not production persistence.

**What closes it.** The remaining 15 collector families on the same harness
(kubernetes, cmdb, kms, hsm, hardware, vendor, the passive and watch planes),
then the same path once against a real deployment: live scanner, real agent,
PostgreSQL, and the console reading the run it just triggered.

## 2. Worker / job architecture — **PARTIAL** (retry added this pass)

**Proven** (guide 111, nine properties, each by an executed drill):

| Property | Observed |
|---|---|
| job queue | one claim, job moves under a lease, second pop gets nothing, ack releases |
| worker | peak concurrency = `max_workers`; a raising handler is reported `False`, slot released, and the failure hook runs |
| retry | lost job requeued with `attempts=1`; **transient failure scheduled with backoff and promoted when due**; `ValueError`, an exhausted budget and a controlled job all dead-letter or refuse |
| timeout | lease expiry recovers; RUNNING row past 90 m → `FAILED`; expired deadline → `ExecutionDenied` at the next checkpoint |
| cancellation | cancelled row denied at the next checkpoint; the same call on a RUNNING row gets past it |
| idempotency | outbox publishes once; duplicate row refused by unique key; duplicate delivery refused at SQL claim |
| dead-letter | past the retry budget → dead-letter with a reason, queue empty |
| recovery | killed consumer's job requeued and completed by the next consumer |
| concurrency | `max_workers=1, queue_limit=1` → third submit blocks until a slot frees |

**What changed this pass: retry-after-failure.** Previously a handler that
raised was logged, reported `False` and **acked** — so a connection reset and a
malformed payload had the same outcome, one lost observation. `retry_policy.py`
now classifies the failure and schedules the retry:

- **Transient** (`ConnectionError`, `TimeoutError`, `BlockingIOError`, and
  SQLAlchemy `OperationalError`/`InterfaceError` *except* syntax/undefined-column
  errors) → exponential backoff with jitter, capped, re-published to a Redis
  sorted set scored by due time and promoted by the maintenance sweep.
- **Permanent** (`ValueError`, `KeyError`, `TypeError`, `PermissionError`,
  `FileNotFoundError`, …) → dead-lettered immediately. A retry would fail
  identically three times and only delay the operator finding out.
- **Unrecognised** → terminal by default. Retrying something we do not
  understand multiplies an incident instead of reporting it.
- **Controlled execution → never retried here.** Those attempts hold an
  approval, a lease and a fence; `decide(controlled=True)` refuses and says why,
  because re-queuing would bypass the operator reconciliation that exists for
  exactly that case.

Two details that keep the retry honest rather than merely present:

- **A reaper cannot republish a job that is only waiting out a backoff.**
  `queued_job_ids()` includes the retry set; otherwise the DB sweep would see a
  delayed job as lost and publish a second copy — one job becoming two.
- **The retry carries the original payload string**, not a reconstruction, so a
  field this worker does not read is not silently dropped on the way back.

**Still open.** Cancellation remains a checkpoint boundary: a stage already
running finishes, and a stage that never returns is not interrupted. Concurrency
is bounded per process, not across the cluster. Nothing here ran against a real
Redis restart or a backlog of thousands — the drills use fakeredis, and a retry
can wait up to one maintenance interval past its backoff.

**What closes it.** A cooperative cancel token checked inside long stages, a
cluster-wide admission budget, and one backlog run against a real Redis.

## 3. PostgreSQL production qualification — **PARTIAL** (server drills executed this pass)

**Proven.** `scripts/pg_qualification.py` regenerates
`115-postgres-qualification.{json,md}` against this checkout, and this pass it ran
against a **real PostgreSQL 16.2** rather than SQLite:
**11 PASS · 1 PARTIAL · 0 FAIL · 1 UNPROVEN**.

| Property | Verdict | Measured |
|---|---|---|
| `migration_chain` | **PASS** | **130** revisions to `0130`, upgrade 5.5 s, full downgrade/upgrade round trip 0.25 s, 157 tables |
| `index_parity` | **PASS** | **495** indexes checked, **0** missing |
| `migration_at_scale` | **PASS** | 200,000 rows, index build 0.13 s, indexed read **26.9 ms → 0.3 ms** |
| `transaction_boundaries` | **PASS** | 50 writes probed, **0** outside an explicit boundary |
| `pooling` | **PASS** | QueuePool 10 + 20 overflow, pre-ping on, a live session reports `statement_timeout = 30s` and a **31 s query is cancelled** |
| `locking` | **PASS** | 11 `with_for_update` sites, 32 optimistic version checks (read, not raced) |
| `migration_lock_safety` | PARTIAL | 239 non-concurrent `CREATE INDEX` builds still take an exclusive lock at bank volume |
| `retention` | **PASS (executed)** | a 60-day window archived **11 rows** to NDJSON+sha256, dropped **4 whole months** as partitions, pruned 3 rows individually; 2 current facts and the recent history survived, and the surviving asset's history still answers |
| `partitioning` | **PASS (executed)** | `estate_observations` is range-partitioned by `last_seen_at` month (migration `0130`); a month-scoped read scans **1** of 19 partitions; dropping a month took **0.003 s** and removed exactly that month's rows |
| `concurrent_writes` | **PASS (executed)** | two sessions read version 0 and both wrote: **one row count 1, one 0**, final version 1; two row locks taken in a fixed order completed, opposite orders was **aborted by the deadlock detector** |
| `backup_restore` | **PASS (executed)** | `pg_dump` (645 KB) → `pg_restore` into a fresh database → **176 tables compared, 0 mismatches** |
| `corruption_recovery` | **PASS (executed)** | a writer killed mid-transaction left **0** rows; `pg_ctl -m immediate` (a crash) → restart replayed the log, **14 rows before and after**, every table still readable |
| `ha_failover` | UNPROVEN | one server is one node: no standby, no promotion, **RPO/RTO unmeasured** |

**Retention and partitioning existed as findings, not as absences, after this
pass.** `db/retention.py` prunes only `HISTORICAL` observations and `STALE`
evidence, refuses under a legal hold, refuses a window under 30 days without
`force`, holds back evidence a surviving fact still points at, and **archives to
NDJSON with a sha256 manifest before the first delete**. `db/partitions.py` plus
migration `0130` convert `estate_observations` into a monthly range-partitioned
table, so the sweep drops a month instead of deleting it row by row — with the
costs stated in the migration: the unique index has to carry the partition key,
`last_seen_at` becomes NOT NULL, and a month with no partition rejects the
insert rather than silently accumulating in a DEFAULT.

**Found while measuring — a real defect, now fixed.** Index parity was failing on
one index. The missing index was `uq_fact_identity`, an *expression* index on
`cryptographic_facts` created by migration `0087`:
`(algorithm, coalesce(tenant_id,''), (tenant_id IS NULL), coalesce(purpose,''), coalesce(file_path,''), coalesce(key_size,0), (key_size IS NULL), coalesce(mode,''))`.
Migration `0123` set NOT NULL by rebuilding the table in batch mode; on SQLite a
batch rebuild reflects the table and **drops expression indexes**, because
reflection cannot reproduce them. PostgreSQL uses in-place `ALTER COLUMN` and
kept the index — so the defect existed only on SQLite, which is every test's
schema, and it was invisible to column-based inspection because SQLite reports
NULL column names for an expression index. `0127_restore_fact_identity_index.py`
recreates it only when absent, and
`services/database/tests/unit/test_fact_identity_index_migration.py` holds it:
the index is present at head, **absent at `0126`** (the negative control that
proves the defect was real), duplicate identities are rejected, NULL and `''`
stay distinguishable by design, and the migration is re-runnable.

**Not proven.** Failover is unmeasured: the sandbox can now start one PostgreSQL
16.2 instance, which is one node, and the drill refuses to pretend otherwise.
Concurrent index builds are still the deployment risk they were. Every drill
ran at tens or hundreds of rows: mechanisms are proven, bank-scale cost is not.
This row stays **PARTIAL**, not PASS.

**What closes it.** A standby pair with a measured promotion, `CREATE INDEX
CONCURRENTLY` on the builds that touch a populated table, and one run of these
drills against the deployment's own cluster with the output attached.

## 4. Evidence durability — **PARTIAL** (moved this pass)

**Proven.** Evidence rows carry `content_hash`, `chain_position`, `chain_hash`
and `previous_hash`; the chain is computed at ingest and verified at chain
creation (`evidence/core/pipeline.py`), at evidence-pack export
(`evidence/pack/evidence_pack.py`) and on datalake and stream reads. Duplicate
content is collapsed **before** positions are assigned, so positions stay
gapless and the chain is verifiable from genesis — the comment in the pipeline
explains why the obvious alternative (a unique index) would abort a load
mid-chain.

**Proven by attack, now** (guide 112, `scripts/evidence_integrity_drill.py`).
Nine tampering attacks against a real stored scan, each applied to a fresh
database and graded by execution:

| Attack | Verifier | Verdict |
|---|---|---|
| control — nothing altered | PASS | CONTROL_OK |
| payload tamper (body edited, hashes untouched) | FAIL | DETECTED |
| content hash rewritten to match a tampered body | FAIL | DETECTED |
| chain link rewritten in place | FAIL | DETECTED |
| record deleted from the middle | FAIL | DETECTED |
| **last record deleted** | FAIL | DETECTED |
| two records reordered | FAIL | DETECTED |
| forged record appended with a consistent link | FAIL | DETECTED |
| manifest anchor removed | UNVERIFIABLE | DETECTED |
| tail deleted **and the manifest rewritten** | PASS | UNDETECTABLE by design |

Two details from that table are the reason it was worth building:

- **Deleting the tail is caught by the manifest, not the chain.** The surviving
  prefix still recomputes correctly, so a chain-only verifier would pass it; the
  scan manifest (a hash over the record ids) is what notices. The drill asserts
  both facts, so the test cannot be satisfied by the wrong mechanism.
- **The manifest is unsigned, so an attacker who can rewrite it wins.** That row
  is graded `UNDETECTABLE` and listed in the report's limits, not quietly
  dropped: the missing control is a signature (or an off-site copy of the
  anchor), and until it exists "tamper-proof" is a claim this build cannot make.

**Proven by execution: the Twin now refuses tampered evidence.** Verification
existed at ingest, export, audit, rescan and host-evidence, but the twin
projected evidence rows into its snapshot **without checking them** — the exact
path from evidence corruption to Twin corruption. `_evidence_integrity` in
`api/routers/digital_twin.py` now verifies each scan behind the snapshot with
the same `verify_stored_scan` the export uses, bounded (200 scans per read),
and reports `PASS` / `PARTIAL` / `FAIL` / `UNVERIFIED` with the failing scan ids
in the payload. Three of the four consumers are enforcement points and all
three reject a payload tamper; the fourth (`build_evidence_pack`) ships the
stored commitments and is a transport, not a verifier.

**Still open.** The unsigned anchor (above). The pack is not an enforcement
point by design. The store is SQLite written by the harness, so PostgreSQL
constraint behaviour under the same attacks is not shown. And nothing here
covers a reader outside these four paths.

**What closes it.** Sign the scan manifest with a key the API does not hold at
write time (an HSM-backed or governance-key signature, verified on read), and
keep an off-site copy of the anchor so a rewrite of the scans table is
detectable. That moves the last row from `UNDETECTABLE` to `DETECTED`.

## 5. Complete authorization model — **PARTIAL**

**Proven.** All **1,225** served operations are classified by the authority their
dependency closure demands (guide 101): **306** role, **71** permission, **12**
tenant-role, **836** session-only, with every session-only write carrying a
policy reason (102). For scan execution the controlled-execution path answers the
questions **in data**: pinned authority, target, revision, window, budget and
permission, re-verified inside the running job.

**Built and probed per collector, this pass.** The first pass of
`scripts/collector_authority.py` graded eleven collector planes × six questions
and found **0 PROVEN, 1 PARTIAL, 10 GAP**: two questions were executed, the rest
were a citation of shared code a new adapter could decline to import. That was a
build item, not a fix, and this pass built it:

- **`services/api/api/security/collector_authority.py`** answers all six
  questions in one function, `evaluate()`. Each plane declares a `PlaneSpec` in
  code — entry point, the permission it needs, the shape of target it accepts,
  and the defaults for its window and budget — so a new adapter cannot inherit a
  different subset of controls.
- **`collector_authorities`** (migration `0131`) is the approval: one row per
  plane with an owner, an expiry, a pinned revision and a rolling-window budget.
  A plane with no row is **refused** (`NO_APPROVAL`), never defaulted — an
  approval nobody signed is not an approval.
- **`/api/v1/collectors/authority`** serves the matrix;
  `POST /collectors/authority/{plane}` approves (bumping the revision, which is
  what makes an older one stale); `POST .../revoke` withdraws it and keeps the
  row; `POST /collectors/authorize` returns the decision with all six answers and
  a named code for the question that failed.
- **`scripts/authorize_collector_plane.py`** is the operator's deliberate act:
  approving planes with a named approver and an expiry, dry-run first.

The drill now **probes every cell through that route** — a request that had to be
refused for that question, and one that had to be allowed:

| Plane | WHO | WHAT | WHICH revision | WHEN | HOW LONG | PERMISSION | Verdict |
|---|---|---|---|---|---|---|---|
| all eleven (`NETWORK` … `VENDOR`) | **P** | **P** | **P** | **P** | **P** | **P** | **PROVEN** |

**11 planes PROVEN · 0 PARTIAL · 0 GAP · 66 of 66 cells probed.** The refusals,
each observed rather than assumed: `401` with no session; `PERMISSION_DENIED` for
a principal who may write but holds no permission the plane accepts;
`TARGET_REFUSED` for `*`, `0.0.0.0/0` and `10.0.0.0/8` (the last one parsed as a
perfectly good `owner/repository` pair until the validator learned that an
address is never a target); `STALE_REVISION` for a stale or unnamed revision;
`OUTSIDE_WINDOW` for an expired approval; `EXHAUSTED` when the budget is spent.

**The negative control.** With `evaluate()` replaced by a function that allows
everything, **11 of 66 cells** still report PROBED and every one of them is
`who` — it is answered by the session gate before the authority is consulted.
The matrix is measuring the gate, not the drill's optimism.

**Not proven, and named in the report.** Each plane's *collector* still reaches
its data through `api.estate_discovery._collect()`, which does not yet call the
gate: the authority is a checkpoint in front of the door rather than in the
doorframe. That is one call site, with the estate job's principal, roles and
descriptor revision to plumb through it — and until it exists a bank should read
the matrix as "the authority exists and refuses" rather than "the collector obeys
it". Approvals are also platform-level in this pass; the per-estate column is
supported and untested. 836 operations still hold nothing beyond a session.

**What closes the rest.** Wire `_collect()` to `evaluate()` and delete the
per-plane admission paths that duplicate it, then re-run this drill with the
collector handlers in the loop instead of the route.

## 6. Performance at bank scale — **PARTIAL** (measured this pass)

**Proven — measured, not extrapolated.** `scripts/scale_qualification.py`
regenerates `114-scale-qualification.{json,md}`: a hundred thousand assets and a
million facts, measured on this machine, 2 pass · 3 fail · 1 unproven.

| Property | Verdict | What was measured |
|---|---|---|
| ingest ceiling | **FAIL** | one discovery request carries at most **20,000 assets** (and 100,000 evidence records); 100k is refused at the model with a 422 before collection runs |
| ingest throughput | **PASS** | 479 assets/s at 20k (2.09 ms/asset, 43.8 s), peak RSS **1.19 GB**; a linear projection puts 100k at **3.5 min** |
| read paths at 100k/1M | **FAIL** | catalogue page 27 ms, asset detail 26 ms, history 2.6 ms, why 5 ms, evidence 1.5 ms, catalogue summary 27 ms — and observation summary **1.2 s**, over the 1 s budget |
| continuous ingestion | **PASS** | four observations of a 2,000-asset estate: 1.7× the first round's cost, exactly 2,000 new fact rows per round, the CURRENT set flat |
| slicing a capped estate | **FAIL** | two 10,000-asset slices leave 10,000 **ACTIVE** and 10,000 **STALE**: the second slice's graph does not contain the first |
| BOM projection at 100k | **UNPROVEN** | no graph of that size can be built through the API, so the projection is measured only at the cap |

**Two things were fixed because the drill found them.** At a million facts the
per-asset reads ran linear in the estate — `history` 1.53 s, `why` 1.42 s —
because the planner drove the single-column tenant index and filtered afterwards.
A composite `(tenant_id, asset_id)` index (migration 0126) took them to **2.6 ms
and 5 ms**; the drill measures the same reads with the index dropped (182 ms) so
the claim is a measurement rather than a comment. `estate_observations.summary`
aggregated a million ORM rows in Python (**21.6 s**); it now aggregates in SQL
(**1.2 s** — better, still over budget).

**Not proven — the gap that keeps this open.** First, the ingest path cannot
*reach* bank scale: 20,000 assets per request is the ceiling, and the estate-wide
graph means slicing is not a workaround — it retires whichever slice came first.
Second, **relationships** are not modelled in this drill at all: the review asked
for millions of edges, and the synthetic estate has none, so the edge table's
behaviour at 5M rows is unmeasured. Third, the observation summary is still over
budget at 1M facts, and it is the console's first request. Fourth, this is
SQLite on one machine: no PostgreSQL, no concurrent writers, no pool. Fifth, the
synthetic estate is regular — a bank has a long tail (one asset with 40k edges)
that this drill does not model.

**A defect the drill found.** Every round of continuous ingestion reports
`verdict: NO_CHANGE` while listing 50 `ASSET_CHANGED` claims and the headline
"the two observations are identical": the verdict comes from the BOM and
coverage comparison, the claims from the twin's asset comparison. A metadata-only
movement is therefore listed and denied in the same response. Reported in the
artifact; not fixed here.

**What closes it.** A streaming or partitioned ingest that does not rebuild the
estate from one payload (or an explicit per-slice merge that does not stale the
others), the same drill with 5M relationships, the summary read brought under
budget at 1M facts, and one run of this drill against PostgreSQL with a
concurrent writer.

## 7. Observability — **PASS** (re-drilled this pass)

**Proven.** `scripts/observability_coverage.py` regenerates
`117-observability-coverage.{json,md}`: **7 PASS · 3 PARTIAL · 0 FAIL** over
eleven surfaces — collector, queue, database, evidence, agent, coverage,
health surfaces, traces, logs, alert rules — with **45 series** scraped from
`/metrics` on a live app.

The metric families the review asked for now exist and are exported:
`cryptoscan_coverage_plane{plane,status}` and
`cryptoscan_coverage_collected_ratio{plane}` for coverage health,
`cryptoscan_coverage_planes_unknown` so an unread plane is counted rather than
omitted; job lifecycle (`_job_lifecycle_lines()`: depth, age, dead-letter) for
queue health; evidence-chain and DB health from `/readyz` and the dependency
gauges; agent last-seen for agent health. `infra/monitoring/prometheus/alerts.yml`
carries **2 groups / 15 rules, 10 of them firing alerts**, three added this pass
for the gaps: `CryptoscanCoveragePlaneUnknown`, `CryptoscanCoverageCollectedRatioLow`
and `CryptoscanDeadLetterGrowing`. Adding them exposed a weakness in the guard
that checks alert rules: it only knew the metrics the request middleware
registers, so a rule about queue depth or coverage would have been reported as
"dead" even though `/metrics` emits it. The check now also reads the metric names
out of `api/routers/metrics.py`, which is where they are written.

**The three PARTIALs, closed and executed.** Each was a control that existed as a
claim; each is now driven and its answer read back:

- **`health_surfaces`** — `GET /healthz/workers` is the worker probe the console
  had (`/health/worker-fleet`) behind a session an orchestrator cannot present. It
  answers the one question liveness and readiness do not: *is anything consuming?*
  The drill calls it twice: with a job waiting and no drain evidence it answers
  **503 Degraded** and names the condition; with a completion observed it answers
  **200 Operational**. `/healthz` and `/readyz` answer 200 throughout, so the three
  probes are shown to be three different questions.
- **`traces`** — the OTLP/HTTP exporter that already existed had never been
  executed. The drill stands up a real socket sink, points a `TraceStore` at it,
  finishes a span, and reads back **one notification** whose `traceId`/`spanId` are
  the span's own, with start/end nanos, `http.route` as an attribute and
  `service.name` in the resource. A second store with no endpoint finishes a span
  and spawns **no exporter thread**: "export is optional" is only true if the
  unconfigured path does nothing.
- **`alert_rules`** — `infra/monitoring/alertmanager/alertmanager.yml` ships a
  routing tree, two receivers, two inhibit rules and a webhook to
  `POST /api/v1/ops/alerts/alertmanager`, and `prometheus.yml` now carries the
  `alerting:` stanza instead of a comment. The drill takes **a rule that exists**
  (`CryptoscanApiDown`, critical, 2m), builds the webhook-v4 notification, posts it
  to the URL its own config names, gets **200 with 1 alert accepted**, and finds
  `cryptoscan_alertmanager_notifications_total{alertname="CryptoscanApiDown",
  severity="critical",status="firing"} 1` in the next `/metrics` scrape. A
  malformed notification is refused 422 rather than silently counted.

The receiver is authenticated as an infrastructure principal
(`ALERTMANAGER_WEBHOOK_TOKEN`, 32+ characters, required at production start),
because a pager has no cookie jar and a rule that fires must not be refused with
401. Delivery to a human stays the bank's Alertmanager configuration; what the
platform now proves is that it was told, and that a receiver which goes quiet is a
series that stops moving.

**Not proven.** No Prometheus scraped these rules and no Alertmanager process ran
in this drill: evaluation, grouping, inhibition and retry are their layers, and
what is proven is the delivery half. The span payload went to a local sink, not an
APM collector. Log shipping is graded READ: structured logging and redaction
exist in the checkout, and what leaves the host is a deployment question.

## 8. Frontend production hardening — **PASS, one row partial** (re-audited this pass)

**Proven.** `scripts/frontend_audit.py` regenerates
`118-frontend-hardening.{json,md}`: nine behaviours read from `frontend/src`,
graded **8 PASS · 1 PARTIAL · 0 FAIL** —

| Behaviour | Verdict | Measured |
|---|---|---|
| API contract coverage | PARTIAL | **537 of 1,147** endpoints reachable (46.8%), **141** typed call sites, **0** console calls with no route |
| error handling | PASS | 415 failure branches; **0** readers that cannot surface a failure |
| empty states | PASS | 171 explained empty states (109 as `role="status"`), 3 asserted by tests |
| large graphs / lists | PASS | 40 collection cuts in 23 files, **0 silent**, 60 pagination sites |
| realtime | PASS | stream + `Last-Event-ID` resume + reconnect, with a jsdom test |
| authorization-aware views | PASS | 68 gating sites across 5 surfaces, 125 refusal-state strings |
| auditability | PASS | **`/audit` is a page**: the hash-chained trail with its chain verdict, 26 audit API calls in 8 files |
| degraded coverage | PASS | 482 coverage/UNKNOWN mentions — "nothing there" and "nothing observed" are different states |
| page test coverage | PASS | **65 of 102** pages have a rendered test (63.7%) |

**Defects found and fixed, not just measured.**

- `useApi` leaked a thrown request: the hook left `running` true for ever and
  kept the previous data on screen, so a panel showed a stale estate with no
  indication the read had failed. It now returns
  `{source: "offline", error: "REQUEST_FAILED", detail}` and always clears
  `running`; `apiUi.test.tsx` pins all three behaviours.
- **29 tables were cut to a fixed row count with no caption**, which reads as the
  whole estate. `Table` now takes `total` and states "showing the first N of M
  rows"; every truncated table passes it. The remaining list/graph cuts
  (estate panel, dependency graph, blast-radius lists, certificate bars) now say
  what they left out.
- The page smoke test was **red at `039d1403`** and had been for a while: the
  maturity register's prose contained a raw API path
  (`GET /estate/evidence/twin/simulation-scenarios`), which the console's own
  "no raw API path on a screen" assertion catches. The prose was reworded and
  `lib/maturity.test.ts` now asserts the property, so a regenerated register
  cannot reintroduce the leak.
- **`KeyReconciliationPanel` threw on a live answer it could not read.** It called
  `r.data.scans.filter(...)` on whatever came back, so a payload without `scans`
  raised an unhandled rejection and left the panel on *Loading…* — the screen read
  as "still checking" when the honest state was "this panel cannot tell". It now
  has an explicit unreadable state, and
  `components/KeyReconciliationPanel.test.tsx` pins all three states.

**Built this pass — the audit trail's own surface.**

`frontend/src/pages/Audit.tsx` replaces the `/audit` redirect. The platform writes
a hash-chained audit record and guide 112 proved it is tamper-evident, but the
console could only read it from inside the evidence screen. The page shows
timestamp, actor, action, target, outcome and source address, filters **through the
API** (a filtered history is a smaller history, not a partial one), pages 50 rows
at a time and says so, and carries the chain verdict beside the table in three
honest states: **verified** (quoting the server's own `checked`/`entry_count`),
**TAMPERED** (with `break_at_sequence` and the reason), and **CHAIN NOT VERIFIED**
for an unanswered or verdict-less verify call — never a green badge for a chain
nobody read. A trail that could not be read says so instead of rendering an empty
table: "no events" and "could not read the events" are opposite claims on an audit
screen. `Audit.test.tsx` covers all of them, plus the filters leaving the browser
as query parameters.

**Fifteen pages with no rendered test now have one** — Agility, Alerts,
AssuranceCoverage, AssuranceQualification, AssuranceRecords, AssuranceSampling,
AssuranceTrace, Automation, Catalog, Cloud, CryptoAssets, CryptoChanges,
Executive, Hardware and Identity — through `src/test/pageSmoke.tsx`, which mounts a
page against a live-but-empty API and fails if it throws, renders nothing, or puts
`NaN`/`undefined`/`Infinity` on a bank screen. That is a floor, not a claim about
correctness, and it paid for itself immediately by finding the panel defect above.

**The `error_handling` row no longer counts the hook's own module as a silent
reader.** `lib/apiUi.tsx` *is* the failure branch — the `catch` that builds
`{error, detail}` — and the row was flagging it because it looked for render sites.
`lib/apiUi.error.test.tsx` now proves the behaviour instead of the row asserting its
absence: a throwing reader becomes `REQUEST_FAILED` with the message, clears
`running`, and invents no data.

**The negative control.** The same graders run against a copy of the console with
its failure branches, empty-state copy, gating, pagination, resume, audit trail and
tests stripped: **PASS 0 · PARTIAL 5 · FAIL 4**, and every row that claimed a
behaviour stops claiming it — including auditability, which the control used to
leave PASSing because the trail was never part of what got stripped. An audit that
cannot fail is decoration, so
`scripts/tests/test_frontend_hardening_artifact.py` asserts that floor and the
trail's surface.

**Not proven, and the one partial named.** Typing is the real gap in the contract
row: **141 typed call sites against 329 `Record<string, unknown>` returns**, so most
payloads the console reads are an unchecked claim — reach (46.8%) is a product
decision, not a defect, and the uncovered half is CLI and drill traffic. 604
endpoints still have no console caller. 37 pages still have no rendered test, and
the fifteen added here are smoke-level rather than behavioural. No browser was
involved, so DOM cost at 100k nodes is unmeasured; a failure branch that exists but
never triggers still counts as present.

**What closes it.** Typing the remaining 329 call sites from the OpenAPI schema,
behavioural tests for the 37 uncovered pages, a browser-level run at 100k nodes,
and an explicit "API-only" register for the 604 uncovered endpoints.

## The order I would take them

1. ~~**Evidence durability (#4)**~~ — **done this pass** (guide 112): twin
   enforcement added, nine attacks executed, the unsigned-manifest boundary
   stated rather than hidden. The residual is one signature, not an audit.
2. ~~**Worker retry (#2)**~~ — **done this pass**: transient failures are now
   retried with backoff and jitter, permanent ones are not, and controlled jobs
   are excluded by name. Remaining in #2: cooperative cancellation inside a
   stage, cluster-wide admission, and a real-Redis backlog run.
3. ~~**End-to-end per family (#1), first five families**~~ — **done this pass**
   (guide 113): runtime, static, network TLS, PKI and cloud each walk 7/7 hops
   with counts and identities asserted, and the harness fails when a hop lies.
   Remaining in #1: the other 15 families, and one run against a real
   deployment.
4. ~~**Bank-scale measurement (#6)**~~ — **done this pass** (guide 114): 100k
   assets and 1M facts measured, and it found what the plan predicted — the
   ingest cap, not throughput, is what stops a bank estate. Two reads were fixed
   on the way (composite index, SQL aggregation). Remaining in #6: relationships
   at 5M, a streaming ingest, and a PostgreSQL run with a concurrent writer.
5. ~~**PostgreSQL qualification (#3)**~~ — **done this pass** (guide 115, the
   second pass on it): the SQLite rows plus **four server drills executed on a real
   PostgreSQL 16.2**, retention and monthly partitioning built rather than
   described, and a real dropped-index defect found, repaired by 0127 and pinned
   by five tests. **11 PASS · 1 PARTIAL · 0 FAIL · 1 UNPROVEN**. Remaining in #3:
   failover (a standby pair) and `CREATE INDEX CONCURRENTLY`.
6. ~~**Per-collector authority (#5)**~~ — **done this pass** (guide 116, second
   pass on it): the descriptor per plane exists, the approval is a row with an
   owner and an expiry, the route serves the matrix, and the drill **probes all
   66 cells** — 11 planes PROVEN, 0 GAP. Remaining in #5: wire
   `api.estate_discovery._collect()` to the gate, and delete the per-plane
   admission paths it duplicates.
7. ~~**Observability gaps (#7)**~~ — **done this pass** (guide 117, second pass
   on it): coverage, queue, evidence and agent families exported; the worker
   probe, span export and Alertmanager receiver all built **and executed** —
   10 of 10 surfaces answer, 0 partial. Remaining in #7: nothing in code; a bank
   points the bundled Alertmanager at its own pager.
8. ~~**Frontend audit (#8)**~~ — **done this pass** (guide 118, second pass on
   it): the audit trail is a page with the chain verdict and an honest unverified
   state, fifteen pages gained rendered tests (49% → 63.7%), a panel that hung on
   a payload it could not read was fixed, and the silent-reader row stopped
   flagging the hook that implements the branch. **8 PASS · 1 PARTIAL · 0 FAIL.**
   Remaining in #8: typing the 329 untyped call sites, tests for the 37 pages still
   uncovered, and a browser run at estate scale.

**Still open, and not moved this pass:** the 15 collector families in #1, the
in-stage cancellation, cluster-wide admission and real-Redis backlog in #2, the
5M-relationship run in #6, and the unsigned manifest in #4. Nothing above makes
the branch bank-production-ready; the four artifacts make the distance specific.
