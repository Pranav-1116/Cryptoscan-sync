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
| 3 | PostgreSQL production qualification | **PARTIAL** | 125 migrations at tip, applied and swept on real PG; PITR/backup/failover drills exist as scripts | no partitioning, no 1M-row or concurrent-write measurement, drills not executed here |
| 4 | Evidence durability | **PARTIAL** | guide 112: 8 of 9 tampering attacks detected on a real stored scan; the Twin now verifies before projecting; export/audit/rescan/host-evidence already enforced | the scan manifest is unsigned — a full rewrite (payload + chain + manifest) verifies PASS; that needs a signing key or an off-site anchor |
| 5 | Complete authorization model | **PARTIAL** | 1,225 operations in the authorization register; approvals carry a typed contract | per-collector target authority is not uniform; the five questions are answered by different mechanisms per family |
| 6 | Performance at bank scale | **BLOCKED** | 150 banks / 2,161 assets / 2,782 edges, ingest 0.029 s (108) | 100k assets, 1M observations, millions of relationships, continuous ingestion: not measured |
| 7 | Observability | **PARTIAL** | `/metrics` (dependency, scanner-family, scan-duration), healthz/readyz, Prometheus alerts, Grafana dashboards | no tracing; no evidence-health, coverage-health or agent-health metric; alerts not exercised |
| 8 | Frontend production hardening | **PARTIAL** | 600 of 1,255 endpoints reachable from the console; 96 frontend test files | authorization-aware views, large-graph handling, realtime consistency: not audited at page level |

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
4. **Bank-scale measurement (#6)** — one measured run at 100k/1M/5M; it will find
   the first non-linearity, and that finding is worth more than the table.
5. **PostgreSQL qualification (#3)**, **per-collector authority (#5)**,
   **observability gaps (#7)**, **frontend audit (#8)** — in that order, each
   with the artifact named above.
