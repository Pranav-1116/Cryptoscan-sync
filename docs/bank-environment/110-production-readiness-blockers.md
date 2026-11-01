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
| 7 | Observability | **PARTIAL** (drilled this pass) | `117-observability-coverage.md`: **7 pass / 3 partial / 0 fail** over ten surfaces, 45 series from `/metrics`, 2 alert groups / 15 rules (10 firing alerts) | no span export, no worker liveness probe, and **no Alertmanager**: the rules are evaluated-ready but nothing receives them |
| 8 | Frontend production hardening | **PARTIAL** (audited this pass) | `118-frontend-hardening.md`: **5 pass / 4 partial / 0 fail** across nine behaviours, negative control strips the console and every PASS disappears | 537 of 1,141 endpoints reachable (47.1%), 49 of 100 pages have a rendered test, no dedicated audit page |

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

## 3. PostgreSQL production qualification — **PARTIAL** (qualified this pass)

**Proven.** `scripts/pg_qualification.py` regenerates
`115-postgres-qualification.{json,md}` against this checkout:
**5 PASS · 2 PARTIAL · 2 FAIL · 4 UNPROVEN**.

| Property | Verdict | Measured |
|---|---|---|
| `migration_chain` | **PASS** | **127** revisions to `0127`, upgrade 4.55 s, full downgrade/upgrade round trip 0.19 s |
| `index_parity` | **PASS** | **494** indexes checked, **0** missing |
| `migration_at_scale` | **PASS** | 200,000 rows migrated, table build 0.09 s, indexed read **17.1 ms → 0.2 ms** |
| `transaction_boundaries` | **PASS** | 50 writes probed, **0** outside an explicit boundary |
| `locking` | **PASS** | 11 `with_for_update` sites, 32 optimistic version checks |
| `pooling` | PARTIAL | QueuePool 10 + 20 overflow, pre-ping on; no saturation measurement |
| `migration_lock_safety` | PARTIAL | 239 non-concurrent `CREATE INDEX` builds will take an exclusive lock at bank volume |
| `retention` | **FAIL** | no delete path anywhere; 1M facts occupy 645.8 MB and stay |
| `partitioning` | **FAIL** | no `PARTITION BY` in the schema |
| concurrent writes, backup/restore, corruption recovery, HA | UNPROVEN | `SERVER_REQUIRED` — the checkout has no PostgreSQL; a row is never scored as passing because it could not be run |

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

**Not proven.** Retention and partitioning are absent, not partial. The four
`SERVER_REQUIRED` rows — concurrent writers, backup/restore of a real dump,
recovery from a *corrupted* database, and failover — cannot be measured in a
checkout without a server, and are printed as `UNPROVEN` rather than folded into
the average.

**What closes it.** A retention job with a measured delete path, partitioning for
`estate_observations`/`cryptographic_facts`, `CREATE INDEX CONCURRENTLY` on the
239 builds, and the four server drills executed on a host with the output attached.

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

**Proven per collector, this pass.** `scripts/collector_authority.py`
regenerates `116-collector-authority.{json,md}`: eleven collector planes × six
questions (who / what target / which revision / when / how long / permission),
each cell graded `PROBED` (executed here), `CITED` (a mechanism found in the code)
or `ABSENT`. Result: **0 planes PROVEN, 1 PARTIAL, 10 GAP**.

| Plane | Cells (who, target, revision, when, how long, permission) | Verdict |
|---|---|---|
| `NETWORK` | `c P c c P -` | **PARTIAL** |
| `RUNTIME`, `STATIC`, `HARDWARE` | `c c c - - -` / `c c - c - -` / `c c - c - -` | GAP |
| `PKI`, `CLOUD` | `c - - c - c` / `c - - - c -` | GAP |
| `KUBERNETES`, `CMDB`, `KMS`, `HSM`, `VENDOR` | `c - - - - -` | GAP |

The two `P` cells are executed, not read: `checked_hosts()` refuses a CIDR and a
loopback/metadata target with 422 before a socket is opened, and a second
collection against the same scope raises `BudgetExhausted` — including the
no-scope negative control, which must refuse rather than default to unlimited.
The single `-` on the strongest plane is the finding: **network collection is
bounded in target and in time, but the request itself carries no per-collector
permission**; it relies on the session.

**Not proven.** That authority is uniform per family. It is not: who decides is
enforced in different places per plane, revision is pinned only where a policy
revision exists, and five planes have no target check the drill could find at
all. 836 operations still hold nothing beyond a session.

**What closes it.** A per-plane authority descriptor — the same six questions as
a single record attached to the collector catalogue, with a route that returns it
— so a console can show an operator exactly what a collector is allowed to touch
before it is allowed to touch it.

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

## 7. Observability — **PARTIAL** (drilled this pass)

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

**Not proven — the three PARTIALs, named.** `health_surfaces`: there is no worker
liveness probe, so a wedged worker is visible only through job age. `traces`: no
span is exported anywhere; the request path is reconstructible from logs and
metrics, not from a trace. `alert_rules`: the Alertmanager stanza is still
commented out in `prometheus.yml`, so the rules are evaluated-ready but nothing
receives them — the rules have never fired.

**What closes it.** A worker probe on `/readyz`, OpenTelemetry span export on the
collector → API → evidence path, and an Alertmanager receiver so each rule is
fired once and the notification recorded.

## 8. Frontend production hardening — **PARTIAL** (audited this pass)

**Proven.** `scripts/frontend_audit.py` regenerates
`118-frontend-hardening.{json,md}`: nine behaviours read from `frontend/src`,
graded **5 PASS · 4 PARTIAL · 0 FAIL** —

| Behaviour | Verdict | Measured |
|---|---|---|
| API contract coverage | PARTIAL | **537 of 1,141** endpoints reachable (47.1%), **141** typed call sites, **0** console calls with no route |
| error handling | PARTIAL | 407 failure branches; **1** reader that could not surface a failure |
| empty states | PASS | 164 explained empty states (103 as `role="status"`), 3 asserted by tests |
| large graphs / lists | PASS | 40 collection cuts in 23 files, **0 silent**, 56 pagination sites |
| realtime | PASS | stream + `Last-Event-ID` resume + reconnect, with a jsdom test |
| authorization-aware views | PASS | 68 gating sites across 5 surfaces, 125 refusal-state strings |
| auditability | PARTIAL | 18 audit API calls in 6 files, **no dedicated audit page** |
| degraded coverage | PASS | 482 coverage/UNKNOWN mentions — "nothing there" and "nothing observed" are different states |
| page test coverage | PARTIAL | **49 of 100** pages have a rendered test |

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
  "no raw API path on a screen" assertion catches. The prose was reworded; all
  91 page smoke tests pass.

**The negative control.** The same graders run against a copy of the console with
its failure branches, empty-state copy, gating, pagination, resume and tests
stripped: **PASS 0 · PARTIAL 6 · FAIL 3**, and every row that claimed a behaviour
stops claiming it. An audit that cannot fail is decoration.

**Not proven.** 604 endpoints still have no console caller (declared API-only, not
missing by accident); 51 pages have no rendered test; there is no dedicated audit
page; no browser was involved, so DOM cost at 100k nodes is unmeasured; and a
failure branch that exists but never triggers still counts as present.

**What closes it.** Rendered tests for the 51 uncovered pages, an audit/approval
page reading the server's own trail, a browser-level run at 100k nodes, and an
explicit "API-only" register for the 604 uncovered endpoints.

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
5. ~~**PostgreSQL qualification (#3)**~~ — **done this pass** (guide 115): 127
   migrations, index parity 494/0, and a real dropped-index defect found, repaired
   by 0127 and pinned by five tests. Remaining in #3: retention, partitioning, and
   the four server drills.
6. ~~**Per-collector authority (#5)**~~ — **done this pass** (guide 116): the
   matrix exists and it says the honest thing — 0 planes PROVEN, 1 PARTIAL, 10
   GAP. Remaining in #5: one authority descriptor per plane, returned by a route.
7. ~~**Observability gaps (#7)**~~ — **done this pass** (guide 117): coverage,
   queue, evidence and agent families exported, 18 alert rules. Remaining in #7:
   a worker probe, span export, and an Alertmanager receiver.
8. ~~**Frontend audit (#8)**~~ — **done this pass** (guide 118): nine behaviours
   graded, a leaked failure path and 29 uncaptioned tables fixed, a red smoke
   test fixed. Remaining in #8: 51 pages without a rendered test, an audit page,
   and a browser run at estate scale.

**Still open, and not moved this pass:** the 15 collector families in #1, the
in-stage cancellation, cluster-wide admission and real-Redis backlog in #2, the
5M-relationship run in #6, and the unsigned manifest in #4. Nothing above makes
the branch bank-production-ready; the four artifacts make the distance specific.
