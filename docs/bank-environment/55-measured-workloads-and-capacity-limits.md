# 4.3 — Measured workloads, bounded tuning and explicit capacity limits

Engineering increment, 2026-10-21. **No bank capacity/SLO, production retention
limit, RPO/RTO or real-browser endurance acceptance is claimed.** Measurements
below are disposable synthetic local observations, not linear extrapolations.

## Instrumentation actually added

The worker pipeline records bounded stage-transition measurements into the
owning durable job's `progress.performance`, including failure transitions. Read
an exact-owned job through `GET /api/v1/assurance/workloads/jobs/{job_id}`:

- queue wait (`created_at` → `started_at`, or current queued age);
- execution time (`started_at` → `completed_at`, or current running age);
- per-stage monotonic wall time, **process** CPU delta, **process high-water**
  RSS and block-I/O counters;
- SQL cursor query count, total/max latency and bounded first-512 sample p95.

SQL event listeners are installed once per engine; ContextVar isolation prevents
cross-attributing concurrent operations on a shared engine. SQL text and query
parameters are never retained. Failed cursor operations are measured too.
Legacy/uninstrumented jobs report `NOT_INSTRUMENTED_OR_LEGACY`, not zero latency.
Measurements are job metadata in the same owner/residency boundary, not an
unapproved external metrics destination.

**Interpretation limits matter:** process counters include concurrent work;
RSS is not an independently reset per-stage peak; block counts are not bytes or
retained filesystem allocation; subprocess/container CPU/heap are not included;
cursor time excludes pool wait, ORM materialization and independent PostgreSQL
server attribution. Queries after the final stage snapshot are not retroactively
included. Use container/cgroup/DB tools in a real site workload to complete these
measurements. Instrumentation itself is bounded (32 stages, 512 query samples).

## Repeatable disposable SQL workload

```bash
python scripts/operator_workload.py --estates 3 --rows 2000 --iterations 60 \
  --out "$NEW_PRIVATE_REPORT_PATH"
```

This command creates and removes a temporary SQLite database. It does not read
production connection settings, acquire source, launch parsers, mint credentials
or contact providers. It seeds **3 synthetic estates × 2,000 tasks and 2,000
jobs (90% completed, 10% attention states)**, then executes the real operator read model on pages of 25 at offsets
0/25/50/75, before and after adding the two estate/page indexes. Reports retain
shape, runtime, query plans, process/resource samples, exact query counts,
response sizes and storage allocation. Output must be a new file and is mode
0600. Data is explicitly synthetic.

Two final sequential repeat runs in this sandbox (same mixed dataset and tool):

| Measurement | Run 1 before | Run 1 after | Run 2 before | Run 2 after |
|---|---:|---:|---:|---:|
| Read-model requests | 60 | 60 | 60 | 60 |
| Errors | 0 | 0 | 0 | 0 |
| Median wall time | 6.642 ms | 5.084 ms | 6.530 ms | 5.191 ms |
| p95 wall time | 7.544 ms | 5.690 ms | 10.027 ms | 5.534 ms |
| Total SQL cursor time | 88.584 ms | 24.277 ms | 95.288 ms | 24.592 ms |

Both actual-shape task/job query plans use the corresponding estate/page index
(the job plan includes its attention-status filter). These measurements support
adding `tenant_id, created_at, id` indexes in migration **0104** for these bounded
reads. They do not establish production capacity. Earlier sequential trials
running alongside the test suites also reduced SQL cursor time but had variable
wall time: one median increased from 6.525 to 8.483 ms while cursor time fell
from 122.890 to 23.054 ms. **No universal wall-clock speedup is claimed.**

The phases run sequentially on one host; warmup/order/contention/noise affect
wall time. Repeat on the deployment's PostgreSQL engine and actual workload.
Nothing here justifies removing input/scan caps, promising concurrent scanner
throughput or linearly extrapolating to bank scale.

The report distinguishes **shared physical SQLite file growth** from **per-estate
logical finding JSON bytes**. The latter excludes row/index/WAL/evidence/blob
allocation and is not physical billing/storage attribution. Retention deletion
is explicitly not exercised. The two small synthetic measurement reports are retained (not the generated
databases); see the [engineering record](../readiness-evidence/operator-engineering-2026-10-21.md)
for its hash and exact test evidence.

## Read-only HTTP workload for an approved site

```bash
python scripts/operator_http_workload.py --base-url "$APPROVED_API_ORIGIN" \
  --tenant-id "$APPROVED_DISPOSABLE_ESTATE" --seconds 60 --workers 2 \
  --token-env CRYPTOSCAN_WORKLOAD_TOKEN --out "$NEW_PRIVATE_HTTP_REPORT"
```

Use an already-authorized credential supplied through the protected environment,
never in CLI arguments/chat. This runner only GETs operator decisions and checks
the returned estate. It mints no keys, mutates no jobs and follows no redirects.
It bounds concurrency, read size, timeouts, offered load and samples, and records
status counts/HTTP 429s/errors/latency/response bytes. HTTP is permitted only on
loopback; remote origins require HTTPS. Non-200/throttled responses fail the run.
A 429 here is **API throttling**, not evidence of cloud/vendor provider limits.
Do not run against a bank without explicit operator workload approval.

## Safe tuning choices rather than unsafe result reuse

- Added measured exact-estate page indexes; batched latest assurance reads and a
  single policy binding per inbox avoid per-change policy lookup loops.
- Frontend requests are bounded, cancellable, non-overlapping and suspended while
  hidden. The displayed state is replaced rather than an accumulating event log.
- There is **no shared/persistent evidence-result cache** and no changed-file
  shortcut in controlled collection. Current authority, scope, receipts and
  freshness are reevaluated on every read/scan. Source receipt provenance is
  retained. No cap was removed to claim scale.
- Full SQL reconciliation every poll handles missed events/replay gaps. This is
  deliberate differential/event safety: events are hints, not authoritative
  removals. A future parser cache must bind estate, canonical target, source
  checksum, parser/runtime/config/policy revisions and approval applicability,
  preserve origin receipts, invalidate on gaps/version changes and periodically
  perform full collection. It is **not implemented or silently enabled here**.

## What remains to be measured before capacity acceptance

| Dimension | Available mechanism | Missing external evidence |
|---|---|---|
| Queue wait/execution/stages | Job workload endpoint and bounded worker probes | Actual PostgreSQL/Redis concurrent estate mix and parser service times |
| CPU/memory/disk per stage | Process probes + local SQL file growth | Isolated parser/container/cgroup CPU, peak heap, disk bytes and cleanup under hostile inputs |
| DB latency/storage/retention | Cursor timings and indexed query plans; synthetic logical per-estate growth | Pool wait, PostgreSQL server plans, WAL/index/blob growth, backup amplification, real retention deletion |
| Provider throttling | Existing admitted provider receipts; HTTP runner status counters | Repeatable approved provider workloads, actual Retry-After/backoff and provider-specific quota behavior |
| Replay contention/recovery | Existing `scripts/redis_recovery_evidence.py` durable old-ACK observer and replay gap handling | Real approved contention/fault/restore/rotation tests with old acknowledgements and independent witness |
| Browser behavior | Tenant-race/replay/error tests; 2,880-poll simulated lifecycle test | Real supported-browser 24h+ wall-clock soak, heap/DOM/network profile, visibility/session/rotation/low-bandwidth cycles |

Use a fixture matrix with realistic estate count, evidence density, file sizes,
provider mix, retention periods, browser sessions and fault schedule. Retain
configuration/image hashes, offered/completed work, errors/429s, queue/resource
traces, post-recovery proof and witnessed acceptance. A missing run stays
**NOT_RUN**, never a performance prediction disguised as qualification.
