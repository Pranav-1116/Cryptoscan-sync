# Executed bounded worker-pool repair — 2026-10-24

**Two long-running correctness gaps repaired: unbounded completed-Future history
and permanently lost admission slots after queued cancellation.** This changes
the existing worker pool, not collectors, APIs, dashboards, services, database
schema, customer deployments or workflows. No production-capacity or bank
qualification follows from this increment.

## What changed and why

The previous pool appended every Future forever. A concurrency semaphore bounded
executing/queued tasks but did not bound this completion history. It also released
slots only inside `_run`; cancelling queued executor work skipped `_run`, losing
that slot permanently. Negative queue limits could create a stalled zero-slot
pool or an unrelated semaphore error.

The pool now owns a locked, bounded set of admitted public futures. Cancelled
public futures retain their slot until an unexposed executor wrapper consumes
the queued entry, without invoking the handler. This avoids both the old permanent
slot leak and a naive cancellation fix that would allow unbounded cancelled
executor tombstones. Completion removes tracking and returns the slot before
normal result/exception callbacks, so nonblocking follow-up submission from a
callback does not deadlock on the completed admission. `wait()` drains the
current admitted snapshot, including cancelled wrappers; shutdown is rechecked
for submitters that were waiting for capacity.

The caller still receives a standard Future, and the existing started-job
counters retain their meaning. Cancellation-before-start is not reported as a
collector success/failure. Local release does not change durable SQL budgets,
UNKNOWN reservations, job cancellation, tenant scope, approvals or isolation.
[Detailed semantics and limitations](../operations/worker-pool-lifecycle.md).

## Final executed checks

| Check | Observed result | Evidence |
|---|---|---|
| Selected product regression, including previous CBOM/evidence/database/API assurance selection, worker units and execution controls/recovery | **2,217 passed**, 9 warnings, 442.26 s, exit 0 | [Transcript](worker-pool-2026-10-24/regression.txt), [JUnit](worker-pool-2026-10-24/regression.xml) |
| Focused pool, new lifecycle, interruption-accounting and worker-lease checks | **38 passed**, 13.82 s, no warnings in summary | [Transcript](worker-pool-2026-10-24/focused.txt), [JUnit](worker-pool-2026-10-24/focused.xml) |
| Historical baseline reproduction, using published `2f9551b0` pool code | **6 expected failures** against the old implementation; not a final gate failure | [Transcript](worker-pool-2026-10-24/baseline.txt), [Runner](worker-pool-2026-10-24/baseline-repro.py) |
| Fresh-process synthetic lifecycle witness | **12,288 jobs**, **12,288 completion callbacks**, **723 intentional synthetic refusals**, peak tracked public futures **102/102**, zero retained after shutdown | [JSON](worker-pool-2026-10-24/lifecycle.json), [Transcript](worker-pool-2026-10-24/lifecycle.txt) |
| Rerun actual API/PostgreSQL/Redis/fresh-worker drill with current pool | **9 checks passed**; PostgreSQL **16.2**, schema **0107**, Redis **8.2.4** | [Result](worker-pool-2026-10-24/dispatch.json), [Transcript](worker-pool-2026-10-24/dispatch.txt) |
| Changed Python Ruff, pip dependency consistency, whitespace | Passed | [Quality](worker-pool-2026-10-24/quality.txt) |
| Owned pool/process/source/runtime cleanup | Pool shutdown completed, owned children/PG stopped, private directories and owned Redis build/archive removed | [Cleanup](worker-pool-2026-10-24/cleanup.json), [Drill cleanup flags](worker-pool-2026-10-24/dispatch.json) |

JUnit totals were parsed and checked: zero failures, errors or skips in both final
runs. These are **selected tests**, not all repository suites or all CI workflows.
No frontend code changed; no frontend/browser rerun is claimed. Test durations
are not comparable scanner latency/performance measurements.

The nine warnings include existing Pydantic/field-shadowing/Starlette warnings,
blocked external socket attempts in an existing failure-path test and pgserver's
runtime-directory warning. A pgserver exit-time log also attempted to write to a
closed stream after the passing summary. That error is retained, not hidden;
test exit was 0 and its owned PG process was confirmed stopped before removing
the known data directory. These warning/helper-logging gaps were not fixed here.

## What the lifecycle witness establishes

One pool is reused for **24 batches of 512 synthetic local jobs**, using two
workers and the unchanged default 100-slot local queue. The observed maximum
active handlers is two; the tracked public-admission budget is 102. All jobs
reach their expected callback/counter outcomes. All **192 sampled Futures** can
be reclaimed after shutdown; batch observations show no growing completion
history. No scanner, database, Redis, tenant or deployment is contacted by this
separate witness.

Nineteen new test cases additionally exercise concurrent producers, queued
cancellation and replacement, cancel/resubmit bounds while a handler is blocked,
result/exception reclamation, mutated snapshots, negative limits, shutdown
races, failing observers, nonblocking callback follow-up
and fresh-process witness validation. The focused run also includes existing
pool/interruption/lease tests. Weak-reference unit checks isolate pool ownership
from pytest's deliberately retained logging tracebacks; this is not a production
logging or authority-gate change.

This is a **bookkeeping/liveness correctness observation, not an RSS cap or
capacity benchmark**. Public and executor futures both exist for admitted work;
caller-retained objects, callbacks, logs, collectors and other buffers can still
consume memory. No sustained scanner throughput, pressure/soak acceptance,
p95/p99 or paired 20% selected-bottleneck improvement was measured or inferred.
The agreed performance targets remain unqualified, including the coordination
overhead of this repair.

## What the real dispatch rerun establishes—and does not

The existing owned local harness creates real Unix-socket PostgreSQL/Redis,
migrates 0107, uses password/session authentication and actual ASGI routes, then
runs unmodified worker entrypoints in fresh OS processes. An **API-created
job—not a seeded completion envelope—produces one development scan and one
verified evidence record despite duplicate Redis delivery**. The normal pool
completion callback acknowledges the transport delivery and services drain.

The same nine-check drill also covers readonly/root/foreign-tenant refusals,
emergency stop after enqueue, real Redis outage leaving the SQL outbox pending,
worker maintenance publication after restart, lease renewal past stopped intake
and a separate transport-only SIGKILL/expiry/redelivery case. These are not
12,288 real scans: the large count belongs only to the synthetic local witness.

Controlled mode validates a durable grant but still refuses the unprovisioned
container profile. There are **zero controlled execution attempts and zero
additional scans**. No preflight, collector, policy or claim double bypasses that
boundary in the actual drill. ASGI TestClient is not a browser or live HTTP
network test. Successful controlled isolation and production TLS/ACL/HA remain
open, not silently upgraded by rerunning development dispatch.

## Cleanup, reproducibility and remaining gaps

Normal harness completion stopped its owned children without forced kill,
stopped PG and removed private source/database/socket/log data. The regression's
known temporary PG directory was removed after its process exited. Owned Redis
source/build/archive were removed after preserving [source and binary hashes](worker-pool-2026-10-24/redis-source.json).
The validation interpreter remains a local development tool. No dependency was
added. [Environment](worker-pool-2026-10-24/environment.txt),
[replay instructions](worker-pool-2026-10-24/README.md) and
[source/artifact SHA256 manifest](worker-pool-2026-10-24/manifest.json) support
inspection, not independent signature or bank acceptance.

**Next open correctness gap:** Redis orphan recovery still removes a processing
payload before republishing it, leaving a crash window. This increment does not
repair or qualify that path as atomic/exactly-once. Also open are successful
controlled isolation with real attempt/checkpoint/artifact receipts, deployed
security/recovery/capacity and the agreed paired performance targets, original45
platform/protocol/runtime/HSM/PKI/PQC and integration work, complete independent
scope, and bank/legal/security/commercial/staffed operating acceptance.

NBOM, CBOM, TechBOM, HBOM, VBOM and SBOM remain distinct evidence surfaces. No
complete six-BOM coverage, historical partial-history clearance, 24/7 staffing,
SLA or bank approval is asserted.
