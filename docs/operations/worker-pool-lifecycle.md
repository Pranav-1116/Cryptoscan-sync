# Bounded long-running worker-pool lifecycle

**2026-10-24 — existing component repair; no new service or scanner.**

The [dispatch increment](worker-dispatch-boundaries.md) fixed Redis publication
fallback and lease renewal while workers drain. It did not bound the pool's
completion history or fix queued-Future cancellation. This increment addresses
those local resource/liveness gaps without changing SQL execution authority.

## Reproduced failures

`WorkerPool.futures` previously appended every submitted Future and never removed
one. A long-lived worker retained completed results, callbacks and, for some
interruptions, exception graphs as job count grew. Backpressure bounded executing
and queued work but **not** that history.

Capacity release also lived in `_run`'s `finally`. Cancelling a queued executor
Future prevents `_run` from being called, so its admission slot was never
returned. Repeating this could stall the pool despite no active collector. A
negative queue limit could create a zero-slot pool or raise an unrelated
semaphore error instead of rejecting the configuration clearly.

The retained [baseline reproduction](../readiness-evidence/worker-pool-2026-10-24/baseline.txt)
uses the prior published pool at `2f9551b0`, not a guessed simulation. Six checks
fail against that implementation. The runner loads only that historical module
in its own test process; it does not checkout/reset or overwrite working files.

## Current behaviour

- `futures` is a locked **snapshot of admitted public futures**, not a mutable
  completion history. Clearing that list does not alter internal accounting.
- The admission budget remains **max_workers + queue_limit**. A queued wrapper
  retains its slot until consumed, even when its public Future is cancelled.
  The cancelled handler is never invoked.
- When a wrapper finishes, its tracking entry is removed **before** its local
  slot is returned or normal result/exception callbacks are invoked. A nonblocking
  follow-up submission from a completion callback therefore does not deadlock
  on the completed admission's slot. Cancellation callbacks retain standard
  Future behaviour: they may run at `cancel()` before the wrapper drains; that
  early notification does not release the admission.
- The existing `ThreadPoolExecutor` remains in place. The public Future carries
  the caller's result/cancellation; an unexposed executor Future runs the wrapper
  even after public cancellation. No private executor queue is inspected or
  modified. There is no new scheduler, persistent queue or architecture.
- Releasing immediately at public cancellation would be unsafe: repeated
  cancel/resubmit could accumulate unlimited cancelled entries inside the
  executor while its workers remain blocked. The wrapper boundary prevents that
  bypass while still returning every consumed slot.
- `wait()` is a coordinator barrier over the current admitted snapshot, including
  queued cancelled wrappers. It is not an ever-growing historical-result replay
  or a promise to include concurrent submissions arriving afterward. Do not call
  it from a handler or callback waiting on work that needs that same worker.
- A submitter that waited for capacity rechecks shutdown and is refused if intake
  closed meanwhile. Submission errors/interruptions return the local slot and
  signal the public Future to snapshot waiters. Negative queue limits are refused.

The existing statistics retain their **started-job** meaning: cancelled-before-
start work is not reported as an executed success/failure. Normal handler errors
and explicit refusals still count as failed, and BaseException interruptions
propagate through the returned Future while releasing local capacity.

## Evidence and limits

[Executed results and replay](../readiness-evidence/worker-pool-2026-10-24.md)
include concurrent producers, cancellation/replacement bursts, success/refusal/
error/interruption reclamation, shutdown races, callback failures and callback
follow-up submission. A separate fresh-process witness reuses one pool across
24 batches of 512 synthetic jobs, with two workers and the existing default
100-slot local queue. It records admitted-future counts, callbacks, counters and
sampled weak-reference reclamation, not scanner throughput.

The actual API/PostgreSQL/Redis/fresh-worker dispatch drill is rerun with this
pool. It remains a development parser success plus controlled-profile refusal,
not successful controlled isolation or production capacity qualification.

**This is not a process-memory limit.** Each admitted task has public and
executor bookkeeping; caller-retained Futures, log buffers, collector allocations,
large descriptors/results and other services can still consume memory. The
tracked-public-Future bound does not measure RSS, memory pressure, p95/p99,
throughput, sustained service availability or the agreed 20% bottleneck target.
The extra completion coordination has not been production-performance-qualified.

Local `Future.cancel()` is **not** SQL job cancellation, collector revocation,
budget release or a durable audit/terminal-job decision. SQL attempts, UNKNOWN
fences, tenant validation, approvals, isolation and the Redis ACK/reaper paths
remain their existing authorities. No new cancellation API or role was added.

## Still open

- Redis orphan recovery still has a separate pop-before-republish crash window;
  this pool repair does not make it atomic or exactly-once.
- Successful digest-pinned controlled execution, real attempt/checkpoint and
  artifact receipts, deployed least privilege/TLS/ACL/HA/partitions/recovery and
  representative scanner load/capacity remain unqualified here.
- The agreed paired workload targets (no correctness regression, no p95/p99
  slowdown, at least 20% selected-bottleneck improvement, same limits and cleanup)
  are not declared satisfied by a structural lifecycle witness.
- The original45, complete independent scope and distinct NBOM/CBOM/TechBOM/HBOM/
  VBOM/SBOM evidence, bank/legal/security acceptance and staffed operating terms
  remain separate closure requirements. No staffing, SLA or bank approval follows
  from these tests.
