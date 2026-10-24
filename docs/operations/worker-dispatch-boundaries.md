# Worker dispatch: durable publication and transport lease lifecycle

**2026-10-24 — existing queue/worker improvements, not a new service.**

The earlier [scoped rescan inspection](scoped-rescan-inspection.md) exercised a
real parser/evidence loader but fixture-created its job completion envelope.
This increment exercises an API-created job through actual Redis and a fresh
worker process. It does **not** retrospectively turn that browser artifact into
a worker-dispatch test or qualify controlled production parsing.

## Two reproduced correctness failures

### 1. A Redis destination must not silently become a process-local queue

`api.routers.trigger._publish_job` uses `enqueue_job`. Previously the helper
constructed `JobConsumer` with its default memory fallback enabled. Even though
`execution_outbox.dispatch_one` requires publication failures to raise, a Redis
write failure could instead enqueue in API-process memory and return success.
The outbox then became `PUBLISHED`; a separately running worker could never see
that delivery. A lower-level test with an explicitly strict consumer missed the
helper's default.

The actual API-publisher regression reproduced **PUBLISHED instead of PENDING**.
The helper now disables memory fallback whenever a Redis URL is configured,
regardless of development/production environment. The worker entrypoint also
rejects a configured Redis outage rather than silently switching transports.
The API still logs a background publication failure; for controlled jobs the
committed SQL job/outbox remains pending for worker maintenance to republish.
This is at-least-once delivery, not exactly-once external effects.

Tools/tests that intentionally instantiate `JobConsumer` with
`allow_memory_fallback=True` retain that explicit development facility. An empty
Redis configuration retains the existing development behaviour. Production
still requires its existing verified Redis configuration; no TLS/ACL check was
relaxed.

### 2. Stopped intake does not mean in-flight ownership ended

Worker leases were renewed while polling. `SIGTERM` stops intake and waits for
in-flight futures, so a scan taking longer than the lease TTL to drain could
lose its Redis lease while its executor was still alive. Backpressure can also
block polling. Another consumer could interpret its processing list as orphaned.

The lifecycle regression reproduced **a missing lease while the worker thread
was still draining**. `JobConsumer.maintain_lease()` now renews on a dedicated
bounded-I/O thread, at one-third of the configured TTL. `Worker.run()` keeps that
context open through orphan adoption, intake and pool shutdown. `stop()` stops
intake, not lease renewal. The keeper is joined when ownership ends; the final
TTL expires normally so any failed ACK can still enter ordinary recovery.

The Redis lease remains a **transport liveness hint**, not the SQL execution
attempt/fence, a guarantee under a network partition, or proof a collector has
stopped. Existing SQL authority checks, duplicate claims, UNKNOWN reservations,
positive approvals and isolation preflight remain unchanged. Atomic recovery
across Redis/process failures and deployed partition/HA qualification remain
separate work; this change does not promise exactly-once processing.

## Fresh-process import correction

The canonical Python script bootstrap had a stale service list: a fresh process
could not import the current API's `devsecops` dependency. It now discovers the
same shared/service roots as the existing shell launcher and container `.pth`
setup. A subprocess test imports both the current API and worker without an
inherited `PYTHONPATH`. This is an import-path repair, not a new architecture.

## What actually ran

The [executed evidence report](../readiness-evidence/worker-dispatch-2026-10-24.md)
records the exact tests and the owned local drill. The drill creates its own
Unix-socket PostgreSQL/Redis, migrates through 0107, provisions synthetic users
and source files, authenticates with the real password/session endpoints, and
calls actual ASGI routes. Jobs/scans/evidence are **not** preinserted. Workers
run the unmodified `python -m worker.main` entrypoint in fresh OS processes.

The successful development job runs the real inline parser, hash pipeline and
PostgreSQL loader. Duplicate Redis hints create only one scan. The test also
engages emergency stop after enqueue through the existing development control
API, then verifies refusal in the fresh worker and at new admission.

After that development case, controlled mode is enabled and remains enabled
for both controlled dispatch cases. A positive grant and SQL outbox are created
through the existing authenticated execution-controls routes. The worker
correctly refuses an unprovisioned isolation runtime, with no execution attempt
or extra scan. A real Redis process stop leaves another API-created controlled
job/outbox pending; after restart, worker maintenance republishes it and the
same isolation boundary refuses it. No collector, preflight or policy double
makes that refusal look like successful controlled execution.

Real Redis transport-only cases separately cover draining beyond a shortened
TTL and an actual SIGKILL followed by recovery after—not before—lease expiry.
Those synthetic transport envelopes are explicitly **not** scan/execution
completion evidence.

## Still open

- Successful controlled execution with a provisioned digest-pinned container,
  production PostgreSQL/verified Redis, actual execution attempts/checkpoints,
  artifact receipt, interruption/reconciliation and an independent observer.
- Deployed TLS/ACL/Sentinel/HA, network partitions, power-loss recovery, external
  collector-effect deduplication, sustained admission/fairness/capacity and load.
- The agreed performance targets: no correctness regression, no p95/p99 slowdown
  and at least 20% selected-bottleneck improvement on the same workload/limits.
  This correctness increment makes **no paired-performance claim**. The keeper
  adds periodic Redis SETs; their deployed overhead is not qualified here.
- Complete bank-approved discovery denominators, platform/protocol/HSM/PKI/PQC
  coverage and independent operational/legal/security acceptance.

The six distinct **NBOM, CBOM, TechBOM, HBOM, VBOM and SBOM** remain distinct
product evidence surfaces. A queue repair does not establish their completeness
or add coverage to any of them. Historical partial-coverage fences and rescan
non-clearance fields remain unchanged. No new collector, dashboard, migration,
customer-deployment change, staffed SLA or bank approval is introduced.
