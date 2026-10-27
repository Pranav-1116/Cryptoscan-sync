# 4. Make execution reliable, bounded and recoverable

[Pack index](README.md) · [Previous: security](03-security-privacy-and-isolation.md) ·
[Next: user workflow](05-user-workflow-and-frontend-quality.md)

## 4.1 Improve predictability before increasing throughput

A reliable product tells the operator whether work was admitted, queued, started,
partially completed, refused, failed or left UNKNOWN—and retains enough evidence
to recover safely. A fast successful demo is not evidence of those properties.

Existing worker authority, claims/fences, partial-progress receipts, SQL history,
Redis roles and performance instrumentation are the starting point. Do not add
an alternative queue, scheduler, database or observability platform for this plan.

## 4.2 Agree measurable objectives for the supported workflow

Choose actual targets with the bank/operations owner **before** running the test.
This table is a planning worksheet, not a claimed SLA or benchmark:

| Dimension | Define before measurement | Record after measurement |
|---|---|---|
| Input | Source file count/bytes, nesting, parser mix and admitted limits | Accepted/refused counts and exact fixture hashes |
| Concurrency | Active estates/jobs and expected arrival pattern | Queue age, admission outcomes, completed/partial/failed/unknown jobs |
| Response | Critical list/detail/task action, page size and representative data | p50/p95/p99 if sample size supports them; counts, errors and timeouts |
| Resource | CPU/memory/disk/connection budget per process/container and site | Peak/steady usage, throttling, leaks and cleanup |
| Recovery | Exact role/scenario and agreed loss/recovery objective | Pre-fault acknowledgements, observed lost IDs, measured interval and limitations |
| Retention | Evidence volume, legal hold, archive/backup rules | Growth, quota behavior, aged-read performance and approved expiry behavior |
| Browser | Workstation/browser/network, concurrent tabs and work period | Task completion, heap/CPU, request count, reconnects, errors and accessibility |

Targets are site-specific. Do not copy a localhost RTO or extrapolate a small
synthetic run to a multi-region bank. A source class or concurrency level beyond
the measured envelope remains unqualified.

## 4.3 Establish a workload envelope

Use repeatable approved fixtures representing **existing** supported inputs:

1. Small normal source release, large allowed release and just-over-limit input.
2. Mixed supported/unsupported files, malformed inputs and expensive parser cases.
3. Quiet estate, busy estate and two estates contending for shared resources.
4. Low/high historical row counts with realistic page sizes and retained evidence.
5. Normal PostgreSQL/Redis operation, controlled slow dependency and unavailable dependency.
6. Browser navigation, hidden tab/resume, multiple tabs and permitted network degradation.

Keep fixture size, hardware, database statistics, image/dependency identities and
configuration with the measurements. Run paired before/after trials with the same
conditions. Include warm/cold behavior where relevant; report variability, not
only the fastest run. Stop safely on pre-agreed resource/impact thresholds.

The [existing workload guide](../bank-environment/55-measured-workloads-and-capacity-limits.md)
and `scripts/operator_workload.py` / `scripts/operator_http_workload.py` provide
starting points. Read their limits before use; they do not launch or qualify
hostile parser/site/browser workloads by themselves.

## 4.4 Understand instrumentation before tuning

Existing stage metrics include process CPU, process high-water RSS, process I/O,
queue/execution time and bounded SQL latency samples. Their limitations matter:

- process high-water RSS is not per-job allocated memory or a container peak;
- process counters may include other work in that process;
- a bounded first-sample p95 is not an unbiased whole-run p95;
- browser simulated timers are not real elapsed-time endurance;
- API health is not worker, connector, parser or data-store health;
- zero errors in a short run does not prove long-term availability.

Use existing monitoring/logging and permitted site tools to obtain the missing
process/container/browser evidence. No new customer dashboard is needed. Logs
must remain bounded and secret-free; recording every SQL query/parameter is not
a suitable performance “fix.”

## 4.5 Improve database/query quality surgically

For each slow critical journey:

1. Reproduce on the intended PostgreSQL lane with representative permitted data.
2. Identify query count, plan, filters, sort order, rows/bytes returned and connection wait.
3. Check exact estate filtering before optimizing; do not use cross-estate caching.
4. Remove demonstrated N+1/repeated reads and bound list/detail payloads.
5. Add/change an index only when paired plans/measurements justify it.
6. Test insert/update cost, migration locking, transaction behavior and large history.
7. Verify pagination with equal timestamps, concurrent inserts and empty last pages.
8. Compare correctness and latency before/after, including denied/degraded requests.

Some operator lists use offsets and are not frozen exports; do not present their
combined pages as a transactional whole-estate snapshot. Existing opaque replay
cursors have a different contract. Avoid “optimizations” that skip periodic SQL
reconciliation and leave stale authority or status indefinitely on screen.

## 4.6 Exercise durable execution boundaries

Use disposable, authorized environments only. At each boundary retain the exact
job/attempt/receipt IDs, durable state before fault, observed state after and reviewer:

| Fault point | Required behavior to verify |
|---|---|
| Before enqueue acknowledgement | Reconcile actual durable state before retry; no fabricated completed job. |
| After transport delivery, before claim | Duplicate delivery cannot create two authorized RUNNING executions. |
| After claim, during parser work | Bound resources, retain honest progress/outcome and do not assume timeout killed effects. |
| After effect, before SQL/outbox acknowledgement | Preserve ambiguous external outcome; do not blindly replay or free reservations. |
| After durable result, before UI notification | SQL remains the source of truth; missing wakeup does not erase the result. |
| On policy/credential revocation while queued | Original persisted pins are rechecked against current authority before execution. |
| On worker/API restart | Recovery respects claim/fence state, ownership and approved reconciliation. |

Do not promise exactly-once external effects. At-least-once transport plus a
QUEUED-only claim is useful, but cannot prove an external operation never happened
in an acknowledgement gap. UNKNOWN requires the existing human reconciliation
process—not a database edit setting the job back to QUEUED.

## 4.7 Redis and PostgreSQL recovery proof

Transport readiness is separate from data survival. Follow the
[Redis role/scenario contract](../bank-environment/47-redis-consumer-and-recovery-evidence.md):
record acknowledgements **before** the fault, then inspect those same IDs after.
A new healthy snapshot or PING cannot substitute for prior-ACK survival.

Plan approved disposable drills for relevant roles and scenarios: process kill,
partition, lag, disk/memory pressure, certificate/credential rotation,
backup/restore and failback. Measure only actual roles exercised, and retain
current topology/objective hashes plus different-human review. Do not inject
faults into customer queues or infrastructure without explicit authorization.

For PostgreSQL restore include schemas, retained records and links, revision
history, evidence/object availability, access controls and re-verifiable hashes.
A row count alone is insufficient. Separate migration and runtime grants,
restore configuration/secret dependencies through approved custody, and prevent
an isolated restore from sending real notifications or resuming real jobs.

## 4.8 Tune in a safe order

1. Fix demonstrated incorrect/duplicate work.
2. Bound input, output, concurrency and connection usage.
3. Remove proven unnecessary queries/parsing/serialization.
4. Tune supported existing pool/timeouts using measurements and failure tests.
5. Re-measure fairness: a large estate must not silently starve another approved estate.
6. Verify overload gives explicit refusal/deferment, not memory exhaustion or false success.
7. Re-run recovery/authority checks after tuning; faster unsafe retries are regressions.

Do not improve a throughput chart by disabling TLS, evidence writes, policy checks,
independent review or resource limits.

## 4.9 Exit criteria

A reviewer sees a measured support envelope, repeatable before/after evidence,
honest partial/UNKNOWN handling, safe duplicate/restart behavior and witnessed
recovery for the intended site. Unmeasured scale, browser endurance or HA remains
explicitly unqualified. Any contractual objective still requires the real service
owner and legal/customer approval; this guide authorizes no SLA.
