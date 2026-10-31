# The job/worker contract — nine properties, each proven by a drill

`cryptoscan.job-contract/1` · generated 2026-10-31T17:36:55.368015+00:00 · **9 proven / 0 broken / 0 unproven of 9**

Each row runs the code that is supposed to provide the property. `PROVEN` means every check passed; `UNPROVEN` means the drill could not run here and is **not** a pass.

| Property | Promise | Observed | Verdict |
|---|---|---|---|
| `job_queue` | a published job is delivered to exactly one consumer, and only dropped on acknowledgement | enqueue → one claim, job moves to the processing list under a lease, a second pop gets nothing, ack releases it | **PROVEN** |
| `worker` | handlers run, concurrency honours max_workers, a failure does not leak a slot | peak concurrency equals max_workers; a raising handler is reported to the submitter as False (logged, not raised) and releases its slot; saturation clears | **PROVEN** |
| `retry` | a job lost with its worker, or failed transiently, is retried with the attempt counted; a permanent failure is not | lost job requeued and redelivered with attempts=1 (max_redeliveries=3); transient failure scheduled 26.0s out and promoted when due; ValueError, an exhausted budget and a controlled job all dead-letter/refuse instead | **PROVEN** |
| `timeout` | a job that stops progressing is timed out, not stuck forever | silent worker's lease expires → job recovered; RUNNING row past 90m → FAILED; expired deadline → ExecutionDenied at the next checkpoint | **PROVEN** |
| `cancellation` | a cancelled job stops before its next stage runs | cancelled job → ExecutionDenied('Execution lease is absent, fenced or expired') at the next checkpoint; the identical call on a RUNNING job gets past that check | **PROVEN** |
| `idempotency` | duplicate publication or delivery cannot execute twice | outbox dispatch publishes once and returns False afterwards; a duplicate row is refused by the unique key; a duplicate delivery is refused at the SQL claim | **PROVEN** |
| `dead_letter` | past the retry budget a job is set aside with a reason | past max_redeliveries → dead letter with reason 'job redelivered 2 times after worker loss; giving up'; queue empty, no requeue | **PROVEN** |
| `recovery` | after a crash the work is picked up and finished | a killed consumer's job is requeued and completed by the next consumer, leaving the processing list empty | **PROVEN** |
| `concurrency` | admission is bounded and over-submission is refused or blocked | max_workers=1 + queue_limit=1 → the third submit blocks until a slot frees, then runs; no admitted work is left behind | **PROVEN** |

## What this does not prove

- `job_queue`: fakeredis; the ordering guarantee (BLMOVE left→right) is exercised against the real client only on a bank host, and a claim is not exactly-once execution
- `worker`: in-process ThreadPoolExecutor. The pool still reports a handler failure as False and releases the slot; whether that failure is retried is policy, and the policy is `retry_policy`'s (see the `retry` row) — the pool only guarantees the hook runs
- `retry`: the retry lives in Redis (a sorted set scored by due time) and is promoted by the worker's maintenance sweep, so a retry can wait up to one maintenance interval past its backoff. The controller path is deliberately excluded: a controlled job's attempt holds an approval and a lease, and re-queuing it would bypass operator reconciliation. Retries are not deduplicated against a job that is still running elsewhere
- `timeout`: the three timeouts are checked at different layers and none of them interrupts a handler already inside a stage — a stage that never returns still occupies its worker
- `cancellation`: cancellation is a checkpoint boundary, not a signal: work already inside a stage runs to the end of that stage, and a stage that never returns is not interrupted
- `idempotency`: this is at-least-once publication with a claim fence, not exactly-once execution: a crash between publish and ack may duplicate a message, which the claim then refuses
- `dead_letter`: the dead-letter list is not drained by anything here: a job there needs an operator, and nothing in this drill proves someone is told
- `recovery`: the crash is simulated by deleting the lease; the process is not actually killed here (scripts/queue_kill9_drill.py does that)
- `concurrency`: backpressure is per worker process; there is no cross-worker admission budget in this drill, and a blocked submitter is not visible to an operator

And across all nine: this is one process, one SQLite database and fakeredis. It does not prove behaviour under a real Redis restart, a PostgreSQL failover, a queue backlog of thousands, or two workers racing on the same row. Those need the bank-host drills (`queue_kill9_drill.py`, `worker_dispatch_drill.py`, `postgres_drill.py`) and a load run.
