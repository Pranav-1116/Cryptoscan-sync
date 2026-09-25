# Runbook — scan job queue (Redis) and stuck jobs

## Keys

| Key | Meaning |
|---|---|
| `cryptoscan:jobs:queue` | pending jobs (JSON payloads), FIFO (`RPUSH` / `BLMOVE … LEFT`) |
| `cryptoscan:jobs:queue:processing:<worker_id>` | jobs a worker has taken and not yet acked |
| `cryptoscan:jobs:queue:worker:<worker_id>` | worker lease, TTL `JOB_LEASE_TTL_SECONDS` (60 s); refreshed on every poll |
| `cryptoscan:jobs:queue:dead` | payloads given up after `JOB_MAX_REDELIVERIES` (3) worker losses |

`worker_id` = `<hostname>:<pid>:<8 hex>`; the worker logs it at start (`cryptoscan_worker_pool`).

## What happens automatically

1. **Worker killed mid-scan** (`kill -9`, OOM, node loss): its lease expires ≤ 60 s later. The next worker to run maintenance (start-up, then every 60 s) moves the payload back to the *head* of the queue with `_attempts+1` and logs `job_requeued_after_worker_loss`. The DB row stays `RUNNING` until the new worker restarts the pipeline (the pipeline re-stamps it), or until the reaper fails it (see 3).
2. **Same job kills three workers**: it is pushed to `…:dead`, the DB row is set `FAILED` with "redelivered 3 times after worker loss; giving up" (`job_dead_lettered`).
3. **DB row RUNNING but no stage update for `JOB_RUNNING_TIMEOUT_MINUTES` (90)**: the reaper sets it `FAILED` ("worker lost: no progress …", `job_reaped_running`). Raise the timeout for estates with very large repos.
4. **DB row QUEUED for `JOB_QUEUED_TIMEOUT_MINUTES` (10) but not in Redis** (Redis restarted without persistence, publish failed): re-published, `progress.requeued` incremented (`job_republished`); after two re-publishes → `FAILED` (`job_reaped_queued`). If Redis is unreachable the reaper leaves QUEUED rows alone — it cannot tell.

## Manual checks

```
redis-cli LLEN cryptoscan:jobs:queue
redis-cli --scan --pattern 'cryptoscan:jobs:queue:processing:*'
redis-cli LRANGE cryptoscan:jobs:queue:dead 0 -1
```

Replay a dead-lettered job (after fixing the cause): `redis-cli RPOPLPUSH cryptoscan:jobs:queue:dead cryptoscan:jobs:queue` and set the DB row back to `QUEUED` (`PATCH /api/v1/jobs/{id}` or SQL) — the `_attempts` counter in the payload is kept, so edit it if you want a full three more tries.

## Redis version

`BLMOVE` needs Redis ≥ 6.2. On older servers the worker logs `blmove_unsupported_at_most_once_delivery` once and behaves as before (message lost on worker crash; the DB reaper still fails the row after the running timeout).

## Drill (once per environment)

Scripted: `REDIS_URL=redis://… python scripts/queue_kill9_drill.py` (≈ 10 s, uses its own queue, exit 0 = PASS). Manual: trigger a scan of a large repository, `kill -9` the worker while `stage=scan`, start a worker again: expect `orphaned_jobs_recovered {"requeued": 1}` in its first log lines and the job to complete with `progress.attempts` visible in the payload. Total added latency ≤ lease TTL + maintenance interval (~2 min).
