# Runbook — scan job queue and persisted execution authority

**Current contract: 2026-10-21.** Redis delivery recovery and SQL execution
eligibility are separate. See the [coordinated upgrade procedure](execution-and-replay-upgrade.md)
and [authority design](../bank-environment/44-queued-authority-and-durable-ssh.md).

## Keys and delivery

| Key | Meaning |
|---|---|
| `cryptoscan:jobs:queue` | Pending JSON descriptors, FIFO (`RPUSH` / `BLMOVE … LEFT`) |
| `cryptoscan:jobs:queue:processing:<worker_id>` | Taken but unacknowledged deliveries |
| `cryptoscan:jobs:queue:worker:<worker_id>` | Worker lease, default TTL 60 seconds |
| `cryptoscan:jobs:queue:dead` | Deliveries exhausted after configured worker losses |

The queue name is configurable. `worker_id` is hostname/PID/random suffix.
BLMOVE requires Redis 6.2 or newer; older-server fallback is at-most-once at the
transport boundary. A minimum command version is not a security/support approval.

## Before a collector can run

The worker reads the persisted job before choosing an estate. Owner, target,
branch, commit, actor, type, system and scan options must match the descriptor.
Database progress replaces queue progress. Existing policy admission then runs
in the persisted estate, followed by fresh pinned authority validation and a
versioned QUEUED-to-RUNNING SQL claim. Inline fallback uses the same executor.

- Forged/missing/stale descriptors invoke no collector and do not fail a victim.
- Duplicate RUNNING/terminal jobs cannot be claimed or overwrite the claimant.
- A matching QUEUED job with revoked authority is refused; its exact-owner
  QUEUED-only FAILED stamp is best effort if SQL is available.
- Unpinned legacy jobs require approved resubmission, not guessed identity pins.

## Automatic recovery: what it does and does not do

1. A worker-loss lease expires (default 60 seconds). Maintenance can return the
   unacknowledged payload to the queue with a delivery-attempt increment.
2. At the configured loss limit (default three), delivery can be dead-lettered.
3. A stale RUNNING SQL job is failed by the database reaper after
   `JOB_RUNNING_TIMEOUT_MINUTES` (default **90**).
4. An old QUEUED job absent from Redis is eligible for re-publication after
   `JOB_QUEUED_TIMEOUT_MINUTES` (default **10**); bounded re-publications eventually
   settle it FAILED. If Redis cannot be inspected, absence is not invented.

**Re-publication is not automatic execution restart.** If the original worker
already committed RUNNING, a replacement's descriptor is refused by the claim
boundary. The reaper/operator must reconcile that original attempt. A recovered
still-QUEUED job can run only if its persisted pin and current authority pass.
There is no exactly-once external-side-effect guarantee or promised two-minute
end-to-end recovery bound.

## Manual checks

Use the approved operator identity and TLS/CA options, supplied through secure
configuration, not credentials in shell history. Queue contents can contain bank
targets; inspect only under authorized incident procedures.

```bash
redis-cli LLEN cryptoscan:jobs:queue
redis-cli --scan --pattern 'cryptoscan:jobs:queue:processing:*'
# Sensitive payloads; do not attach the output to a public ticket.
redis-cli LRANGE cryptoscan:jobs:queue:dead 0 -1
```

These examples omit connection flags deliberately; do not assume plaintext
localhost is the production endpoint. Queue clients are not all Sentinel-aware.

## Safe retry

Do **not** reset FAILED/CANCELLED/COMPLETED rows to QUEUED, change their owner,
forge pins, or move dead letters into the queue as an execution workaround.
First reconcile whether any external effects occurred. For an eligible owned
repository/binary job, `/api/v1/jobs/{id}/retry` creates a new currently admitted
job under the retrier's authority and carries supported options. Synchronous
network jobs return 409 here; resubmit their original network/SSH route instead.
Retain the old attempt and link the new change/incident record.

## Drills

`scripts/queue_kill9_drill.py` exercises consumer/lease recovery on its own queue;
its child does not run `JobExecutor` or create an authoritative SQL job. A PASS
is therefore **transport evidence**, not proof that RUNNING jobs resume or that
fresh execution authority survived a production crash. Run it only with approved
disposable Redis and protect any output containing connection details.

Qualify the real producer → SQL → executor → collector path separately, including
revocation, forged envelopes, duplicate claims, commit/ack ambiguity and unknown
side effects. Sentinel replay promotion tests in
[Guide 45](../bank-environment/45-redis-tls-sentinel-qualification.md) qualify a
different boundary; they are not a worker kill/recovery certification.
