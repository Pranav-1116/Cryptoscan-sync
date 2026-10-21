# Execution authority, SSH receipts and replay — upgrade runbook

**Reviewed 2026-10-21 against implementation `e9bfbef7`.** This is an operator
procedure, not evidence that a production upgrade or recovery drill was run.
See [queue/SSH design](../bank-environment/44-queued-authority-and-durable-ssh.md),
[Redis qualification](../bank-environment/45-redis-tls-sentinel-qualification.md)
and the [production evidence gate](../../PRODUCTION-READINESS.md).

## 1. Pre-change inventory

Record the release, topology, service owners and rollback/forward decision.
Inventory QUEUED/RUNNING jobs by exact estate, producers, actor kinds, API-key
policies, repository configurations, Redis consumers and all retained replay
cursors. Back up SQL, evidence and the approved Redis persistence state through
separate procedures; the evidence database backup does not back up Redis.
Do not include passwords, raw API keys, private certificates or bank payloads in
public change records.

## 2. Coordinate producers and workers

1. Pause admission and drain or account for in-flight work through the approved
   maintenance process. Record unknown outcomes instead of inventing success.
2. Deploy pinning producers and reconciling workers together. Keyword and
   object-form `JobRepository` creation pin current authority on QUEUED rows.
3. New monitor repository work uses `MONITOR_REPOSITORY`; a human named
   `monitor` remains a human. Real usernames colliding with reserved `apikey:`
   or `scheduler:` actor namespaces fail closed and need reviewed remediation.
4. Reconcile legacy unpinned jobs. Cancel or resubmit approved work under current
   admission with a new ID. Do not synthesize old enqueue pins, edit ownership,
   reset terminal rows or change queue options to force execution.
5. Verify bank A, bank B and NULL/platform claims independently. A forged envelope
   must cause neither collection nor mutation of the victim job.
6. Revoke a test initiator after enqueue. Collection must be refused. A duplicate
   of an already RUNNING job must not run again or fail the current claimant.

A Redis lease recovers delivery, not execution authority. Recovered RUNNING jobs
cannot be claimed by the QUEUED-only worker. Investigate possible external side
effects, let the reaper/operator settle the original job, then create an approved
new attempt where needed. Exactly-once execution is not provided.

## 3. Configure verified Redis before enabling production

Provision a named non-default ACL user, `rediss://`, an approved CA bundle and
hostname-valid server certificates. Optional Sentinel requires at least three
distinct TLS discovery endpoints, a master service name and dedicated discovery
credentials. Every discovered data endpoint must pass certificate verification.
Mount CA material in the API containers; setting a host path alone is insufficient.
Never disable verification to make startup pass.

The factory covers realtime/current-run clients, not every queue, cache,
health-probe or rate-limiter client. Review each consumer's direct URL, CA/client
options, command set and key/channel prefixes. Three configured addresses and a
Compose/Kubernetes manifest do not establish independent failure domains.
The edge HTTPS overlay does not provision Redis TLS.

Production startup exercises scratch journal commands, including INCRBY,
WATCH/MULTI, stream writes, publication, replay and cleanup. INFO is needed for
primary-bound snapshots. PING is not a write-readiness test. Missing commands or
credentials must prevent required durable operation, not enable local fallback.

## 4. Upgrade replay clients

Use `next_cursor` from exact-estate pages and opaque `Last-Event-ID` tokens for
SSE. Nonzero numeric `since_id` is refused with 409. Save the acknowledged
checkpoint only after processing its preceding events. Do not reuse a cursor
under a different selected estate.

On initial 409/epoch reset, explicitly discard the old continuation and refresh
application state before requesting a new retained snapshot. Retention gaps
require the same application-level reconciliation. Backend 503 is not an empty
history. Midstream `events.unavailable`/`events.refused` means stop and recover
according to the current authority/backend condition; inspect the reconnect
response rather than retrying a rejected cursor forever.

Promotion or a Redis process restart changes primary-bound production epochs,
even if all data survived. A complete new retained snapshot does not prove all
previously acknowledged writes survived asynchronous replication. Reconcile
business records/receipts separately. Preserve historical ownership.

## 5. Verify SSH consumers

For an approved target, retain both `job_id` and `run_id` from
`POST /api/v1/network/ssh-scan`. Read the owned job and network-run detail after
the original HTTP response. Bank B must receive 404 for bank A's IDs.

A COMPLETED job means recording finished, not every host succeeded. Check the
stored verdict/findings/telemetry: TIMEOUT/FAILED observations remain failures.
Known-host baselines are caller supplied and unverified. Generic job retry
returns 409 for synchronous network collections; resubmit the original SSH
profile through its route and current admission.

Failure before the initial receipt commit prevents packets but may leave no
job. Failure later rolls back the success ledger and best-effort stamps FAILED;
a crash may leave RUNNING. Do not manufacture a result for an unknown outcome.

## 6. Acceptance and evidence

Run bank-specific negative tests, scoped canaries and the approved rollback/
restore drill. The destructive Redis lab in Guide 45 must run only on disposable
services with both opt-in guards. It is not a production drill and must not be
pointed at bank Redis.

Retain release/command/environment/time, results, skips, limits and operator
approval in the controlled evidence store. The implementation ledger records
1315 passed/4 skipped in the broad affected run, then 205 focused passes after
final provenance changes, and 28 real TLS/Sentinel plus unit passes. These are
historical local runs with overlapping coverage, not new results from this
documentation refresh or a substitute for production acceptance.
