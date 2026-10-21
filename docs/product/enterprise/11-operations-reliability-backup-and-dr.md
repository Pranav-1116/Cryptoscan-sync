# Operations, reliability, backup, and disaster recovery

## 1. Operating model

The service owner is accountable for availability, integrity, security,
capacity, backup, restore, upgrades, and customer communication. Product,
security, database, platform, and support owners must have explicit handoffs.

Maintain an operations calendar for:

- health and queue review;
- failed/partial scan review;
- credential and certificate rotation;
- backup completion;
- restore drill;
- vulnerability and dependency updates;
- policy and rule review;
- access review;
- capacity/soak test;
- release approval; and
- customer notification windows.

## 2. Service health

Monitor at least:

- API error and latency by route class;
- authentication failures and lockouts;
- queue depth, age, retries, leases, and dead letters;
- worker throughput and failure rate;
- scan duration and partial coverage;
- database connections, locks, storage, and migration state;
- Redis/graph/artifact availability;
- evidence chain verification failures;
- export and connector delivery failures;
- certificate and key expiry; and
- backup age and manifest verification.

Health should expose enough to decide whether the service can accept work, but
should not leak credentials, customer data, or internal topology to unauthenticated
callers.

## 3. Backup design

Back up separately:

- PostgreSQL database and migration metadata;
- evidence/artifact storage and manifests;
- graph data where it cannot be rebuilt within the recovery objective;
- configuration that is safe to retain; and
- audit/export packages under their retention policy.

Do not put `.env` files or raw secrets in ordinary database backups. Encrypt
backups, restrict access, record checksum and timestamp, and copy to an
independent failure domain.

## 4. Restore procedure

1. declare the restore reason and recovery scope;
2. select a backup and verify its manifest/hash;
3. restore to an isolated environment first;
4. apply or verify the expected migration state;
5. start the minimum API/worker stack;
6. verify recent evidence chains and report hashes;
7. check user, system, baseline, job, and policy state;
8. rebuild optional graph/materialized data if required;
9. compare row counts and known identifiers;
10. record data loss or replay window;
11. obtain owner approval; and
12. switch traffic or resume jobs with a recovery notice.

A backup is not a recovery plan until a restore drill demonstrates that the
required evidence and services can be recovered.

## 5. RPO and RTO

The customer must set RPO/RTO based on business use. Example planning values
must be labeled as targets, not achieved commitments:

| Workload | RPO decision | RTO decision | Evidence required |
|---|---|---|---|
| Scan queue | How much queued work may be replayed/lost | Time to resume workers | Queue replay and idempotency drill |
| Evidence database | Maximum accepted observation loss | Time to read/verify evidence | Restore and chain verification |
| Dashboard/API | Acceptable configuration/session loss | Time to serve reads | Failover or restart drill |
| Reports/artifacts | Acceptable export loss | Time to regenerate or restore | Artifact/manifest restore |

## 6. Failure handling

When a dependency fails:

- stop or drain unsafe work;
- preserve job state and correlation ID;
- mark coverage incomplete;
- prevent duplicate external actions;
- retry with bounded backoff if safe;
- route irrecoverable jobs to a dead-letter review;
- notify the responsible owner; and
- document recovery and customer impact.

A retry that creates duplicate tickets, duplicate scans, or duplicate evidence
is an integrity problem, not merely a performance problem.

## 7. Upgrade and migration operations

Before a release:

1. review changelog, migration, security, and compatibility notes;
2. generate and inspect the release/SBOM packet;
3. test migration from a representative prior state;
4. verify backup and rollback/forward plan;
5. deploy to staging;
6. run health, smoke, scan, evidence, and export checks;
7. approve a maintenance window;
8. apply the release with operator observation; and
9. retain result, logs, and rollback decision.

Do not claim zero downtime or backward compatibility without an executed test
for the actual topology.

## 8. Recovery evidence

Retain:

- incident or change record;
- affected components and versions;
- backup identifier and checksum;
- command/operator/time;
- before and after health;
- chain/report verification;
- data-loss and replay assessment;
- customer communication; and
- follow-up actions.

The [DR recovery runbook](../../runbooks/dr-recovery.md), backup/restore guide,
and production checklist provide the repository-specific commands.

## Current recovery constraints

Use the [execution/replay upgrade runbook](../../runbooks/execution-and-replay-upgrade.md).
Reconcile SQL separately from Redis backups. Legacy unpinned work requires
approved resubmission; RUNNING recovered deliveries cannot be reclaimed or
resumed by changing a terminal row. Preserve unknown side effects and old IDs.

Promotion/process restart resets primary-bound production cursors, even if the
stored data survived. A complete new retained snapshot is not proof of lossless
asynchronous replication. The [TLS/Sentinel lab](../../bank-environment/45-redis-tls-sentinel-qualification.md)
is destructive/disposable local qualification, not evidence of your topology's
RPO/RTO, credential rotation, partitions, restore or failback.
