# Backup and recovery architecture

**Status:** customer-specific architecture template
**Owner:** `[OPERATIONS OWNER]`
**Review:** every material topology, database, storage, key, or retention change

This document describes backup and recovery for the actual CryptoScan
deployment. A backup command or local restore drill is not, by itself, proof
that a customer service meets an RPO/RTO.

## 1. Recovery scope

| Component | Backed up? | Recovery method | Dependency | Owner |
|---|---|---|---|---|
| PostgreSQL/system database | `[YES]` | `[STREAMING/PG_DUMP/SNAPSHOT]` | `[KEY/NETWORK]` | `[OWNER]` |
| Evidence/object storage | `[YES]` | `[VERSIONED COPY/REPLICATION]` | `[KEY/REGION]` | `[OWNER]` |
| Redis/queue | `[YES/REBUILD]` | `[PERSISTENCE/REPLAY]` | `[DEPENDENCY]` | `[OWNER]` |
| Graph store | `[YES/REBUILD]` | `[METHOD]` | `[DEPENDENCY]` | `[OWNER]` |
| Configuration/policies | `[YES]` | `[SIGNED EXPORT/GIT]` | `[KEY]` | `[OWNER]` |
| Secrets/integration credentials | `[METHOD]` | `[HSM/SECRET MANAGER]` | `[QUORUM]` | `[OWNER]` |
| Signing/evidence keys | `[HSM/KMS]` | `[KEY RECOVERY CEREMONY]` | `[DUAL CONTROL]` | `[OWNER]` |
| Certificates/DNS | `[METHOD]` | `[PKI/DNS PROCESS]` | `[AUTHORITY]` | `[OWNER]` |
| Runbooks and images | `[YES]` | `[SIGNED BUNDLE/REGISTRY]` | `[TRUST KEY]` | `[OWNER]` |

## 2. Backup controls

Record:

- frequency and schedule;
- full/incremental method;
- encryption at rest and key ownership;
- off-host and off-site copy;
- immutability and ransomware isolation;
- retention and destruction authorization;
- backup integrity checksum;
- access logging and two-person deletion;
- provider and region;
- restore authorization; and
- alerting for backup failure.

## 3. Recovery targets

| Target | Value | Measurement method | Approver |
|---|---|---|---|
| RPO | `[VALUE]` | `[REPLICATION/RESTORE MARKER]` | `[OWNER]` |
| RTO | `[VALUE]` | `[FAILOVER TIMER]` | `[OWNER]` |
| Maximum data loss | `[VALUE]` | `[INVARIANT CHECK]` | `[OWNER]` |
| Backup retention | `[VALUE]` | `[LIFECYCLE REPORT]` | `[OWNER]` |
| Restore test interval | `[VALUE]` | `[SCHEDULE]` | `[OWNER]` |

## 4. Restore procedure

1. authorize recovery and record incident/change ID;
2. fence or isolate failed primary;
3. verify backup and key availability;
4. restore into an isolated recovery boundary;
5. verify schema, migrations, tenant/scope, audit chain, evidence, findings,
   scans, configuration, and key references;
6. start dependencies in order;
7. verify health, authentication, authorization, queue, and reports;
8. promote or redirect traffic only after checks pass;
9. record timestamps, logs, RPO, RTO, data invariants, and deviations;
10. communicate service status;
11. perform failback or rollback where the plan requires; and
12. complete post-recovery review.

## 5. Tests required

- clean restore from encrypted off-host backup;
- database promotion and fencing;
- API/worker/scheduler restart;
- queue and cache recovery;
- evidence-chain verification;
- signing/HSM/KMS timeout and recovery;
- certificate, DNS, and integration recovery;
- failback and second recovery;
- deletion and retention behavior; and
- recovery under representative load.

## 6. Evidence package

Retain:

- architecture and failure-domain diagram;
- backup checksum and encryption metadata;
- raw database/provider/host logs;
- promotion/failback transcript;
- load profile and concurrent activity;
- restore verification output;
- incident timeline;
- operator and reviewer;
- release/source commit and environment;
- limitations and residual risks; and
- customer-approved post-drill report.

## 7. Responsibility boundary

Customer-managed infrastructure, cloud accounts, database, HSM/KMS, network,
DNS, certificates, and backups remain Customer responsibilities unless the
Order Form explicitly assigns them to Vendor. The SLA must reflect that
boundary.
