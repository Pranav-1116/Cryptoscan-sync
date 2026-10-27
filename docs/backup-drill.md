# Backup / restore drill

> **2026-10-23 detailed recovery plan:** start with the
> [end-to-end backup and disaster-recovery pack](disaster-recovery/README.md).
> This dated SQLite/local-store report is retained unchanged below. It is not a current controlled PostgreSQL, whole-site or cyber-recovery qualification.

Ran 2026-10-05T09:39:13Z. Hot online backup (SQLite backup API) + event-bus logs +
live-CBOM store -> restored into a clean data dir -> second instance
booted from the backup alone -> estate verified through the real API.

| Check | Result |
|---|---|
| seed: stream ingest accepted | ✅ |
| seed: CBOM version exists for marker | ✅ |
| backup: online SQLite image taken | ✅ |
| backup: bus + CBOM stores copied | ✅ |
| restore: fresh data dir built from backup only | ✅ |
| restore: recovered instance serves the restored database | ✅ |
| recover: login works on restored estate | ✅ |
| recover: seeded system survived | ✅ |
| recover: CBOM asset set intact (version monotone) | ✅ |
| recover: CBOM hash chain verifies from genesis | ✅ |
| recover: event bus replays persisted sequence | ✅ |
| recover: detection state serviceable | ✅ |

**Verdict: PASS** (12/12 checks).

Scope note: drills the durable trio (SQLite estate, JSONL bus logs,
signed CBOM store). Postgres deployments use pg_dump/pg_basebackup +
the same verify-against-restored-instance procedure; cross-region
replication remains roadmap ⛔ (needs real regions).