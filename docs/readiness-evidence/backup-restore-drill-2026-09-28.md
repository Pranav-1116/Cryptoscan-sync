# Backup / restore drill

Ran 2026-09-28T17:24:48Z. Hot online backup (SQLite backup API) + event-bus logs +
live-CBOM store -> restored into a clean data dir -> second instance
booted from the backup alone -> estate verified through the real API.

| Check | Result |
|---|---|
| seed: stream ingest accepted | ✅ |
| seed: CBOM version exists for marker | ✅ |
| backup: online SQLite image taken | ✅ |
| backup: bus + CBOM stores copied | ✅ |
| restore: fresh data dir built from backup only | ✅ |
| restore: recovered instance boots | ✅ |
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
---

## Encryption fail-closed verification (same session)

`scripts/db_backup.sh` was exercised for the property fix.md item 11 cares
about: that a backup never silently degrades to plaintext. `age` was **not**
installed on the drill host, which is the interesting case.

| Condition | Expected | Observed |
|---|---|---|
| `BACKUP_AGE_RECIPIENT` set, `age` binary absent | refuse before dumping | refused; **0 files written** |
| `BACKUP_ENCRYPTION_REQUIRED=1`, no recipient | refuse plaintext backup | refused; **0 files written** |
| `BACKUP_ENCRYPTION_REQUIRED=0` (dev opt-out) | warn explicitly, then proceed | warned, then stopped because Postgres was not running |

No plaintext artifact was produced on any path, including the one where
encryption was requested and impossible.

## What this drill does NOT establish

Recorded so the PASS above is not read as more than it is:

- **Off-host copy** — backup and restore happened on one host. Transfer to
  object storage or a vault is untested.
- **Retention and destruction** — no retention period is defined anywhere,
  and no destruction procedure or certificate exists. Both are at `none` in
  the control register.
- **Encrypted round trip** — the fail-closed paths are verified; an actual
  `age` encrypt → decrypt → restore cycle is not, because the binary is
  absent here.
- **Age identity recovery and key rotation** — untested.
- **Restore authorisation audit** — nobody had to be authorised to run this.
- **Periodic drill** — this is one run, not a schedule.
- SQLite estate only. A Postgres deployment restores through
  `pg_dump`/`pg_basebackup`; that path is covered separately by
  `scripts/postgres_drill.py`, whose clean-restore stage passed on
  2026-09-28 against a two-node sandbox.
