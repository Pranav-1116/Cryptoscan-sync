# Point-in-time platform recovery drill

> **Scope.** This proves *platform* recovery: a consistent snapshot plus verified
> replay of the signed event log to a chosen point. It is **not** PostgreSQL WAL
> point-in-time recovery, which needs a bank-operated physical base backup and WAL
> archive (see `docs/runbooks/dr-recovery.md`); the governance backup API refuses a
> requested PIT on a `pg_dump` artifact rather than reporting one.

Ran 2026-09-17T08:09:44.709455+00:00 — executable proof (`scripts/region_drills.py`), temporary regions, real bus code.

| Check | Result |
|---|---|
| consistent snapshot taken (db + logs + manifest) | ✅ PASS |
| PITR to recovery point: exact state, nothing beyond | ✅ PASS |
| recovered stream accepts new writes (seq continuity) | ✅ PASS |
| database restored to snapshot point | ✅ PASS |

Model: consistent DB snapshot (SQLite online backup in this drill) +
append-only signed event logs. Recovery to point T = snapshot + verified
replay of events in (snapshot, T]. The recovered stream continues with
correct sequence numbering. Database *physical* recovery of the PostgreSQL
cluster to a point in time is a separate, bank-operated workflow and is out
of scope here.

**Verdict: PASS**
