# Point-in-time platform recovery drill

Ran 2026-11-06T12:53:34.083531+00:00 — executable proof (`scripts/region_drills.py`), temporary regions, real bus code.

**Scope — what this drill is, and is not.** This is platform-event
recovery — snapshot + verified replay of the signed event log — in one
process. It is **not** PostgreSQL WAL PITR, **not** a bank backup
restore, **not** a measured RPO/RTO, and **not** SOC 2 evidence. The
bank-side restore drill is `scripts/restore_drill.py` against its own
backups and recovery database.

| Check | Result |
|---|---|
| consistent snapshot taken (db + logs + manifest) | ✅ PASS |
| PITR to recovery point: exact state, nothing beyond | ✅ PASS |
| recovered stream accepts new writes (seq continuity) | ✅ PASS |
| database restored to snapshot point | ✅ PASS |

Model: consistent DB snapshot (SQLite online backup in this drill) +
append-only signed event logs. Recovery to point T = snapshot +
verified replay of events in (snapshot, T]. The recovered stream
continues with correct sequence numbering.

**Verdict: PASS — same-process code drill (see Scope; not a site qualification)**
