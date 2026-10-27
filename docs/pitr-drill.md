# Point-in-time recovery drill

Ran 2026-09-17T08:09:44.709455+00:00 — executable proof (`scripts/region_drills.py`), temporary regions, real bus code.

| Check | Result |
|---|---|
| consistent snapshot taken (db + logs + manifest) | ✅ PASS |
| PITR to recovery point: exact state, nothing beyond | ✅ PASS |
| recovered stream accepts new writes (seq continuity) | ✅ PASS |
| database restored to snapshot point | ✅ PASS |

Model: consistent DB snapshot (SQLite online backup / pg_basebackup
in production) + append-only signed event logs. Recovery to point T
= snapshot + verified replay of events in (snapshot, T]. The
recovered stream continues with correct sequence numbering.

**Verdict: PASS**
