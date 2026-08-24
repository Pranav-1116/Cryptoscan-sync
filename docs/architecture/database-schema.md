# Database schema

Tables created by `init_db()` (and Alembic 0001–0009):

- `scans` — one row per scan session (`id` UUID string)
- `evidence_records` — one row per finding, FK `scans.id`
- `scan_jobs` — queue metadata
- `baselines` — approved scan per target
- `drift_events` — changes vs baseline
- `repo_configurations` — webhook allow-list
- `verification_log` — load-time integrity notes

SQLite uses `JSON`. PostgreSQL uses the same columns (JSON, not JSONB) so the ORM stays portable.
