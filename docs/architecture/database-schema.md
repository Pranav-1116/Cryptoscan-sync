# Database schema

Core Part 1 tables:

- `scans` — one row per pipeline run
- `evidence_records` — hashed findings, policy JSON, normalized crypto
- `scan_jobs` — queue / inline job progress + logs
- `baselines` — approved scan per target
- `drift_events` — NEW / REMOVED / CHANGED / UPGRADED

Part 2 tables:

- `crypto_assets` + `crypto_asset_evidence` — deduplicated inventory
- `systems` + `system_assets` + `system_dependencies` — simple inventory
- `container_scans` + `vulnerabilities` — image-root results
- `repo_configs` — per-repo webhook settings

SQLite is the local stand-in (`data/cryptoscan.db`). Production is Postgres
via Compose; JSONB columns degrade to JSON on SQLite.
