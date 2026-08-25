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

Part 3/4 tables:

- `certificates` + `certificate_usages` + `network_scan_targets`
- `cloud_accounts`, `business_processes`, `business_owners`, `vendors`
- `system_agility_scores` — historical 6-factor scores
- `policy_exceptions` + `exception_reviews`
- `vendor_crypto_inventory`
- `ot_devices` + `ot_crypto_findings`

SQLite is the local stand-in (`data/cryptoscan.db`). Production is Postgres
via Compose; JSONB columns degrade to JSON on SQLite. `init_db` creates
missing tables and adds new columns without reseeding.
