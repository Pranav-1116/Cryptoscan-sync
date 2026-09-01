# Run CryptoScan

Production cryptographic inventory: **scan source / containers / IaC / local certs → hash evidence → store → normalize → evaluate policy → REST API → dashboard**.

Policy is never decided by AI. Fail/pass comes from YAML in `services/policy/rule_definitions/`.

## Local (laptop / this sandbox)

```bash
python3 -m pip install -r requirements.txt
export CRYPTOSCAN_ROOT=$PWD
export PYTHONPATH=$PWD/shared/shared_config:$PWD/shared/shared_logging:$PWD/shared/shared_models:$PWD/services/api:$PWD/services/database:$PWD/services/scanner:$PWD/services/evidence:$PWD/services/normalization:$PWD/services/policy:$PWD/services/drift:$PWD/services/worker:$PWD/services/deduplication:$PWD/services/cbom:$PWD/services/container_scanner:$PWD/services/network_scanner:$PWD/services/cloud_scanner:$PWD/services/graph_engine:$PWD/services/business_context:$PWD/services/quantum:$PWD/services/remediation:$PWD/services/reporting
python3 scripts/seed_demo.py
bash scripts/run_stack.sh
```

Development login is `admin` / `cryptoscan`. Open `/ui` or the dashboard container. From a scan detail page you can **Verify chain**, **Export CBOM** (CycloneDX 1.5), and **Export JSON**.

```bash
make test    # per-service pytest (avoids shared `tests` package clash)
make api     # frontend :3003 + API :8010
```

Trigger a scan of the bundled sample with `local://demo/vulnerable-app`.

**24/7 live scanning** (see `docs/dev/LIVE-SCANNING.md` for the full picture):

```bash
make monitor       # continuous daemon: change-watch + interval scanning, HA lease
make monitor-once  # single sweep (cron mode)
```

Register targets with `POST /api/v1/monitor/targets`; add `"watch": true` in
`config` for a REPO/CONTAINER target to rescan **immediately on change**
(git push / image update) instead of waiting for the next interval.

## Docker (development stack)

Copy `.env.example` → `.env` first. Host ports are offset so another project can keep Postgres `5432`, Redis `6379`, and Neo4j `7687`.

```bash
cp .env.example .env
docker compose up --build
```

http://localhost:8088 (nginx → API + dashboard).  
Postgres `55432`, Redis `56379`, Neo4j Browser `57474` (`neo4j` / `cryptoscan`).  
Leave `NEO4J_URI` empty in `.env` when you run `bash scripts/run_stack.sh` so CryptoScan does not touch the other project's Bolt port.

If a previous `compose up` died mid-start:

```bash
docker compose down
git pull origin arena/01a034cc-cryproscan
docker compose up --build
```

Neo4j must not bind-mount `infra/neo4j/init` onto `/import` (the image `chown`s that directory and exits if the mount is read-only). Constraints are applied by `cryptoscan-neo4j-init` after Bolt is up.

## Production

Use a dedicated host. Do **not** run the production overlay on a laptop that already owns `:80`.

```bash
cp .env.production.example .env
python3 scripts/hash_admin_password.py    # ADMIN_PASSWORD_HASH
openssl rand -hex 32                      # SECRET_KEY
openssl rand -hex 24                      # GITHUB_WEBHOOK_SECRET
# set POSTGRES_PASSWORD, NEO4J_PASSWORD, CORS_ORIGINS
bash scripts/deploy_prod.sh -d
```

Details: `docs/admin-guide/production.md`.

The API refuses to start in production if demo secrets, SQLite, or `CORS_ORIGINS=*` are still configured. Postgres/Redis/Neo4j are not published on the host.

## Development credentials

| Item | Value |
|---|---|
| Username | `admin` |
| Password | `cryptoscan` |
| SQLite (dev) | `./data/cryptoscan.db` |
| Queue | `cryptoscan:jobs:queue` |

These defaults are rejected when `ENVIRONMENT=production`.
