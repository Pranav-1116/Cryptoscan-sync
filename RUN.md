# Run CryptoScan

Part 3 extends the local loop: **scan Java/Python/JS/C#/Go/PHP/Ruby/Rust → container + IaC + local certs → hash evidence → store → normalize → evaluate baseline + PCI/NIST/CNSA/FIPS/HIPAA (scoped) → dedupe assets → Neo4j (or in-process) blast-radius / business context / quantum HNDL → REST API → dashboard**.

## Local (this sandbox / a laptop)

```bash
python3 -m pip install -r requirements.txt
export CRYPTOSCAN_ROOT=$PWD
export PYTHONPATH=$PWD/shared/shared_config:$PWD/shared/shared_logging:$PWD/shared/shared_models:$PWD/services/api:$PWD/services/database:$PWD/services/scanner:$PWD/services/evidence:$PWD/services/normalization:$PWD/services/policy:$PWD/services/drift:$PWD/services/worker:$PWD/services/deduplication:$PWD/services/cbom:$PWD/services/container_scanner:$PWD/services/network_scanner:$PWD/services/cloud_scanner:$PWD/services/graph_engine:$PWD/services/business_context:$PWD/services/quantum:$PWD/services/remediation:$PWD/services/reporting
python3 scripts/seed_demo.py
bash scripts/run_api.sh
```

Open the app, sign in with **`admin` / `cryptoscan`**, and inspect the seeded scan of `demo/vulnerable-app`.

From a scan detail page you can **Verify chain**, **Export CBOM** (CycloneDX 1.5), and **Export JSON**.

```bash
make test    # per-service pytest (avoids shared `tests` package clash)
make api     # dashboard + API on :8000
```

Trigger another scan from the UI with:

```
local://demo/vulnerable-app
```

## Docker (Postgres + Redis + Neo4j + API + worker + nginx)

```bash
docker compose up --build
```

Then http://localhost (nginx → API + dashboard). Neo4j Browser is http://localhost:7474 (`neo4j` / `cryptoscan`). Leave `NEO4J_URI` empty in `.env` to keep the in-process graph.

## Default credentials

| Item | Value |
|---|---|
| Username | `admin` |
| Password | `cryptoscan` |
| SQLite (dev) | `./data/cryptoscan.db` |
| Queue | `cryptoscan:jobs:queue` |

Policy is never decided by AI. Fail/pass comes from YAML in `services/policy/rule_definitions/`. Advanced standards apply only when a finding carries matching `compliance_scopes`.
