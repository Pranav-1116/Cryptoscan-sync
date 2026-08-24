# Run CryptoScan

Part 1 is a complete local loop: **scan Java → hash evidence → store → normalize → evaluate 4 baseline policies → optional drift → REST API → dashboard**.

## Local (this sandbox / a laptop)

```bash
python3 -m pip install -r requirements.txt
export CRYPTOSCAN_ROOT=$PWD
export PYTHONPATH=$PWD/shared/shared_config:$PWD/shared/shared_logging:$PWD/shared/shared_models:$PWD/services/api:$PWD/services/database:$PWD/services/scanner:$PWD/services/evidence:$PWD/services/normalization:$PWD/services/policy:$PWD/services/drift:$PWD/services/worker
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

## Docker (Postgres + Redis + API + worker + nginx)

```bash
docker compose up --build
```

Then http://localhost (nginx → API + dashboard).

## Default credentials

| Item | Value |
|---|---|
| Username | `admin` |
| Password | `cryptoscan` |
| SQLite (dev) | `./data/cryptoscan.db` |
| Queue | `cryptoscan:jobs:queue` |

Policy is never decided by AI. Fail/pass comes from YAML in `services/policy/rule_definitions/baseline/`.
