# Installation

## Development

1. Python 3.11+
2. `pip install -r requirements.txt`
3. Copy `.env.example` to `.env`
4. `python scripts/seed_demo.py`
5. `bash scripts/run_api.sh`

SQLite is the default. Leave `REDIS_URL` empty to run jobs in-process.

Docker on a laptop (isolated host ports):

```bash
cp .env.example .env
docker compose up --build
```

Dashboard: http://localhost:8088 — development login `admin` / `cryptoscan`.

## Production

Do not use `.env.example` as-is. Follow `docs/admin-guide/production.md`.

```bash
cp .env.production.example .env
python3 scripts/hash_admin_password.py
bash scripts/deploy_prod.sh -d
```

Set `SECRET_KEY`, `ADMIN_PASSWORD_HASH`, `GITHUB_WEBHOOK_SECRET`, `POSTGRES_PASSWORD`, `NEO4J_PASSWORD`, and an explicit `CORS_ORIGINS` list from a secrets manager. Never ship the development defaults.
