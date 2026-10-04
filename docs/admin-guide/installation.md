# Installation

## Development

1. Python 3.11+
2. `pip install -r requirements.txt`
3. Copy `.env.example` to `.env`
4. Start the empty stack with `bash scripts/run_stack.sh`; no source data is seeded.
5. `bash scripts/run_api.sh`

SQLite is the default. Leave `REDIS_URL` empty to run jobs in-process.

Docker on a laptop (isolated host ports):

```bash
cp .env.example .env
docker compose up --build
```

Dashboard: http://localhost:8088 — development login `admin` / `cryptoscan`.

If the API logs `could not translate host name "postgres"`:

- That hostname exists only on the Compose network `cryptoscan-net`. Docker’s
  restart policy can start `cryptoscan-api` before Postgres has joined DNS.
- Recreate on one network: `docker compose down && docker compose up --build`.
- Do not start `docker-compose.prod.yml` without `docker-compose.yml`.
- A process on the laptop must use `127.0.0.1:55432`, not `postgres`.

## Production

Do not use `.env.example` as-is. Follow `docs/admin-guide/production.md`.

```bash
cp .env.production.example .env
python3 scripts/hash_admin_password.py
bash scripts/deploy_prod.sh -d
```

Set `SECRET_KEY`, `ADMIN_PASSWORD_HASH`, `GITHUB_WEBHOOK_SECRET`, `POSTGRES_PASSWORD`, `NEO4J_PASSWORD`, and an explicit `CORS_ORIGINS` list from a secrets manager. Never ship the development defaults.
