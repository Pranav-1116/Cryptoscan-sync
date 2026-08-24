# Installation

## Development

1. Python 3.11+
2. `pip install -r requirements.txt`
3. Copy `.env.example` to `.env`
4. `python scripts/seed_demo.py`
5. `bash scripts/run_api.sh`

SQLite is the default. Leave `REDIS_URL` empty to run jobs in-process.

## Production

Use `docker compose up --build`. This starts Postgres 15, Redis 7, the API, the worker, and nginx on port 80.

Set `SECRET_KEY`, `ADMIN_PASSWORD`, `GITHUB_WEBHOOK_SECRET`, and `DATABASE_URL` from a secrets manager. Never ship the development defaults.
