# Production deploy

Use this on a **dedicated host**. Do not run the production overlay on a laptop that already binds `:80`, `:5432`, `:6379`, or `:7687`.

## 1. Secrets

```bash
cp .env.production.example .env
python3 scripts/hash_admin_password.py   # paste into ADMIN_PASSWORD_HASH
openssl rand -hex 32                     # SECRET_KEY
openssl rand -hex 24                     # GITHUB_WEBHOOK_SECRET
```

Set `CORS_ORIGINS` to the real dashboard origin (`https://cryptoscan.example.com`).  
Set strong `POSTGRES_PASSWORD` and `NEO4J_PASSWORD`. Leave `ADMIN_PASSWORD` empty when a hash is set.

The API and worker refuse to start if demo secrets, SQLite, or `CORS_ORIGINS=*` are still present.

## 2. Start

```bash
bash scripts/deploy_prod.sh -d
```

Equivalent:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d
```

Never start the overlay file alone. `DATABASE_URL` uses hostname `postgres`, which only
resolves on the Compose network from the base file. If the API logs
`could not translate host name "postgres"`, recreate: `docker compose down && bash scripts/deploy_prod.sh -d`.

Nginx listens on `${NGINX_PORT:-80}`. Postgres, Redis, and Neo4j are **not** published on the host.

## 3. Health

- `GET /health` — process up
- `GET /ready` — database reachable
- `GET /api/v1/meta` — `environment=production`, `docs_enabled=false`

OpenAPI (`/api/docs`) is off unless you set `DOCS_ENABLED=true`.

## 4. What this overlay changes

| Item | Development compose | Production overlay |
|---|---|---|
| `ENVIRONMENT` | development | production |
| Host DB ports | 55432 / 56379 / 57687 | none |
| HTTP | 8088 | 80 (override with `NGINX_PORT`) |
| Admin password | plaintext `cryptoscan` | `ADMIN_PASSWORD_HASH` required |
| CORS | `*` | explicit list required |
| API workers | 1 | 2 |
| Docs | on | off |
| Cookies | insecure | `Secure` |

Development login (`admin` / `cryptoscan`) is rejected in production and is not shown on the dashboard.
