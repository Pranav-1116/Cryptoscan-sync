# Installation

## Development

1. Python 3.11+
2. Python 3.11 locked environment: `python -m pip install -r requirements.txt -c requirements.lock.txt`
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

## Controlled production installation

Do not promote `.env.example` or the development Compose stack unchanged. Use
[operator install/upgrade/recover](../runbooks/operator-install-upgrade-recover.md)
for the reviewed local-source/v1 topology, external regional PostgreSQL,
verified-TLS Redis, isolated parser and exact immutable package inputs. Apply the
full migration chain through **0105** and coordinate API/worker/frontend/shared
models. Never truncate monitor history to force 0105 downgrade.

Provision secrets, CA bundles, permissions, regional storage and actual site
qualification through the approved operator/customer process. Legacy
[Compose production examples](production.md) do not establish that qualification.
The manual unsigned release preflight does not publish or install this package.

## Execution and replay upgrade (2026-10-21)

Production also requires verified TLS Redis with named ACL credentials and a
mounted CA bundle; a plain Compose Redis URL is not sufficient. Optional
Sentinel covers realtime/current-run clients, not all Redis consumers. Review
[production configuration](production.md) before launching the example above.

Both queued and inline/background jobs require persisted current authority;
legacy unpinned work must be approved and resubmitted, not backfilled from old
usernames. Follow the [upgrade runbook](../runbooks/execution-and-replay-upgrade.md).
Development memory replay is bounded/non-durable; production primary changes
require explicit cursor resynchronization.
