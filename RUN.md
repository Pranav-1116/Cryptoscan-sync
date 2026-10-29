# Run CryptoScan

CryptoScan's evidence path is **authorized collection → hash evidence → store → normalize → evaluate policy → REST API → console**. Local development availability does not qualify a production deployment.

Policy is never decided by AI. Fail/pass comes from YAML in `services/policy/rule_definitions/`.

## Local development (not production)

Provision PostgreSQL, Redis, the API, worker, and existing console on loopback:

```bash
# Privately supply LOCAL_DB_PASS, LOCAL_SECRET_KEY, LOCAL_WEBHOOK_SECRET and
# LOCAL_ADMIN_PASS from an operator-controlled secret store before first startup.
# Keep them available for restarts; the launcher neither records nor prints them.
bash scripts/run_local_stack.sh up
bash scripts/run_local_stack.sh status
```

Open `http://127.0.0.1:3003`. There is **no preset administrator password** in
this launcher. Bootstrap requires an empty users table; public registration alone
cannot grant scan privileges. A working console and daemon heartbeat are not
proof of collection: the inventory remains empty until an approved real scan
retains evidence. An isolated legacy API-only runner exists as `scripts/run_stack.sh`;
do not use its development defaults as product credentials.

```bash
make test    # per-service pytest (avoids shared `tests` package clash)
make api     # frontend :3003 + API :8010
```

Trigger a scan of the bundled sample with `local://<authorized-source>`.

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

The API refuses production startup with demo secrets, SQLite, wildcard CORS or
an unusable required realtime journal. Provision a named non-default Redis ACL
user, `rediss://`, hostname-valid certificates and an approved CA bundle mounted
inside the API container. Startup tests actual journal commands, not just PING.
The edge TLS overlay does not configure Redis TLS; the checked-in Compose Redis
service is not automatically a verified TLS/Sentinel deployment.

Optional `REDIS_SENTINELS`/`REDIS_SENTINEL_MASTER` and dedicated discovery
credentials apply to realtime/current-run factory clients, not every worker
queue or rate-limit consumer. Review each consumer before starting. Follow the
[coordinated upgrade runbook](docs/runbooks/execution-and-replay-upgrade.md),
including resubmission of unpinned legacy work. Postgres/Redis/Neo4j are not
published on the host by the production overlay.

## Running the estate continuously (24/7)

A schedule row is not a scheduler: without something calling it, the estate is
last week's coverage with no error anywhere. Start the loop and check it:

```bash
# Bank admin terminal: first authenticate to the bank-owned API (or set a private
# CRYPTOSCAN_SERVER / CRYPTOSCAN_TOKEN from an approved session).
cryptoscan schedule add nightly --every 6h --plane STATIC  # bank API, stored evidence only
# Bank server service, not the admin workstation:
cryptoscan serve                                           # daemon (SIGTERM = clean stop)
cryptoscan serve --once                                    # one cycle, for cron/systemd-timer installs
curl -s -H "Authorization: Bearer ${CRYPTOSCAN_SESSION_TOKEN:?}" \
  http://127.0.0.1:8010/api/v1/estate/evidence/realtime | jq '{verdict, daemon: .daemon.liveness}'
```

This cadence reads **persisted evidence**. It does not clone source, probe a network,
contact a cloud/HSM, or authorize any new collection. Acquire evidence through its
separately approved collector before treating a scheduled projection as coverage.
The operator CLI uses the bank-owned HTTPS control plane; schedule mutations
require a current human session with monitor-management authority. The daemon
runs on a bank server with database access. Deletion is refused because it
would cascade into historical run receipts; pause instead.

`cryptoscan serve` claims due schedules with a database lease (so several
replicas, or a daemon plus a manual `tick`, never double-run), publishes
`estate.run.*` / `estate.change.detected` on the SSE stream, and compares every
run with the previous one. Down-time produces one catch-up run, not a queue; a
failed run is recorded and does not stop the loop.

Two deployment options are checked in: the `estate-daemon` Compose service, and
`k8s/app/31-estate-daemon-deployment.yaml` (two replicas, liveness probe reading
the heartbeat). For a single process, `ESTATE_REALTIME=1` runs the same loop
inside the API.

The realtime endpoint is the answer to "is it running, and is anything being
scanned": `LIVE`/`STALE`/`STOPPED`/`NEVER_STARTED` for the daemon, plus
`IDLE_NO_SCHEDULES` (alive, nothing scheduled — nothing is being re-scanned) kept
distinct from `WAITING` and `NOT_RUNNING`. A live API process is never treated as
proof of coverage.

## Identity and deployment boundary

Do not copy example or legacy development credentials into an operational estate.
Provision a distinct administrator through the reviewed bootstrap path, store only
password hashes in CryptoScan, and use a current human session for schedule changes.
Production requires the controlled deployment profile, approved source/runtime
isolation, independent evidence and a passing site-specific release gate; a local
`ENVIRONMENT=development` stack is not a production qualification.
