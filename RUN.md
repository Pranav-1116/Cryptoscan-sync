# Run CryptoScan

CryptoScan's evidence path is **authorized collection → hash evidence → store → normalize → evaluate policy → REST API → console**. Local development availability does not qualify a production deployment.

Policy is never decided by AI. Fail/pass comes from YAML in `services/policy/rule_definitions/`.

## Local development (not production)

Provision PostgreSQL, Redis, the API, worker, and existing console on loopback:

```bash
# Privately supply absolute LOCAL_DB_PASS_FILE and LOCAL_APP_PASS_FILE (0600),
# distinct LOCAL_SECRET_KEY and LOCAL_WEBHOOK_SECRET (32+ characters each), and optional
# LOCAL_ADMIN_PASS from an operator-controlled secret store before startup.
# Keep them available for restarts; there are no built-in secret defaults.
# Existing data volumes require LOCAL_REUSE_VOLUME=1 after inspection;
# running named containers require LOCAL_REUSE_RUNNING=1 after inspection.
bash scripts/run_local_stack.sh up
bash scripts/run_local_stack.sh status
bash scripts/run_local_stack.sh tools  # running vs unconfigured backend tools
bash scripts/run_local_stack.sh monitoring-up  # optional real Prometheus, loopback :55909
# With LOCAL_GRAFANA_ADMIN_PASSWORD_FILE in a protected directory:
bash scripts/run_local_stack.sh grafana-up    # optional Grafana, loopback :55910
# With LOCAL_NEO4J_AUTH_FILE=... (protected file containing neo4j/<password>):
bash scripts/run_local_stack.sh graph-up      # staged Neo4j, loopback Bolt :55912
bash scripts/run_local_stack.sh gateway-up    # local NGINX HTTP gateway, loopback :55920
# To wire a running API/worker to that graph, use the same protected core/S3
# variables as `up`, set LOCAL_NEO4J_AUTH_FILE, then run `reload` after jobs
# are idle. The graph remains empty until real retained relationships project.
```

`down` stops only launcher-owned core processes/containers; staged MinIO,
Neo4j, Prometheus, Grafana and the local NGINX process remain running. It never
purges their data. Inspect them individually before any shutdown or deletion.

The core launcher starts PostgreSQL, Redis, API, worker, and console, not all
13 engines in the requested bank architecture. Optional local MinIO evidence
requires `SBOM_S3_ENDPOINT`, `SBOM_S3_BUCKET`, and separate **non-root** access/
secret credential-file paths. The launcher requires a probed S3 bucket by
default; `LOCAL_EVIDENCE_REQUIRED=0` explicitly opts into core-only local
startup without a verified S3 evidence store. The local machine has limited free memory and
heavy swap use: Neo4j, OpenSearch, Kafka, Grafana and monitoring must be staged,
not silently launched as a memory-exhausting bundle. `tools` distinguishes
running services from unconfigured or unverified integrations. Existing volumes
or named processes are never silently removed/reused by `up`.

Open `http://127.0.0.1:3003`. There is **no preset administrator password** in
this launcher. Bootstrap requires an empty users table; public registration alone
cannot grant scan privileges. A working console and daemon heartbeat are not
proof of collection: the inventory remains empty until an approved real scan
retains evidence. An isolated legacy API-only runner exists as `scripts/run_stack.sh`;
do not use its development defaults as product credentials.

```bash
make test    # per-service pytest (avoids shared `tests` package clash)
make api     # frontend :3003 + API :8010

# One command, no Docker: API + console on SQLite (development only)
bash scripts/run_dev_stack.sh          # up; Ctrl-C stops both
bash scripts/run_dev_stack.sh status   # what is listening, and is /ready 200
bash scripts/run_dev_stack.sh down     # stop the stack AND free both ports
bash scripts/run_dev_stack.sh down --force  # also take back a port a stray listener holds
bash scripts/run_dev_stack.sh restart       # down --force, then up
bash scripts/run_dev_stack.sh reset-admin   # set a known admin password (SQLite dev DB)
```

`scripts/run_dev_stack.sh` is the smallest path to a working console: SQLite
instead of PostgreSQL (the same `ALLOW_SQLITE=1` path the tests use), no Redis
and no worker. Consequences, stated because they are easy to misread:

- with no Redis nothing consumes the scan queue, so a submitted scan stays
  `QUEUED` and no evidence appears — a fresh console is an EMPTY estate, and
  every screen is supposed to look empty rather than healthy;
- it bootstraps one admin **only if the users table is empty**, so a generated
  password applies exactly once. If the banner says the password is `UNKNOWN`,
  that database already has an admin and the printed value would not work — run
  `bash scripts/run_dev_stack.sh reset-admin` to set a known one (optionally
  `ADMIN_PASSWORD=... reset-admin`, or `reset-admin <username>`), or `RESET_DB=1`
  to start from an empty database;
- `down` frees the *ports*, not just the launcher pids: `npm run dev` is
  npm → sh → vite and uvicorn can outlive its parent, so the script resolves the
  pid actually holding the socket, and only kills it when the command line shows
  it is this stack. A stranger on :3003 is reported with its pid and left alone
  unless you pass `--force`;
- it is not a qualification deployment. The real local stack (Postgres + Redis
  + worker) is `scripts/run_local_stack.sh`, which needs Docker.

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

Provision bank-owned PostgreSQL, its separate non-superuser runtime role, and a
bank-operated TLS Redis with an ACL identity and trusted CA. Keep actual secrets
in the bank's secret manager, not Git or an image. The reference Compose requires
`CRYPTOSCAN_APP_DATABASE_URL` distinct from the PostgreSQL migration superuser.
It also requires `BACKUP_STORAGE_HOST_PATH` to name an existing, bank-managed
persistent directory writable by the API container's uid 10001. The production
backup endpoints refuse missing/unwritable mounts and unavailable stable keys
instead of writing to `/tmp` or using a process-ephemeral encryption key.
Production restore is disabled until `CRYPTOSCAN_RESTORE_TARGET_DB` designates
an isolated database different from the signed source; the console offers no
one-click restore. Test a real backup and a reviewed restore before treating
this mount as protected recovery. `pg_dump` plus a supplied WAL fragment is
**not** PostgreSQL PITR; that requires a separate physical backup/WAL archive.

```bash
# Bank DBA creates the runtime login first; supply private deployment variables.
bash scripts/deploy_prod.sh --migrate-only
# Bank DBA grants table/sequence permissions and verifies RLS on the runtime role.
bash scripts/deploy_prod.sh -d
```

Details: [bank-owned PostgreSQL runtime role](docs/runbooks/onprem-postgres-runtime-role.md)
and `docs/admin-guide/production.md`. Neither sequence alone is site qualification.

For a separately provisioned, TLS-enabled, **bank-owned** versioned MinIO/S3
bucket, add `docker-compose.s3.yml` after `docker-compose.prod.yml` in the
operator's Compose invocation. Configure the six `SBOM_S3_*` host-path/endpoint
variables in `.env.production.example` with a restricted artifact identity,
never the object-store root identity; supply a trusted bank CA. The overlay
mounts credential files read-only into only the API and worker. Both processes
must address the same bucket. The loopback-only MinIO used for local tests is
not reachable from the Compose network as `127.0.0.1` and must not be passed off
as the production endpoint. A configured backup path and retention period satisfy
only configuration checks: actual independent backup, Object Lock and restore
are separate operator controls, not proven by S3 versioning or this overlay.

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
