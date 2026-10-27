# Opt-in notification scheduler

Round 85, 2026-10-17. Local implementation; **not a deployed/qualified
notification service**. This closes the automatic-drain implementation gap
left in round 84. SMTP remains unimplemented in this notification path.

## Purpose and boundaries

`scripts/run_notifications.py` runs a dedicated process which periodically calls
the durable webhook/SIEM receipt drain. It is not attached to the scan worker,
Redis consumer maintenance callback, API request loop or monitor leader lease.
Slow receivers therefore do not occupy scan-worker slots or monitor ticks.

Automatic sending is **off by default**, with no default tenant or platform
selection. Enabling a daemon does not opt newly created tenants into delivery.
The deployment operator must explicitly select registered active tenant UUIDs
and/or the platform estate. The existing routing matrix and integration enabled
flags still apply. **Review destinations, routing, retained-journal backfill and
legacy-history limitations before enabling any estate.** This authorizes real
outward sends; it is not a dry-run command.

See [durable notification delivery](notification-delivery.md) for migration
0096, stop-old-writer handoff, legacy unknown suppression, ambiguous historical
ownership and receiver deduplication requirements. There is no new migration in
round 85. Existing datasets must be migrated before running the scheduler; do
not use development create_all as a production history handoff.

## Configuration

The scheduler reads environment variables / `.env`, using its own settings
schema rather than requiring scanner images, Redis or Neo4j credentials.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NOTIFICATION_DISPATCH_ENABLED` | `false` | Explicit process-wide opt-in |
| `NOTIFICATION_DISPATCH_PLATFORM` | `false` | Include platform-exact, NULL-owned events/receivers |
| `NOTIFICATION_DISPATCH_TENANTS` | `[]` | JSON array of up to 1,000 distinct registered tenant UUIDs; never `all` |
| `NOTIFICATION_DISPATCH_REGION` | empty | Declared worker processing region; required when selecting tenants |
| `NOTIFICATION_DISPATCH_INTERVAL_SECONDS` | `30` | Interruptible wait **after** a tick, 1–3,600 seconds |
| `NOTIFICATION_DISPATCH_BUDGET_SECONDS` | `20` | Whole-tick soft budget, 0.1–120 seconds |
| `NOTIFICATION_DISPATCH_SCOPE_BUDGET_SECONDS` | `5` | Per-estate soft budget, 0.1–30 seconds and not greater than tick budget |
| `NOTIFICATION_DISPATCH_MAX_SCOPES` | `10` | Maximum estates visited in one tick, 1–100 |
| `NOTIFICATION_DISPATCH_LIMIT` | `50` | Per-estate destination-pair enqueue/attempt bound, 1–200 |
| `DATABASE_URL` | development file SQLite | Shared receipt database; PostgreSQL required in production |
| `ENVIRONMENT` | development | Set `production` for production migration enforcement |

Non-finite/zero/invalid bounds, duplicate UUIDs, enabled-without-estates and
missing tenant processing region fail validation. SQLite memory databases are
refused: a scheduler restart must not erase its delivery authority. Production
refuses SQLite and unsupported database dialects. Database URLs are redacted
from settings repr/redacted output; error logs do not repeat exception text,
event details, endpoints or credentials.

Each selected tenant is reloaded before its drain, not cached across ticks. It
must exist and be active. The configured region must match an entry in its
`processing_regions`; if that field is unspecified, `data_residency_region` is
the allowed region. Empty/malformed policies fail closed. Region matching is
case/whitespace normalized, not a geographical-prefix approximation. A blocked
scope is reported, not silently treated as delivered.

**This checks declared configuration, not the physical location of a process.**
Operators still need actual infrastructure/residency proof. This is not a new
universal region gate for every manual API/collector path. A policy change or
shutdown cannot undo an HTTP request already in progress.

## Running

Use the repository's normal Python dependency/import setup. The script uses the
canonical bootstrap and works without an ambient PYTHONPATH.

For an explicitly authorized **platform-only** development estate, after
reviewing routing/receivers:

```bash
export NOTIFICATION_DISPATCH_ENABLED=true
export NOTIFICATION_DISPATCH_PLATFORM=true
export NOTIFICATION_DISPATCH_TENANTS='[]'
python scripts/run_notifications.py --once
# Or run continuously under the deployment's process supervisor:
python scripts/run_notifications.py
```

For tenant operation, set platform selection false unless it is separately
intended. Set `NOTIFICATION_DISPATCH_TENANTS` to the approved registered tenant
UUID array and `NOTIFICATION_DISPATCH_REGION` to the approved declared region.
Do not paste receiver/SMTP/vault credentials into this command or chat. The
existing integration transport resolves its configured secret references in
the **scheduler process**, so its approved secret environment must be supplied
separately. The scheduler service does not inherit arbitrary API secrets by
copying the entire API environment.

One-shot mode permits **exactly one estate**. It performs one bounded tick, not
a complete backlog drain. For repeated cron invocations select one estate per
job; a multi-estate one-shot always restarting at the first scope could starve
later scopes, so it is rejected before opening a database. Use the long-running
daemon for multi-estate round-robin scheduling.

Exit codes: `0` for a successful one-shot tick or graceful daemon shutdown;
`1` for a one-shot with blocked/failed/unconfirmed outcomes or an observed stop;
`2` for disabled/invalid/startup-failed configuration. A successful empty tick
means only that the selected scope ran without a reported error, **not** that
all retained events were delivered or a receiver is healthy.

### Optional Compose service

The base and production overlay include a separate `notifications` service,
under the **notifications profile**. It is not started by the default stack.
After configuring opt-in and estates and completing the migration handoff:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --profile notifications up --build -d notifications
```

Production waits for the migration job and verifies the database head itself.
The service has no Redis/Neo4j dependency or public port, runs as the existing
unprivileged worker image user, drops capabilities and has no-new-privileges.
Startup failures retry at most three times instead of turning a disabled or
invalid configuration into a permanent crash loop. It must share the same
**authoritative** receipt database as manual drains/other replicas; independent
or asynchronously replicated writable ledgers do not provide mutual exclusion.
Compose YAML/tests are not evidence that an image was built or this service ran.

## Fairness, transactions and shutdown

The process visits the explicit estate list in round-robin order, advancing its
cursor **before** attempting a scope. A busy/poison estate, DB failure or budget
overrun cannot pin every later tick to that estate. Each tick visits at most
one round and the configured maximum number of scopes. A failed scope closes
its session and does not kill subsequent scheduled ticks.

A fresh session and tenant context is used per estate, with context restored on
success, block, error and stop. A tenant-context caller cannot invoke the loop
to silently elevate to the platform. No shared ORM identity map crosses estates.
The cursor is process-local: restarts reset it, and pathological repeated
restarts can still starve later scopes. This is not a durable distributed
fairness/global throughput quota.

Receipt leases and stable Idempotency-Key, not daemon leadership, protect
ordinary overlapping manual/daemon/replica attempts. Two daemon processes can
run, but this does **not** prove multi-replica production qualification. Existing
120-second leases, fenced completion, per-destination backoff and at-least-once
ACK/crash ambiguity are unchanged. A receiver must deduplicate ambiguous retries.

SIGINT/SIGTERM set a stop event and interrupt the between-tick wait. No further
scope is started after observing stop. The drain also checks stop between
destinations and immediately before HTTP. A claimed but unsent receipt remains
inflight until its committed lease expires; a stopped process does not invent a
success or erase the claim. If stop arrives during HTTP, the attempt's outcome
is finalized/audited before exiting, rather than discarding a possible ACK.

Budgets/timeouts are **soft**, not hard DNS/network or termination deadlines.
The final transport attempt can outlast the budget. Configure supervisor grace
and crash recovery accordingly; a forced kill still relies on lease expiry and
receiver idempotency. Clock synchronization/latency bounds need qualification.

## Observability and validation

Each tick logs only bounded numeric/boolean summaries: scopes attempted,
completed, blocked, failed/unconfirmed, destination attempts, enqueues,
transport outcomes and lease loss. `observed_pending_receipts` and
`observed_legacy_unknown` summarize the **visited** scopes, not a global estate
backlog or a delivered/ingested proof. Empty/disabled/blocked is not a positive
notification readiness result. There is no new scheduler health endpoint or
production uptime/load evidence in this slice.

Tests use real SQLite databases and fake HTTP, covering allowlisting/exact
scope, region/active checks, independent sessions/context restoration,
round-robin budget/failure behavior, persisted retry backoff without early
resend, repeated scheduler instances sharing receipt authority, stop before
work/after claim/during transport, CLI exit/signal/disposal behavior, production
configuration/migration gate and an enabled one-shot empty-database subprocess.
The latter is a CLI/bootstrap smoke, **not** a delivered notification.

Remaining qualification: positive PostgreSQL and Compose/image runtime,
provider ingestion/deduplication, forced-crash/clock-skew/load behavior,
secret/environment provisioning, supervisor operation and customer field data.
SMTP transport, unknown-history redrive/retention and broader cached-read/
relationship authorization review remain open. Nothing was deployed or
externally sent to a notification receiver by these tests.

### Observed local evidence

Final regression: **2,291 passed, 17 skipped, 8 live deselected**, 97 warnings,
180.18s (`/home/user/notification-scheduler-final.{log,xml}`). This includes five
full test roots (database, control-plane, worker, DevSecOps, shared models) and
14 related API notification/tenant/RBAC/quota/webhook/delivery/security files,
not all 54 suites or the complete API suite. Included: **44 scheduler tests**,
**26 receipt tests** (three new shutdown cases) and **26 ABAC/transport tests**
(two new log-redaction cases). The enabled CLI subprocess uses an empty,
disposable SQLite database; receiver attempts are fake HTTP in the unit tests.

Ruff (`services scripts shared`), dependency consistency and tenant inventory
audit (**116 scoped / 12 platform tables, 1 explicit opt-out**) passed.
Compose profile/production-migration dependencies are YAML contract-tested,
not Docker-validated: Docker/Compose is unavailable here. No positive live
PostgreSQL/receiver proof or frontend revalidation was performed in this
backend-only slice. The previous round's frontend result remains historical,
not a new browser/production proof.

## Receipt inspection (round 86)

A read-only count/page view is now available independently of sending. It does
not establish that this scheduler is alive; receipt backlog/time eligibility
is not a heartbeat. This build's head is 0097 (index-only inspection extension
after the 0096 receipt handoff). See
[receipt inspection](notification-inspection.md) for metadata/role/estate
boundaries and the standard-index construction caveat.
