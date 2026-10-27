# Read-only notification receipt inspection

Round 86, 2026-10-18. Locally implemented; not a live-provider, scheduler uptime,
PostgreSQL or production-readiness qualification.

## Why this exists

Durable receipts and an optional scheduler do not help an operator diagnose a
backlog if the only way to see counts is to **send another batch**. The
notification center now has an independent read-only receipt view, available
before any dispatch, plus a metadata-only paginated ledger. Refreshing,
filtering or navigating does not enqueue, claim, retry, reconcile, delete or
acknowledge a delivery. Inspection statements disable ORM autoflush too, so
unrelated uncommitted receipt work is neither flushed nor presented as a
durable acknowledgement.

This does not choose a resend policy for `legacy_unknown`, erase suppression
history, or add a force-redrive button. SMTP, retention/redrive policy and
scheduler liveness measurement remain separate gaps.

## API and authorization

Both reads require authenticated **admin, superadmin or CISO** authority under
the existing authentication/tenant resolution and middleware policies:

- `GET /api/v1/notifications/delivery-summary`
- `GET /api/v1/notifications/deliveries?limit=25&status=failed&cursor=...`

Ordinary/readonly access is not widened. Every query requires **both** the
exact current `tenant_id` and its `scope_key`. Platform is NULL-owner/platform
only, not a cross-tenant roll-up. Operational reads do not inherit platform
receipts through the general ORM's NULL-reference readability. No tenant/owner
request parameter can select a different estate.

### Summary semantics

`counts` includes pending, inflight, delivered, failed, skipped and
legacy_unknown, including zero counts for an observed empty ledger. `total`
counts destination receipts, **not unique events**. `pending` is the sum of
pending/inflight/failed/skipped. `oldest_pending_at` is the oldest creation time
among those receipts, or null when none exist.

`time_eligible` counts due pending/failed/skipped receipts plus inflight claims
whose lease has expired. `expired_claims` counts the latter subset. These are
**clock predicates**, not a claim that a send will occur: routing, disabled or
deleted/reclassified destinations, a stopped/disabled scheduler, concurrency
and other policy can still defer them. No liveness/healthy conclusion is made.
`observed_at` timestamps the read; it is not a heartbeat or successful send.

A `delivered` receipt establishes recorded HTTP 2xx acknowledgement only, not
provider ingestion, a ticket, a human response, or exactly-once delivery.
Unknown historical outcomes remain unknown and suppressed. An empty ledger is
not proof that every retained source event has a receipt or was delivered.
Reads do not reconstruct legacy settings/audits; existing data requires the
reviewed migration handoff described in the receipt operations guide.

### Ledger projection and pagination

The endpoint selects only receipt/event/integration IDs, channel/class, state,
claim count, creation/ack/retry/lease-expiry times, HTTP status, a `has_error`
boolean and time eligibility. It **does not fetch an envelope** or return
payloads, event details, endpoint URLs, transport error text, response bodies,
lease tokens or delivery keys. Existing transport audit APIs/retention are a
separate controlled-data surface, not newly exposed here.

`attempt_count` counts claims since this ledger implementation. Imported
successful historical receipts can have zero new claims; zero is not proof no
old transport request occurred. Retry time is omitted for delivered/unknown
history, and lease expiry is shown only for inflight work. An expiry timestamp
does not prove a process is alive. Missing acknowledgement time is not invented.

Pages are newest-**created** first using `(created_at, id)` descending, with a
1–100 limit (default 25). Status filtering happens before LIMIT. UUIDs are only
a deterministic tie-breaker, never a claimed temporal event cursor. Updating a
retry time does not reorder receipt creation history. One extra row determines
whether a next cursor exists; no unbounded receipt array is returned.

The versioned base64url cursor binds estate, filter, timestamp and ID. It is a
navigation hint, **not a signed authorization token**; editing it cannot remove
the independent exact-estate SQL predicate. Invalid scope/filter bindings or cursor parsing return a generic 422 without
echoing the cursor. Framework query-bound/type validation also returns standard
422 validation details; cursors are navigation metadata, not secret tokens. Refresh from
the newest page after an invalid/stale cursor. This is not a frozen database
snapshot: concurrent inserts may appear only after refresh, and status changes
can move records between filtered views. Counts and pages are separate reads. SQLite additionally resolves a cursor's anchor within the exact
estate to preserve server-default timestamps that omit fractional seconds;
normalizing those to a different text spelling must not repeat pages. An
unavailable/deleted SQLite anchor requires a refresh (422), not an unscoped
lookup. PostgreSQL uses native timestamp comparisons.

## Notification center behavior

The new **Durable delivery receipts** panel shows counts and a bounded page
without invoking dispatch. It provides state filtering, older-page navigation,
return-to-newest and a read-only refresh. A dispatch completion/failure also
refreshes inspection from the newest/all-states view, so an ambiguous send does
not leave the old pre-dispatch count displayed indefinitely.

A changed page/filter remounts its request; old rows are hidden while loading,
and late replies to the old view cannot overwrite the selected view. Unavailable
counts/rows say **not measured**, not zero/healthy or "no receipts". A genuinely
empty observed result says it does not establish delivery completeness.
`legacy_unknown` is explicitly distinct from HTTP acknowledged. No green
scheduler-liveness/ingestion verdict is synthesized from these counts.

## Schema and rollout

Apply Alembic through **0097**, the repository head for this slice, before
starting production API/worker/scheduler processes. Migration 0096 owns the
receipt/legacy-history handoff; 0097 adds only
`ix_notification_deliveries_inspection(scope_key, created_at, id)` for keyset
reads. No receipt, envelope, lease, acknowledgement or deduplication key is
changed. Existing migration-head gates still fail closed when behind.

0097 downgrade removes only the index and preserves a populated ledger;
0096's refusal to discard receipt/scoped-routing authority remains unchanged.
Plan/rehearse index construction on large deployments: this is a standard
index build, **not PostgreSQL CONCURRENTLY**, and can block writers. Aggregate
summary reads still scan the selected estate's receipt metadata; neither the
index nor bounded page size proves constant-cost counting or load qualification.
No deployment schema was migrated by this implementation task.

## Remaining work and assurance boundary

Tests use real SQLite sessions/migrations and API authentication plus mocked
frontend requests. They cover platform/tenant exactness amid unrelated traffic,
status/time predicates, tied-timestamp keyset traversal, cursor tampering and
validation, safe column projection, absence of ledger mutations/sends, role
refusals, index rollback with existing receipts, and UI loading/error/empty/
filter/navigation/late-response behavior.

These are not positive PostgreSQL or real provider observations. Scheduler
heartbeat/liveness, receiver ingestion/deduplication, customer rollout,
crash/clock-skew/load qualification, SMTP, explicit unknown-history redrive and
retention remain open. See [receipt delivery](notification-delivery.md) and
[opt-in scheduling](notification-scheduler.md).

## Toolchain advisory follow-up

This section records the R86 baseline. [R87 toolchain hardening](frontend-toolchain-security.md)
subsequently qualified compatible upgrades and a fresh zero-advisory lock;
that later evidence supersedes the advisory backlog here, not these historical
R86 test/audit observations.

Dependency installation/audit in this slice reported **8 existing development
toolchain advisories** (3 moderate, 2 high, 3 critical), involving Vitest/coverage/
tinypool, Vite/vite-node/esbuild and source-map-js. The production-dependency-only
`npm audit --omit=dev` reported **0 advisories**, not a security certification.
Remediation includes major Vite/Vitest upgrades and needs its own compatibility
regression slice; no blind `npm audit fix --force` or lockfile rewrite was
applied here. Do not treat successful test/build output as closing these
advisories or expose a vulnerable development/test server as production.

## Observed local evidence — 2026-10-18

- Final backend: **2,321 passed, 17 skipped, 8 live deselected**, 105 warnings,
  144.88s (`/home/user/receipt-inspection-qualified.{log,xml}`). Five full roots
  (database, control-plane, worker, DevSecOps, shared models) plus 15 related API
  notification/tenant/RBAC/quota/webhook/delivery/security files; **not** all
  54 suites or the full API suite. Included new inspection cases: **26** service,
  **1** populated-index migration rollback and **3** authenticated API cases.
  The final focused inspection lane separately passed **30** tests.
- Frontend: **344 tests / 36 files passed**, 91.12s; TypeScript and production
  build passed (`/home/user/receipt-frontend-final.log`). Includes six focused
  receipt-view cases and the existing notification/page-smoke coverage.
- Scoped Ruff, `pip check`, tenant inventory audit (**116 scoped / 12 platform
  tables, 1 explicit opt-out**), scoped whitespace and migration workflow
  YAML/embedded-shell checks passed. The workflow now includes the index-only
  populated rollback test; a definition is not a successful observed GitHub run.
- The interrupted/superseded broader runs are not used as final qualification.
  The final fresh run includes both no-autoflush and SQLite server-default
  timestamp pagination regressions. No positive PostgreSQL/Compose/provider
  runtime or deployment proof was acquired.
- Fresh npm audit again reported **8 development-toolchain advisories** and
  **0 production-only advisories**. These remain separate upgrade work, not
  closed by the passing tests/build.
