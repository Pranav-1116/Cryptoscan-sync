# Durable notification delivery

Local implementation, 2026-10-17 (rounds 84–85). **Not a production delivery
qualification.** SMTP transport remains open. Round 85 adds a separately enabled
[notification scheduler](notification-scheduler.md); no deployment was started.

## What changed

The manual notification drain previously kept up to 2,000 whole event IDs in
an AppSetting registry. It recorded an event before knowing whether any receiver
accepted it, and used a small recent-journal window. Consequently failures,
air-gap configurations and missing receivers could suppress later delivery;
registry eviction or concurrent drains could send duplicates. Its exactly-once
wording was incorrect.

The drain now uses `notification_deliveries` (migration **0096**): a durable row
per **scope, event, integration and channel**, with a unique identity and stable
64-hex-character `Idempotency-Key`. Delivered receipts are not automatically
pruned. A new receiver can receive an event already delivered to another
receiver while the source journal event is retained. Retries of existing
receipts survive journal retention; new-receiver backfill does not reconstruct
events whose source journal is gone. Missing receivers do not create acknowledgements. Successful receivers
are not retried merely because another receiver failed.

The canonical catalog/routing helper is shared by API and delivery code. Routing
settings use exact namespaces:

- `notification.routing.v1:platform` for the platform estate;
- `notification.routing.v1:tenant:<tenant-id>` for a tenant.

An owner's old unqualified key is read only when no modern row exists, and
moved to that owner's namespace on save. A tenant never inherits platform
operational preferences or events. The platform drain is platform-exact, not a
cross-tenant roll-up. The feed also filters owner and routed event types **before
LIMIT**, so unrelated traffic does not hide mapped notifications. Shared routing
writes and manual dispatch require admin/superadmin/CISO authority; ordinary
read authentication/RBAC is unchanged.

## State, retries and concurrency

| State | Meaning |
| --- | --- |
| `pending` | Enqueued destination, no completed attempt yet |
| `inflight` | An expiring, token-fenced claim is held |
| `delivered` | A transport HTTP 2xx acknowledgement was durably recorded |
| `failed` | Transport/configuration failure; retry after backoff |
| `skipped` | No endpoint configured; not delivered, retry after backoff |
| `legacy_unknown` | Old event-only registry history; automatically suppressed, not a success |

Discovery joins eligible events to enabled, same-owner integrations and excludes
existing destination receipts in SQL before applying the limit. It walks the
retained mapped journal oldest-first, rather than inspecting only the latest
150 rows or treating UUIDs as a temporal cursor. The SIEM channel claims SIEM/SOAR
integration kinds; the webhook channel claims ITSM/CMDB kinds. These channel
partitions do not overlap.

A minimal bounded event-detail snapshot is captured at enqueue (detail truncated
to 2,000 characters). Retry payloads survive journal edits/deletion. Receipts do
not have cascading foreign keys: deleting an event/integration must not erase
past delivery authority. Disabled/deleted/reclassified destinations or routing
switched off defer existing work rather than acknowledging it. Deleted-target
receipts can therefore remain pending indefinitely until an explicit operator
policy is implemented. The receipt is not an encrypted secret vault; source
classification, historical sensitive evidence and retention policy are separate.

Each destination claim is a conditional SQL UPDATE committed **before** network
I/O. Ordinary concurrent drains cannot both claim the same unexpired receipt.
The claim lasts 120 seconds; an abandoned claim can be reclaimed after expiry.
A random fencing token prevents a stale owner overwriting the new owner's
receipt. Neither read nor write transactions are held across network I/O.

The transport performs one HTTP attempt per claim, without sleeping inside the
request. Failed/skipped attempts have persistent exponential backoff from
60 seconds to one hour. A later manual drain or separately enabled scheduler
tick retries due receipts. Automatic operation requires the dedicated opt-in
process; the API/scan/monitor loops do not schedule it implicitly. Routing/destination eligibility is
re-read before attempting a claim. Changes cannot retroactively cancel an HTTP
request already in progress.

`DispatchRequest.limit` is now **destination attempts**, 1–200 (default 50), not
whole events with unbounded fan-out. Enqueue and work selection are bounded by
that limit. The dispatch loop has a 20-second **soft** budget and passes a
10-second timeout to the transport. This is **not** a hard end-to-end DNS/HTTP
or request deadline; a final attempt/DNS lookup may outlast it. Browser timeout
or disconnect is not proof the receiver did not accept a send.

## Delivery authority and unavoidable ambiguity

**At-least-once, never exactly-once.** A receiver can accept a request immediately
before the sender crashes or its database commit fails. The HTTP side effect
cannot be rolled back with the database. After lease expiry the same stable
Idempotency-Key is retried; effective deduplication requires receiver support.
A slow attempt can also outlive its lease; application clock skew can shorten
the effective lease, so clock synchronisation needs operational qualification.
The fencing token protects database state, not arbitrary external side effects.

A receipt update, integration sync status and existing `cp_delivery_logs` audit
commit together. An acknowledged request followed by persistence failure does
not return a fabricated durable success: the API returns a generic 503 and
leaves recovery to the durable claim. A stale-token attempt is audited but its
receipt is marked unconfirmed in the response/UI. A 2xx receipt proves only
transport acknowledgement, not ingestion, ticket creation, human action or a
customer security outcome.

The shared webhook transport now signs **the exact canonical JSON bytes it
transmits**. Previously it signed sorted/compact JSON but sent a different
spaced serialization. Generic HMAC signing, vault-reference secret resolution,
provider shaping and existing URL guards remain in that transport; this slice
does not qualify DNS rebinding, a real SIEM provider or real edge/network policy.
No SMTP credentials, running deployment daemon or outbound receiver was
provisioned. The optional scheduler's local implementation is not an uptime or
provider-ingestion qualification.

The UI explicitly says at-least-once, shows pending and legacy-unknown receipts,
and never concludes that an empty drain means all events were delivered. A
lost receipt fence is shown as unconfirmed, not green delivered. The old
`registry_size` response field is retained for compatibility but now counts
receipts, not unique event IDs; `window` is the number of candidate destination
pairs enqueued. New fields include `receipts`, `enqueued`, `destination_attempts`
and `lease_lost`. `email_routed` only counts attempted outward event groups
whose email toggle is on; it is neither an email backlog nor an SMTP send count.

## Existing-data handoff and rollback

1. **Stop old drains before upgrading.** Mixed old/new drain implementations
   are not a supported rolling-deployment mode. Review registered destinations
   and the retained journal: enabling/adding a receiver can backfill **all
   retained matching events**, bounded per drain call/tick, not just recent events.
2. Back up/rehearse on a disposable copy, then apply Alembic through **0097** for this build (0096 receipt handoff,
   0097 inspection index).
   No migration was applied to a deployment by this implementation task.
3. Successful old `notification.*` delivery audit rows with HTTP 2xx are copied
   into delivered per-destination receipts, including successes evicted from
   the old 2,000-ID registry. Failed/skipped audit rows are not invented as
   successful. Old logs/settings are retained.
4. Old registry IDs become `legacy_unknown` event tombstones within their
   recorded owner scope. They suppress automatic historical replay there even
   if old outcomes were failed/skipped; the
   event-only registry cannot establish per-destination truth. This deliberately
   does not choose an operator resend/disposition policy or offer a force-
   redrive API. Reconcile against provider audits before a later explicit
   redrive mechanism.
5. History already evicted **and** missing successful audit evidence cannot be
   reconstructed. It may replay from retained journal history; the new header
   cannot retrospectively deduplicate old requests sent without that key.
   Old mixed-tenant/shared-NULL history can also have ambiguous ownership; this
   migration preserves recorded owners rather than guessing/reassigning them.
   It cannot guarantee deduplication across earlier cross-scope dispatches.
   Review these limitations before resuming drains.
6. Malformed registry history fails before new-table DDL instead of guessing.
   Existing production datasets must use the migration, not `create_all` as a
   handoff substitute. The runtime additionally imports retained registry IDs
   conservatively for development datasets, but does not replace migration's
   successful-audit backfill.
7. Downgrade refuses to discard nonempty receipts **or scoped routing settings**.
   Empty-schema downgrade/upgrade is supported and tested. Real rollback needs
   a reviewed receipt/settings handoff, not deletion of the deduplication record.

The general SQLAlchemy tenant-insert guard also required correction: plain
`.values(tenant_id='owner')` literals are wrapped in BindParameter and used to be
mistaken for foreign claims. Fixed literal owners now work, with checks for
foreign/dynamic/callable owners, execution-time overrides, parameter-dictionary
inserts and INSERT-from-SELECT. This is tested isolation hardening, not a claim
that every possible SQL construct or all application authorization is certified.
Final review also reproduced and closed a cached-ORM write loophole: flush
UPDATE/DELETE bypasses the Session DML hook. A row loaded before entering a
tenant scope, including a readable platform row, is now checked for exact
ownership before any flush writes. Cached/expired instances, deletes, atomic
rollback of mixed batches and allowed own/unscoped platform writes have 13
regressions; the pre-fix platform-update case demonstrably failed. This is a
write/delete check, not an audit of session reuse/cached reads or every possible
relationship/cascade authorization policy. Other AppSetting namespaces were
not migrated by this slice.

## Validation and remaining qualification

Local tests use real SQLite sessions/connections/migrations with fake HTTP
receivers. They cover retries without resending successful peers, air-gap and
missing/new destinations, >2,000 receipts, bounded fan-out, routing pauses,
immutable retry envelopes, exact tenants, concurrent claims, stale-owner fences,
no open transaction during HTTP, ACK/commit ambiguity, legacy handoff and blocked
unsafe downgrade. Wire-level tests verify HMAC over captured transmitted bytes
and stable/safe idempotency headers. UI tests cover pending/unknown/unconfirmed
states and the absence of an exactly-once claim.

For the opt-in PostgreSQL receipt tests, set `CRYPTOSCAN_TEST_PG_URL` to an
approved test instance with permission to create a temporary schema, then:

```bash
python -m pytest -q -p no:xdist -m live \
  services/database/tests/unit/test_notification_receipts_postgres.py \
  --junitxml=notification-postgres.xml
python scripts/check_junit.py notification-postgres.xml
```

Those tests create/drop **only a unique temporary schema**, never a database.
No configured URL skips visibly; a configured but unreachable/misconfigured
server fails. Skipped/empty proof is rejected by the proof checker. The migration
workflow includes this lane plus SQLite handoff/guard regressions, but populated
workflow YAML is not a successful observed GitHub run.

**Still open:** positive PostgreSQL runtime/migration evidence here, real
signed-receiver/provider deduplication and ingestion, multi-replica/load and
long-running crash/lease-expiry qualification, explicit unknown-history redrive
and retention policy, SMTP delivery, scheduler deployment/runtime qualification
and customer rollout.
No external-readiness category is closed by local tests alone.

### Observed local evidence (round 84 snapshot)

See [notification scheduler](notification-scheduler.md) for round 85's newer
backend validation. Frontend code was not changed in that slice.

- Final backend regression: **2,242 passed, 17 skipped, 8 live deselected**
  in 178.56s, `/home/user/notification-final-safety.{log,xml}`. This covers the
  database, control-plane, worker, DevSecOps and shared-model test roots plus
  14 related API notification/tenant/RBAC/quota/webhook/delivery/security files.
  It is **not** an all-54-suite or full-API certification. The earlier broad
  six-root/full-API run was stopped as superseded, not counted as passing.
- Included new receipt tests: 23; migration handoff/rollback: 4; tenant bulk
  literal/parameter guards: 13; cached-write/delete guards: 13. Separate focused
  insert/cache checks: **26 passed**. Existing signed-wire and API suites also
  cover the new protocol and permission contracts.
- Full frontend: **337 tests / 35 files passed** in 113.21s. After a final
  duplicate-word copy fix: all **8 notification tests**, TypeScript check and
  production build passed again (`/home/user/notification-copy-final.log`).
- Scoped Ruff, dependency consistency, tenant-isolation inventory audit and
  migration workflow YAML/embedded-shell parsing passed. The audit inventory
  is not an exhaustive runtime authorization proof.
- PostgreSQL receipt proof: **2 skipped**, with no configured URL. The required
  JUnit proof checker correctly **rejected** those skips. No positive live
  PostgreSQL, Docker, SMTP or external receiver result is claimed here.

## Read-only inspection (round 86)

Counts and metadata-only keyset receipt pages can now be inspected without
triggering another drain. The notification center exposes this through a
separate read-only panel; unavailable results stay not measured and unknown
history stays distinct from acknowledgements. Apply the 0097 inspection index
for this build. See [inspection operations](notification-inspection.md) for
role/estate boundaries, safe projection and live-pagination semantics.
