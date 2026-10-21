# Real-time API and machine access (enterprise integration)

**Current contract — 2026-10-21.** Unified event history is exact-estate and
cursor-based. Pub/Sub is a low-latency wakeup, not the durable source of truth.

- **`GET /api/v1/events/stream`** — SSE with opaque resume tokens, heartbeats,
  checkpoints and fresh authority checks.
- **`GET /api/v1/events/recent?limit=100`** — first retained estate page; send
  `cursor=<next_cursor>` for later pages. The limit is bounded to 1–500.
- **`GET /api/v1/events/stats`** — selected-estate replay metadata, not a global
  subscriber count or activity summary.

Use the normal session/Bearer or supported API-key authentication and authorized
estate selection. Query-string credentials are not accepted by unified SSE.
Platform-unselected history is NULL-only; a selected bank needs live authority.
The server rechecks credentials/estate during replay and idle/live delivery;
foreign frames are excluded before subscription queueing.

Resume SSE with `?last_event_id=<opaque-token>` or `Last-Event-ID`. The query value
takes precedence. Store the acknowledged cursor after consuming the preceding
page/events. Nonzero numeric `since_id` is refused with 409; do not calculate a
cursor from an event count or reuse another estate's token.

Pages include `next_cursor`, `has_more`, `complete`, `retention_gap`, `epoch`,
`snapshot_through` and `coverage=RETAINED_ESTATE_SNAPSHOT`. Completeness describes
a bounded frozen retained snapshot, never every historical scan. On an initial
409/reset, explicitly refresh application state and begin a new snapshot. On
503, retry availability later; an outage is not an empty successful page.
Midstream `events.gap`, `events.unavailable` or `events.refused` requires the
corresponding resynchronization/reconnect/reauthentication action. Do not retry a
rejected old cursor indefinitely.

Development memory history is bounded and lost on process restart. Configured
Redis Streams retain independent estate partitions across API restarts, within
retention/persistence limits. Production requires verified TLS, named ACL
credentials and an actual journal-command startup probe. Optional Sentinel and
production factory clients bind public epochs to the actual primary process:
promotion or Redis process restart requires an explicit old-cursor reset, even
when data survived. Subscriber reconnection cannot make asynchronous replication
lossless. Other Redis consumers are not all migrated to Sentinel.

See [replay design](../bank-environment/42-estate-streams-graphql-and-exports.md),
[TLS/Sentinel qualification](../bank-environment/45-redis-tls-sentinel-qualification.md)
and the [operator upgrade runbook](../runbooks/execution-and-replay-upgrade.md).

## Event catalogue

| type | source | when |
|---|---|---|
| `scan.queued` | api | a scan trigger was accepted |
| `scan.stage` | pipeline | each pipeline stage starts (clone, scan, evidence, policy, …) |
| `scan.completed` | pipeline | pipeline finished — carries findings count + gate decision |
| `scan.failed` | pipeline | pipeline failed at a stage |
| `monitor.scan_ok` / `monitor.scan_degraded` / `monitor.scan_failed` / `monitor.blocked` / `monitor.alert` | monitor | live-monitor probe outcomes |
| `auth.login` | auth | a session was issued (user + roles, never token material) |
| `apikey.create` / `apikey.revoke` | api-keys | machine keys changed |
| `remediation.task_created` / `task_accepted` / `task_completed` / `task_verified` / `drift_tasks_created` | remediation | task lifecycle transitions (verification outcomes included) |
| `notifications.dispatched` | notifications | an outward dispatch drain ran (examined/dispatched/delivered counts) |

## Notifications (routed delivery)

The Notification center routes event classes to channels (in-app, email,
webhook, SIEM/SOC) — and the routing is load-bearing:

- **In-app** — `GET /api/v1/notifications/feed` delivers only classes routed
  to in-app; switching a class off removes it from the feed.
- **Webhook / SIEM** — `POST /api/v1/notifications/dispatch` is the
  operator-triggered outward drain: each routed notification is sent once per
  tenant (dispatch registry) over real signed HTTP — the SIEM channel to
  SIEM/SOAR integrations, the webhook channel to ITSM/CMDB receivers — with
  every attempt audited in the integrations delivery log. Email routing is
  stored but no SMTP transport is wired for notifications; nothing is claimed
  sent.

Unmapped event types stay in this events stream, unrouted — never force-fit
into a class.

Honest latency note: events produced inside the API process (pipeline runs
inline when no Redis queue is configured, auth, keys) are pushed the instant
they happen. Events from the separate monitor daemon are written to its
database table and federated by a tailer every `EVENT_TAILER_SECONDS` (2s
default; 0 disables). The stream states its delivery mode — it never claims
push semantics for tailed sources.

## Machine API keys (`X-API-Key`)

For CI pipelines, SIEM pulls, and anything that cannot hold a browser
session. Admins create keys in the dashboard ("API keys") or via API:

```bash
curl -X POST …/api/v1/api-keys \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"ci-pipeline","roles":["auditor"]}'
# → { "raw_key": "csk_…", "key_prefix": "csk_ab12…", … }   # raw shown ONCE

curl -H "X-API-Key: csk_…" …/api/v1/scans
```

Rules, stated plainly:

- The raw key is displayed once at creation; only a **SHA-256 hash** is
  stored. Lists show the 12-char prefix only.
- A key carries **its own roles**, checked against each route's permission
  matrix, owner and configured scope. Empty roles do not imply admin. Check the
  current `scan.trigger` matrix rather than treating a read role as scan authority.
- Revocation/expiry are rechecked at authorization checkpoints, including
  long-lived stream checks; this is not an instantaneous in-flight kill switch.
  Expiry is optional. `last_used_at` is stamped at most
  once a minute per key so hot CI loops do not turn into write storms.
- Key management is admin-only and lands in the tamper-evident audit trail.
- Rate limits key per key (each key gets its own sliding-window buckets —
  same limits as humans: 5/min on login, 100/min scan submits, 600/min API).

## Limits that remain

- No indefinite archive, historical database backfill or exactly-once delivery.
- A complete new retained snapshot after failover does not prove every previously
  acknowledged event survived asynchronous replication.
- Local TLS/Sentinel qualification is not a deployed cross-zone security/HA test.
- The event catalog names possible source families, not permission to see all
  tenants' events or a claim every scanner is qualified.
- Mixed-source aggregate/export surfaces can be deliberately refused until their
  estate contract is qualified; a refusal is not a successful bank archive.
