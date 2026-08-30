# Real-time API and machine access (enterprise integration)

CryptoScan pushes what happens as it happens — no polling loops to build:

- **`GET /api/v1/events/stream`** — server-sent events (SSE). One connection,
  every event: scan queued → each pipeline stage → completion (with gate
  decision), monitor probe results, logins, API-key changes.
- **`GET /api/v1/events/recent?since_id=N`** — bounded history for
  catch-up/fallback polling (ring buffer, last 500 events).
- **`GET /api/v1/events/stats`** — subscribers, buffered events, tailer state.

Auth is the standard session (cookie or `Authorization: Bearer`). Browsers get
it free — cookies ride along same-origin. Reconnect with
`?last_event_id=<id>` (or the `Last-Event-ID` header) to resume without gaps:
the server replays buffered events after that id. Slow consumers never block
the pipeline — their queue drops oldest and a `events.dropped` notice tells
them to resync.

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
- A key carries **its own roles** (`viewer` / `auditor` / `admin`), enforced
  on every endpoint exactly like human RBAC — a `viewer` key cannot trigger
  scans, an `auditor` key can. Key roles never fall back to "no roles ⇒
  admin".
- Revocation is immediate; expiry optional. `last_used_at` is stamped at most
  once a minute per key so hot CI loops do not turn into write storms.
- Key management is admin-only and lands in the tamper-evident audit trail.
- Rate limits key per key (each key gets its own sliding-window buckets —
  same limits as humans: 5/min on login, 100/min scan submits, 600/min API).

## What this is not (yet)

- **Multi-node fan-out** — the bus and its buffer are per-process. Behind a
  load balancer, sticky sessions route a stream to one node, and the honest
  claim is "single-process real-time". A Redis pub/sub bus is the upgrade
  path (`REDIS_URL` already wired for rate limits and job queue).
- **Replay across restarts** — history is in-memory; after an API restart the
  stream starts from the tail. Durable eventing would need the bus backed by
  the DB or a broker. Not claimed today.
