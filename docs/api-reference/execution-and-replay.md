# Execution, SSH and exact-estate replay contracts

**Reviewed 2026-10-21 against `e9bfbef7`.** This companion supplies semantics that
an OpenAPI operation table does not convey. [Generated routes](rest-api.md) are a
schema snapshot, not proof that every profile is enabled or production-qualified.

## Authentication and ownership

Use the route's current permissions, session/Bearer or supported API-key
credentials, and server-resolved estate context. `X-Tenant-ID` selects only an
estate the caller may currently use; it is not an authority grant. Unselected
platform history is NULL-only. Reviewed job/run, unified SSE/WS, GraphQL and
export reads use exact ownership; shared inventory exceptions do not authorize
history or execution. Foreign and missing detail IDs are indistinguishable.
Mixed-source packs/aggregates can return explicit refusals; no blanket claim of
all-route, all-export tenancy certification is made.

## Queued jobs and retry

The server persists target/options/actor/owner and pins current initiating
identity before publication. Workers reconcile the descriptor before scope
selection, recheck policy and pinned live authority, and version-claim only
QUEUED rows. Forgery or duplicate RUNNING work cannot invoke collectors or fail
another claimant. Inline fallback uses the same boundary.

`POST /api/v1/jobs/{job_id}/retry` creates a new admitted attempt under the
retrier with supported original options. Synchronous NETWORK_SCAN/
NETWORK_DISCOVERY jobs, including SSH, return **409**: resubmit the original
collection route. Do not patch terminal rows or edit queue authority to retry.
Legacy unpinned jobs require current approved resubmission.

## SSH request/result

`POST /api/v1/network/ssh-scan` accepts `hosts`, `timeout`, `include_kex`,
`strict_kex` and `known_host_keys`. It commits a RUNNING job before collectors,
rechecks each live phase, then commits the result ledger plus completion.
Response IDs address `GET /api/v1/jobs/{job_id}` and
`GET /api/v1/network/runs/{run_id}`; list with
`GET /api/v1/network/runs?target_kind=ssh`.

Collection metadata identifies SSH, durable recording, host-key/optional-KEX-only
coverage and caller-supplied unverified baselines. A COMPLETED job may contain
failed observations. Initial receipt failure prevents packets; later failures do
not claim a stored success and best-effort settle FAILED. An initial storage
failure may return 500; non-admission failures inside the collection boundary
return generic 503. No device-trust or full-BOM assurance is implied.

## Unified replay and SSE

| Operation | Contract |
|---|---|
| `GET /api/v1/events/recent?limit=100` | First selected-estate retained snapshot page |
| `GET /api/v1/events/recent?cursor=<next_cursor>&limit=100` | Continue the same estate's frozen page window |
| `GET /api/v1/events/stream` | SSE; resume with opaque `Last-Event-ID` or `last_event_id` query token (query takes precedence) |
| `GET /api/v1/events/stats` | Estate-local replay metadata; no global subscriber/activity summary |

Nonzero numeric `since_id` returns **409**. Tokens are opaque and owner-bound;
query-string credentials are not accepted by unified SSE. Limits are bounded
1–500. Pages include events, next_cursor, has_more, complete, retention_gap,
epoch, oldest/latest_sequence, snapshot_through, durable and
`coverage=RETAINED_ESTATE_SNAPSHOT`.

Completeness is relative to the retained snapshot, not an indefinite history or
all scans. Invalid/foreign/stale epochs return 409; backend failures return 503,
not successful emptiness. Initial HTTP errors differ from a failure after SSE
headers: midstream `events.gap`, `events.unavailable` or `events.refused` directs
reconciliation/reconnect/reauthentication. Rejected cursors must not be retried
forever. Process restart/promotion changes primary-bound production epochs and
requires an explicit fresh snapshot even when all records survived. A complete
new snapshot does not prove all acknowledged asynchronous writes survived.

Configured Redis is the replay authority; Pub/Sub only wakes readers. Production
requires verified TLS and command-level readiness. Sentinel currently covers
realtime/current-run factory clients, not every queue/rate-limit/health consumer.
No lossless replication, exactly-once delivery or deployed HA SLA is promised.

## Detailed contracts

- [History/streams/GraphQL/exports](../bank-environment/42-estate-streams-graphql-and-exports.md)
- [Queue authority and SSH](../bank-environment/44-queued-authority-and-durable-ssh.md)
- [Redis TLS/Sentinel engineering and local evidence](../bank-environment/45-redis-tls-sentinel-qualification.md)
- [Operator upgrade and recovery](../runbooks/execution-and-replay-upgrade.md)
