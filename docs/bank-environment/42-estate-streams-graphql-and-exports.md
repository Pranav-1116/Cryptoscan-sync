# 42 — Estate-bound streams, GraphQL, exports and retained replay

[Guide index](README.md) · [Previous socket contract](41-exact-estate-websocket-history.md) ·
[Qualification and open blockers](43-a01-a02-qualification-and-open-blockers.md)

**Implemented locally, 2026-10-21. This extends, rather than replaces, guides
40–41. A01/A02 and production deployment qualification remain partial.**

The implementation now uses estate-partitioned retained journals for the unified
SSE, polling and event WebSocket surfaces. It also closes the reviewed GraphQL
job/batch/runtime and scan/evidence export boundaries. This is not an indefinite
archive, a signed evidence chain, an exactly-once transport, or certification of
every inventory, report or region in the product.

## 1. Authority is the selected estate, not a missing middleware filter

A bank session resolves its current membership from persisted state. A platform
operator without a selection reads **only NULL/platform history**, not all bank
history. An authorized explicit `X-Tenant-ID` selects exactly that bank. A bound
machine key cannot switch estates, including a NULL-bound key attempting to
select a bank. Missing middleware never supplies an unscoped history grant.

The unified event HTTP endpoints use the same strict persisted-identity policy
as the sockets:

- signed and unexpired session **and** live persisted session, not merely an
  environment/test fallback or a token claim;
- active persisted user with reader roles; fresh membership/estate status;
- active key, hard estate binding, reader roles, endpoint/method/IP restrictions;
- quota charged once at admission, including when HTTP auth middleware already
  charged it; frame checkpoints do not consume quota again;
- pinned principal, estate and credential identity for an open stream;
- fresh checkpoints before event payloads, and idle checks at approximately five
  seconds for unified SSE/WS. This is checkpoint authorization, not an atomic
  transaction with an administrator's simultaneous revocation.

HTTP event credentials are headers or session cookies. Unlike a browser socket
upgrade, HTTP event requests do **not** fold query-string credentials into
headers. A valid session cookie is suitable for native EventSource; the console
uses authenticated `fetch` so it can also select the estate in headers.

GraphQL and scan exports retain the existing HTTP authentication/role contracts
and add authoritative `history_context` plus explicit owner predicates. They do
not silently replace every legacy HTTP identity rule across the application.

## 2. Public routes and deliberate compatibility changes

| Surface | New boundary/behavior |
|---|---|
| `GET /api/v1/events/recent` | Ascending retained estate pages, `cursor`, `limit` 1–500; ownership is applied before pagination |
| `GET /api/v1/events/stream` | Same journal for initial catch-up and subsequent delivery; opaque `Last-Event-ID` or `last_event_id` query token |
| `GET /api/v1/events/stats` | Only selected-estate journal metadata; no deployment subscriber totals, global counters or tailer activity |
| `WS /api/v1/ws/events` | Same paginated journal; `cursor` resume, topic filtering and explicit checkpoints |
| `GET /api/v1/live/environment` event block | Estate-bound retained page; global bus IDs/subscriber totals removed from this block |
| `GET /api/v1/telecom/events` | Estate page and cursor, then topic projection; `count_scope=THIS_PAGE_ONLY`, not a total across all retained topic pages |
| `GET /api/v1/cbom/stream/{system_id}` | Existing physically partitioned CBOM service, authoritative context and fresh authority; not a unified-journal history replay endpoint |
| `GET /api/v1/security/posture/stream` | Mixed-source aggregate refused for bank selections/multi-estate installations; fresh authority on the remaining single-platform profile |
| `GET/POST /api/v1/graphql` | Exact owner for single/list/batch jobs, runtime rows and runtime summaries |
| Scan export/CSV/verification-script/CBOM/verify | Foreign and missing scan IDs both return the same 404; evidence queries are also owner-bound |
| `GET /api/v1/export/findings.csv` | Exact-owner count and pages before truncation; existing CSV bounds/headers retained |
| Audit pack/engagement archive/exit report/access-review reads and attestation | Refused when a selected bank or any mixed/orphaned estate makes a safe aggregate unavailable |

**Old numeric resume tokens are not converted into estate authority.** Nonzero
`since_id` polling requests return 409; numeric SSE IDs are invalid cursors; WS
nonzero `since`/`last_event_id` closes with policy refusal. Omit the resume value
for a consciously fresh stream, or reuse the new cursor. In particular, do not
send `last_event_id=0` to mean a fresh SSE connection.

Public event `id` is now an **estate-local sequence**, not a shared global
counter. Pair it with `estate_epoch` for deduplication. This avoids disclosing
foreign event volume through the gaps between two visible global IDs. Transport
node identities/global sequence IDs stay internal. The legacy internal global
bus cache/journal interfaces remain for compatibility; they are not the new
history API or a complete estate replay implementation.

## 3. What retained completeness means

[Replay/cursor implementation](../../services/api/api/events/estate_replay.py) and
[Redis journal](../../services/api/api/events/redis_estate_journal.py) implement:

1. A server-derived owner bucket. NULL and any tenant string have distinct keys.
2. A separate sequence, epoch and retained stream for each estate.
3. Memory retention of 500 events **per estate** by default; Redis retention of
   10,000 **per estate**, with exact trimming, not a global window filtered later.
4. A frozen snapshot watermark for intermediate pages. New publications do not
   silently move the end of a pagination walk.
5. Ascending pages plus one look-ahead record, `has_more` and a continuation token.
6. A final token that can tail publications after the completed snapshot.
7. Explicit retention gaps, epoch resets, ownership/sequence disagreement and
   missing/corrupt journal records. Such failures are never empty-success fallback.

A cursor contains a format version, owner binding, epoch, last estate sequence
and optional snapshot watermark. It is opaque application state, **not a secret,
cryptographic signature, authorization grant or evidence-integrity proof**. Even
an invented token cannot change the server-derived owner. Do not parse or edit
tokens to infer permissions. Exact ownership is checked on stored envelopes;
conflicting payload tenant labels cause refusal rather than promotion.

`complete=true` means this page reached the end of the requested retained segment
without a gap on that request. It does not mean history before retention exists.
A client traversing pages must remember **every** gap/error it encountered, not
look only at the final page. `historical_backfill=false` is deliberate: old global
Redis entries and arbitrary DB monitor rows are not retroactively declared
complete entries in the new journal.

`durable=false` identifies volatile local memory. `durable=true` identifies reads
from the configured shared Redis journal; it is **not an independent assertion of
AOF, fsync, backup, HA, residency or recovery qualification**. Those are deployment
obligations. A fresh memory process loses its journal; an old nonempty cursor is
refused after reset, not acknowledged as fully replayed.

## 4. Why replay and live delivery no longer have a handoff hole

Both unified SSE and event WS subscribe **before** reading the first journal
watermark. An exact envelope-owner predicate runs before queueing. Foreign
traffic neither enters that queue nor increments its dropped counter.

The queue is only a wakeup mechanism. After wakeup or bounded idle timeout, the
handler reads ordered records from its estate journal. Consequently:

- a publication between first snapshot capture and replay completion is read
  after the frozen snapshot;
- an out-of-order Pub/Sub arrival cannot reorder persisted estate delivery;
- a bounded queue overflow does not by itself discard retained observations;
- a lost Pub/Sub wakeup is recovered by the next journal poll;
- if history really aged out, a gap is explicit; replay does not invent recovery;
- backend failure closes/refuses the stream rather than substituting local data.

Checkpoint cursors are emitted **after** preceding page events. A client must not
acknowledge a page's checkpoint before it has consumed those events. Reconnects
can still replay duplicates after an ambiguous disconnect/acknowledgement. This
is not exactly-once delivery. A gap requires an application-state resynchronization;
a freshly fetched current state cannot reconstruct erased historical events.

## 5. Redis append and failure boundary

[Bus publication](../../services/api/api/events/bus.py) now persists before local
fanout. When a required **or configured estate journal** fails, the publisher is
told failure and that call does not enter local history/live delivery. A required
or configured estate provider without an installed publisher also refuses
publication; a read-only adapter is not permission for unjournaled local success.

Within Redis, WATCH/MULTI covers estate sequence allocation, exact-retention
append, metadata update, compatibility global append and Pub/Sub publication.
Key types and estate tail/metadata consistency are checked before queueing
writes. Contention uses bounded jitter/retries, then explicit refusal. Readers
also validate a consistent watched snapshot; missing middle entries are errors.
WATCH command reads are not themselves a snapshot: a preliminary inconsistency
is confirmed with an empty EXEC before reporting corruption. A concurrent commit
invalidates WATCH and retries instead of producing a false integrity refusal.
Deterministic interleaving tests cover both append and page reads; a small real
Redis concurrent-writer test checks accepted-only sequence/payload completeness.
That is not sustained-load/fairness certification.

Important limits:

- This is **not** a SQL/Redis distributed transaction. A caller can still fail
  before/after a separate business-data commit.
- A lost Redis reply can leave publication outcome uncertain; retry is not
  idempotent business-event deduplication.
- Redis transactions do not generally roll back runtime command errors. The
  checked type/sequence preconditions cover reviewed ordinary corruption cases,
  not arbitrary ACL/server failure sequences.
- The present cross-key transaction assumes a standalone/Sentinel-compatible
  deployment. Redis Cluster/hash-slot support is **not qualified**.
- Production needs correct ACLs including **INCRBY** (redis-py's increment wire
  command), TYPE, EXISTS, hash reads/writes, WATCH/MULTI/EXEC, stream operations,
  Pub/Sub, scratch DEL and INFO for primary-bound snapshots. The subsequent
  [TLS/Sentinel delivery](45-redis-tls-sentinel-qualification.md) adds verified
  transport and actual scratch journal-command readiness. PING is insufficient;
  startup success still cannot guarantee future runtime permissions, persistence,
  capacity/retention or restore correctness.
- Production factory and Sentinel clients bind public epochs to the actual
  primary process in the watched snapshot validation. Promotion/process restart
  explicitly resets old cursors, even if data survived. A new complete retained
  snapshot cannot establish lossless asynchronous replication. The factory does
  not migrate all queue/rate-limit/health Redis consumers.
- Pub/Sub health is separate from journal completeness. An unavailable listener
  does not make polling a different source of history.

The optional local-development callback without an estate journal retains its
old best-effort semantics. Once a shared estate journal is configured, silently
successful unjournaled local publications are not an accepted replay contract.

## 6. Polling example: finish the retained snapshot, then tail

Use a valid persisted session/key and a legitimately selected estate. The client
should deduplicate by `(estate_epoch, id)`, not treat a shared ID as a count.

```python
import requests

session = requests.Session()
session.headers.update({"Authorization": "Bearer " + session_token})
# Set only when authorized to select this bank:
session.headers["X-Tenant-ID"] = selected_bank_id
cursor = None
seen = set()
while True:
    params = {"limit": 100}
    if cursor:
        params["cursor"] = cursor
    response = session.get(base_url + "/api/v1/events/recent", params=params)
    response.raise_for_status()  # 409/503 are not an empty event list
    page = response.json()
    if page["retention_gap"]:
        raise RuntimeError("Retained history was lost; resynchronize explicitly")
    for event in page["events"]:
        identity = (event["estate_epoch"], event["id"])
        if identity not in seen:
            consume(event)
            seen.add(identity)
    cursor = page["next_cursor"]
    if not page["has_more"]:
        break
# Save cursor only after consume() succeeded; reuse it on the next polling pass.
```

The example is illustrative client code, not executed bank acceptance evidence.
A polling caller interested only in telecom must still follow page continuation;
a page containing no telecom events can contain other owned event types and have
`has_more=true`.

## 7. SSE and socket examples

Fresh SSE, no fabricated numeric cursor:

```bash
curl -N --fail-with-body \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "X-Tenant-ID: $AUTHORIZED_BANK_ID" \
  "$BASE_URL/api/v1/events/stream"
```

Resume using the exact last acknowledged token:

```bash
curl -N --fail-with-body \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "X-Tenant-ID: $AUTHORIZED_BANK_ID" \
  -H "Last-Event-ID: $ACKNOWLEDGED_CURSOR" \
  "$BASE_URL/api/v1/events/stream"
```

SSE control events include `events.checkpoint`, `events.gap`, `events.refused` and
`events.unavailable`. Before headers, invalid/reset/corrupt replay is 409 and a
backend outage is 503. After headers, refusal/unavailability is an explicit
control event followed by closure; it cannot become a second HTTP status.

Event WS accepts `cursor=<URL-encoded token>` and optional `topics=scan.,runtime.`.
It sends `hello`, event frames, page `checkpoint` frames, gap warnings and pings.
A topic projection is not a declaration that other topics have no history.
Invalid/foreign cursor or journal-integrity refusal closes with 1008; backend
failure closes with 1011. Session/key authentication follows guide 41. Never put
actual secrets into copied examples or unredacted proxy access logs.

## 8. Console behavior

[Realtime client](../../frontend/src/lib/realtime.tsx) now:

- preserves opaque string cursor IDs instead of `parseInt`/numeric comparison;
- ignores checkpoint/control frames in the scan-event feed;
- deduplicates replayed events and shows a retained-loss/resync warning;
- does not silently turn a refused/reset cursor into a fresh successful stream;
- clears private events and aborts the old stream on estate change/sign-out;
- ignores late responses/reader frames from the previous estate;
- represents unavailable subscriber/rate counters as unknown, not invented zero
  or deployment-wide statistics, including the header rate display; caps the client
  pending frame buffer at 1,048,576 decoded-character units (not a total browser
  memory or raw-byte allocation guarantee).

The new client tests use controlled browser-shaped streams, not a live browser,
reverse proxy or bank network. Native EventSource's reconnect implementation is
not certified by these frontend unit tests.

## 9. GraphQL and exports

Job single/list/batch reads now use exact-owner repository predicates, including
NULL. Both native JSON-path batch lookup and its existing fallback apply estate
ownership before the candidate limit. Runtime rows and summary aggregates use an
owner-bound repository executor, so foreign hosts/algorithms cannot influence a
selected estate's totals or top-suite list.

Scan export authorization checks the scan owner before disposition, evidence or
verification. Evidence is filtered again by the exact owner; a foreign evidence
row referring to an owned scan ID cannot poison that scan's exported chain.
Verification integrity can still correctly fail for corrupt **owned** evidence;
a 200 verification response is not a claim that its integrity verdict passed.

Findings CSV keeps its bounded/truncation headers but counts/pages only owned
rows. This does not silently partition every report elsewhere in the product.
The mixed-source audit pack and access-review family is conservatively refused
for bank selections, any Tenant row, or non-NULL owned records surviving deletion
of the tenant catalogue. Deleting an organization is not declassification.
Single-platform installations retain their prior aggregate behavior.

## 10. Evidence and non-claims

New regression sources:

- [Journal memory/emulator contracts](../../services/api/tests/unit/test_estate_replay.py).
- [Real Redis command/fanout contracts](../../services/api/tests/integration/test_estate_replay_redis.py).
- [Authenticated SSE/metadata/CBOM checks](../../services/api/tests/unit/test_sse_estate_contract.py).
- [GraphQL/export/archive checks](../../services/api/tests/unit/test_cross_surface_estate_contract.py).
- [Socket authority and paginated replay](../../services/api/tests/unit/test_socket_history_contract.py).
- [Console cursor/estate reset tests](../../frontend/src/lib/realtime.test.tsx).

See [guide 43](43-a01-a02-qualification-and-open-blockers.md) for executed results,
the standalone Redis restart/outage experiment, expected failures and the actual
A01/A02 release blockers. Other REST handlers in the file-backed stream router,
including ingestion/attack summaries and CBOM version reads, also receive
router-wide estate context. This is not comprehensive qualification of their
collector, processing, provenance or export chains. CBOM notification reads
recheck authority after storage I/O and explicitly refuse backend failures. Do not present skipped/expected-failure cases as passed
security controls.

No historical estate ownership, ORM sharing defaults, migrations, workflow files
or main branch were rewritten. SBOM, NBOM, CBOM, TechBOM, HBOM and VBOM retain their
separate evidence meanings: delivery/replay success is not new observation,
verified supplier provenance, proof of deployment, or a cross-BOM relationship.
