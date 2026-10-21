# 41 — Exact-estate WebSocket history and authorization checkpoints

[Guide index](README.md) · [HTTP history boundary](40-exact-estate-http-history.md) ·
[Enterprise backlog](33-international-bank-engineering-and-rollout.md)

**Subsequent delivery:** [Guide 42](42-estate-streams-graphql-and-exports.md)
supersedes this increment's shared-window replay limitation with per-estate
retained journals and opaque estate-local cursors. Its wire compatibility changes
apply to current SSE/WS clients. The original implementation/results below remain
a historical record; [guide 43](43-a01-a02-qualification-and-open-blockers.md)
records current qualification and open blockers.

## Status — 2026-10-21

**Implemented locally: a further bounded A02 history-isolation increment.**
These two read-only WebSocket routes now establish their own trusted estate
boundary rather than depending on optional tenant middleware:

- `/api/v1/ws/binary/jobs/{job_id}`;
- `/api/v1/ws/events`.

This follows [guide 40](40-exact-estate-http-history.md), which qualified the
specific HTTP job/network-run history boundary. Neither increment is a claim
that A01/A02, export/graph/SSE history isolation or bank deployment qualification
is complete. No scanner, workflow, migration or immutable-history rewrite is
included. Internal dispatch and event-bus publishing/federation are unchanged.

## 1. What was closed

The binary socket previously used an ordinary unscoped job read unless tenant
middleware happened to establish context. A platform session could therefore
read a bank's job, and an app without that middleware could read other estates.
The event socket subscribed to the shared bus without an estate predicate and
replayed the shared history without tenant filtering.

The [socket routes](../../services/api/api/routers/ws.py) now use the
[fresh socket authority helper](../../services/api/api/security/socket_history.py).
Binary polling supplies an explicit owner to the guide 40 repository method.
Event replay, queue admission and final live-send checks use the same selected
estate and topic filter. There is no wildcard platform owner.

| Selected estate | Job snapshots and event ownership |
|---|---|
| Bank A | Bank A only, not Bank B or NULL/platform |
| Bank B | Bank B only, not Bank A or NULL/platform |
| Platform, no selected bank | NULL/platform only, not all tenants |
| Authorized platform session explicitly selecting Bank A | Bank A only for that connection |
| Tenant-bound machine key | Exactly the key's bound estate; selection cannot widen it |

An unknown/foreign job follows the existing `hello`, generic `error`, close-4404
shape. The hello contains the caller's requested job ID and polling mechanism,
not a private target or job snapshot. Other estates' existence is not disclosed.
The existing terminal `final` and normal close-1000 behavior is retained for an
owned job.

## 2. Credentials, roles and compatibility changes

The socket helper normalizes browser query credentials using the same
[query-to-header mapping](../../services/api/api/middleware/tenant_scope.py) as
the tenant middleware. Authentication and tenant selection therefore use one
precedence rule rather than different credentials for scope versus data reads:

1. API key header, or query `api_key` when no key header is present;
2. explicit bearer header, or query `token`/`access_token` when that header is absent;
3. the existing session cookies when no selected bearer is present.

A nonempty invalid machine key is refused; it does not fall through to a valid
cookie. Header `X-Tenant-ID` wins over query `tenant`. The existing trusted tenant
resolver checks human membership and authorized platform selection. No payload
`tenant_id` is accepted as access authority.

**Intentional tightening:** human sockets require a valid HMAC session token,
a matching unrevoked/unexpired server-side session record, an existing active
user and current reader roles. Development/test token-only fallback is not
used for these history routes. Deleted users, absent session records, unreadable
authority and roleless sessions do not become legacy platform administrators.
An ordinary reader without a tenant membership cannot implicitly watch platform
jobs; standalone platform-history fixtures now use real platform-admin roles.
No production gate was disabled to keep those old fixtures passing.

Reader roles retain the existing normalized role catalog: admin/superadmin,
security analyst, auditor and readonly, including catalog aliases. A scanner-only
machine key does not become a history reader.

Tenant-bound credentials also require an existing **ACTIVE** tenant. A platform
session selecting a bank is checked for active-bank status by this helper even
if the underlying privileged resolver permits broader administrative reads.
API-key NULL ownership means platform only, including for a privileged key; it
is not permission to select a bank with a query/header.

### Machine-key policy

The helper reuses the pure API-key path/method rules and trusted client-IP
resolution/allowlist checks. The upgrade is evaluated as **GET** against the
actual `/api/v1/ws/...` route. A key scoped to `/findings`, POST-only or from a
nonmatching client network cannot use a WebSocket as a policy bypass.

A positive per-minute key cap uses the existing durable `DbQuotaWindow` counter
**once per upgrade authorization attempt after identity/role/policy checks**,
not once per frame.
A second upgrade over the cap is refused. This is not a frame/byte quota,
concurrent-connection budget or live multi-replica performance qualification.
Existing key-use/audit accounting is not newly claimed as complete.

## 3. Fresh authority between data batches

A connection pins principal, selected estate and machine-key identity. Fresh
checks must match that grant; an existing socket cannot silently switch estates
when membership changes.

- Binary progress revalidates before every job-row poll. Poll intervals remain
  clamped to 0.25–10 seconds, default 1 second.
- Event replay is checked before its bounded replay batch is sent.
- Live event delivery revalidates before processing each delivered event batch.
- Idle event connections revalidate every 5 seconds by default, independently
  of the existing 25-second heartbeat cadence.

Checks reload session/key validity, reader roles, selected-tenant authority and
active status. Machine-key path/method/IP restrictions are rechecked without
re-consuming the upgrade quota. Revocation, expiry, suspension, membership or
role removal, and relevant policy changes prevent the next authorized batch.
An already authorized/in-flight frame or replay batch is not recalled. These
are checkpoints, not instantaneous revocation or packet-level cancellation.

Policy/credential refusal closes with **1008**. Authority lookup failures and socket read/backend errors that propagate
close with **1011** and generic diagnostics, rather than returning database
exception strings or private backend details. Middleware can refuse a handshake
earlier using its existing policy-close behavior; that does not establish a
weaker fallback. Event subscriptions are removed on close, refusal and failures.

## 4. Envelope ownership, queue privacy and honest resume

An event's top-level envelope `tenant_id` determines its owner. A nested payload
label cannot promote an unowned/platform event into a bank's stream. Conflicting
non-NULL payload versus envelope labels are rejected, as are invalid owner
shapes. Publishers must still stamp ownership correctly: this is not a semantic
proof that arbitrary producer content is truthful or properly classified.

The predicate runs **before queue insertion**, combining owner and requested
topic prefixes. Another estate's burst does not fill the socket's queue,
increment its dropped counter or produce cross-estate drop warnings. Live sends
also recheck visibility. Topic filters do not grant access to another estate.

Hello `replayed` counts only the visible, topic-matching replay entries. Hello
and heartbeat `latest_id` use the last visible cursor (or caller-supplied resume
cursor), not the bus's global latest ID. The global event IDs remain opaque
resume tokens and can have gaps; they are not per-tenant sequence numbers or
completeness measurements.

**Important retained limitation:** replay considers at most 200 candidates from
the existing shared recent-history window and then applies estate/topic filters.
It is not 200 guaranteed per-estate events. Other tenants' traffic can displace
an estate's older events from that window. Durable-adapter availability,
retention, replay/live duplicates, ordering and cursor/gap semantics remain the
existing bus's contract. No complete archive, exactly-once delivery or guaranteed
recovery is claimed. Hello and drop-warning wording explicitly disclose bounded
replay rather than promising to fill every gap.

Do not switch to an unreviewed SSE/export/GraphQL route to bypass a refusal.
Those independently exposed surfaces still require their own authority review.

## 5. Practical clients

Use the application's existing authenticated browser/session or a suitably
restricted key; do not paste credentials into documentation or chat. Query
credentials are supported for browser upgrade limitations, but URLs can appear
in logs/history. Prefer session cookies or explicit headers where available;
query-secret redaction and WebSocket origin/CSRF policy remain separate work.

For a bank session, the event path can be:

```text
/api/v1/ws/events?topics=scan.,binary.&since=<last-visible-id>
```

For an already-authorized platform session deliberately selecting a bank:

```text
/api/v1/ws/binary/jobs/<owned-job-id>?tenant=<selected-bank-id>
```

The second path is not a grant for an ordinary bank user. A key tied to another
estate cannot widen itself using the same parameter. Reconnect after a 1008
only once the underlying membership/session/policy issue is resolved; do not
interpret reconnecting as renewed execution permission.

## 6. Controlled evidence

[50 new authenticated socket cases](../../services/api/tests/unit/test_socket_history_contract.py)
exercise actual session authentication and SQL authority, with and without tenant
middleware. They cover:

- all three estates' own/foreign job snapshots, exact event replay/live delivery,
  explicit trusted platform selection and no selection bleed to the next socket;
- forged selection, contradictory event labels, foreign queue bursts and private
  heartbeat/replay metadata;
- session deletion, user deletion/disablement, role/membership removal, suspended
  tenants and between-poll/event authority changes;
- machine-key scope, method and IP restrictions at upgrade and between frames,
  expiry/revocation, estate binding and once-per-upgrade quota behavior;
- explicit bearer versus query/cookie precedence with/without middleware;
- initial/connected session-store outages, replay failure, generic close reasons
  and subscription cleanup.

The [11 existing socket cases](../../services/api/tests/unit/test_websocket_api.py)
also pass, retaining polling/terminal frames, intervals, topic/resume behavior and
reader-role refusals under the corrected platform fixture authority.

Final broad scoped backend regression on Python 3.11.2: **2,123 passed, 5 skipped,
7 deselected, 142 warnings**, 516.33 seconds. It includes the guide 40 backend
selection plus socket, event-bus/SSE, stream-tenancy and API-key suites. The 61
socket cases passed together after formatting. Existing warnings include legacy
asyncio test markers; skips/deselections are not executions. This is controlled
local Python/SQLite/protocol evidence, not live Redis/PostgreSQL/Neo4j, bank,
frontend or production runtime certification.

Changed-Python F/E9 lint, new/changed socket formatting, whitespace and bank-guide
link/JSON/shell syntax validation are checked with publication. No workflow,
migration, main-branch or historical ownership changes are included.

## 7. Remaining work and six-BOM integrity

SSE/recent/stats, GraphQL job lookup, exports/archives, other scanner streams and
platform dashboards still need explicit review. Producer ownership, real durable
per-estate replay, audited privileged selection, query-secret redaction,
origin/CSRF controls, frame/connection budgets, distributed fairness and live
revocation/load qualification are not closed here. Queued/plugin/SSH admission
and broader A01 work remain separate.

NBOM, CBOM, SBOM, TechBOM, HBOM and VBOM evidence is neither relabeled nor enriched
by an access-control check. A progress percentage, socket receipt or event label
is not complete collection coverage or observed crypto/software/hardware/
vulnerability evidence. Immutable provenance and older snapshots remain
unchanged. **A01 and A02 remain partial.**
