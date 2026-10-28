# 96 — Realtime channels: making the console event-driven without lying to it

Status: implemented for the transport, the contract and eight product surfaces. Migration of
the remaining poll-only panels is a ratchet, not a completed sweep — the numbers below are
measured, not estimated.

## 1. What already existed, and what was missing

The platform was not missing realtime plumbing. Before this change it had:

- `GET /api/v1/events/stream` — SSE with `Last-Event-ID` resume, `events.checkpoint`,
  `events.gap`, a 15s heartbeat and a grant re-check (`services/api/api/routers/events.py`);
- an `EventBus` with a durable journal, tenant-filtered subscriptions, a 500-event ring and
  drop-oldest subscriber queues (`services/api/api/events/bus.py`);
- `emit_platform_event()` persisting a `monitor_events` row and publishing the event
  (`services/api/api/events/platform_events.py`), already called from estate, digital twin,
  graph, inventory, notifications, ops, platform and remediation routers;
- a frontend store (`frontend/src/lib/realtime.tsx`) with one SSE connection, watchdog,
  backoff and a resume cursor.

What it did not have was a **contract**. Events were published under ad-hoc names
(`graph.updated`, `remediation.task_verified`, `estate.change.detected`), so:

1. a screen could not state what it depends on — it either refetched on *every* event
   (`useRealtimeRefresh`, 25 call sites) or on a timer (117 `usePollingApi` call sites);
2. a typo in an event name produced an event nothing could receive, silently;
3. nothing could answer "is this surface actually live, or have we just declared it so?";
4. the estate panel opened a **second** SSE connection of its own (`useEstateEvents`), with
   its own cursor and its own connection light that could disagree with the header's.

## 2. The contract

`services/api/api/realtime.py` declares eight **channels** — product surfaces, not event
sources — and, for each, the kinds and the read path a subscriber should refetch:

| channel | carries | resource | mapped event types |
| --- | --- | --- | --- |
| `estate` | discovery runs, coverage, detected changes | `/estate/evidence/changes` | `estate.run.*`, `estate.plane.finished`, `estate.change.detected`, `estate.coverage.lost` |
| `twin` | twin snapshots, graph rebuilds | `/estate/evidence/twin` | `digital_twin.snapshot`, `graph.snapshot`, `graph.updated` |
| `crypto` | BOM projections, evidence-chain integrity | `/cbom` | `technology_bom.{snapshot,export,evidence_package}`, `evidence.chain_broken` |
| `inventory` | asset lifecycle and ownership | `/inventory/assets` | `inventory.asset_lifecycle`, `inventory.asset_ownership` |
| `remediation` | tasks opened → verified | `/remediation/tasks` | `remediation.task_*`, `remediation.drift_tasks_created` |
| `security` | posture drops, policy, cascade | `/security/policy` | `security.posture_drop`, `security.policy_updated`, `cascade.*_changed` |
| `notifications` | dispatch | `/notifications` | `notifications.dispatched` |
| `findings` | findings triaged / retracted / restored | `/findings` | *(direct publish only)* |

Rules the contract enforces:

- **`publish(channel, kind, …)` refuses an undeclared pair.** A publisher cannot invent a
  kind, so the catalogue cannot advertise something nothing emits.
- **Existing events are classified, not renamed.** `realtime.stamp()` runs inside
  `emit_platform_event()` and adds `channel` / `kind` / `sequence` to the payload, so the
  code already emitting estate/remediation/graph events becomes addressable without a
  rename sweep. Stamping never overwrites an explicit channel and never raises: a routing
  bug must not cost an audit row.
- **An unclassifiable event is counted, not invented.** `catalog()["unrouted"]` lists event
  types that carry no channel; operatically-irrelevant ones (`technology_bom.schedule*`,
  `retirement.*`) are listed in `UNCHANNELLED` explicitly rather than left unexplained.
- **`findings` is now actually published.** Retraction and restore (`routers/findings.py`)
  publish `findings.status_changed` after commit — best-effort, because the retraction is
  already audited and a broken bus must not turn it into a 500.

## 3. The stream

`GET /api/v1/realtime/stream?channels=estate,findings`

- filtering happens **in the bus subscription**, not in the HTTP generator: a shared Redis
  channel must never place another estate's event in a subscriber's queue (the same
  invariant `test_sse_estate_contract.py` pins for the audit stream);
- `GET /api/v1/realtime/catalog` and `GET /api/v1/realtime/channels/{name}` expose the
  contract, the resource to refetch, `last_event` per channel and the union of unrouted
  types;
- replay comes from the in-process ring by numeric id. When the requested cursor is beyond
  the ring, the stream emits `realtime.gap` and says to refetch — it never pretends to have
  caught up;
- a withdrawn grant closes the stream with `realtime.refused` on the next wake, not on the
  next event: a quiet channel must not keep an unauthorised socket open;
- frames coalesce (a burst drains in one wake), and the loop is bounded by
  `RECHECK_SECONDS`, not by traffic.

**This stream is a delivery path; `/events/stream` remains the audit path.** Channels
resume by ring id and restart at 1 after a restart; the estate journal keeps its cursor
authority. That split is stated in `catalog()["limits"]` so no client reads a sequence as
an offset.

## 4. The console

- `useChannelSignal(channels)` — a panel's subscription, with three states that stay
  distinct: `LIVE` after a change arrives, `QUIET` (connected, nothing yet), `POLLING`
  (no stream).
- `useChannelRefresh(channels, runs)` — refetch on a change to *that* channel. Rewritten
  from a leading-edge throttle to leading + trailing coalescing: the old version dropped
  every event inside its 4s window, so a burst during a refetch could leave the screen on
  pre-burst data with no later call to correct it.
- `usePollingApi(fn, interval, deps, { channels })` — the same hook the product already
  uses. Declaring channels makes it event-driven and **slows** its timer to 120s. It does
  not remove the timer: an event is a hint to re-read, and only a re-read after a
  reconnect can make a screen correct.
- `useEstateEvents` now reads the shared store instead of opening its own `EventSource`, so
  the console holds one connection, one cursor and one connection state.
- `ChannelLiveBadge` renders the three states per panel, so "live" on screen means a change
  actually arrived.

Converted in this batch (17 declared call sites across 11 files): Findings, Crypto, Alerts,
Cmdb, Hardware, Libraries, Hbom, Certificates, DigitalTwinPanel. `realtime.coverage.test.ts`
holds the line — poll-only call sites have a ceiling (100) that may be lowered and never
raised, channel names must exist in the backend contract, and a scoped panel may not also
use the unscoped global refresh.

## 5. What is still not live, stated plainly

- **100 `usePollingApi` call sites still poll blindly.** They are not listed as converted
  anywhere. Most are on surfaces with no emitter yet (delivery logs, integration health,
  network topology, resource monitoring), which is the honest reason they still poll.
- **Backend emission coverage is partial by design.** `catalog()["unrouted"]` is the
  measurement, not a promise: a channel declared here is live only once `last_event` is
  non-null in a running deployment.
- **`sequence` is per-process.** It coalesces repaints; it is not a resume token and it
  resets on restart.
- The channel stream is not a replacement for the estate journal in any compliance sense —
  it carries no retention guarantee beyond the 500-event ring.

## 6. Verification

- `services/api/tests/unit/test_realtime_contract.py` — 17 tests: every declared event type
  routes to exactly one kind, the events the tree actually emits are all classified, the
  unchannelled list cannot become a dumping ground, stamping is idempotent and never
  invents a channel, the catalogue admits an undeclared channel is `last_event: null`.
- `services/api/tests/unit/test_realtime_stream_api.py` — 5 tests over real ASGI: catalogue
  contents, no cross-estate `last_event` leak, unknown channel is a 404/422 refusal, a
  `channels=findings` subscriber receives only findings and leaves no subscription behind.
- `frontend/src/lib/realtime.channels.test.tsx` — 12 tests: channel classification, per
  channel signals, burst coalescing, timer slowdown, single connection, badge states.
- `frontend/src/lib/realtime.coverage.test.ts` — 3 tests: the ratchet above.
