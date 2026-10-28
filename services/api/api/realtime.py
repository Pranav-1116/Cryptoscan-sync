"""The product's realtime contract: one channel per surface a screen can watch.

The platform already had a realtime *transport* — a durable estate journal, a
tenant-filtered pub/sub bus and an SSE stream with resume. What it did not have is a
**contract**: events were emitted under ad-hoc names (`graph.updated`,
`remediation.task_verified`, `estate.change.detected`), so a screen could not say what it
depends on, nothing could tell a polling screen that its data is already pushed, and a
typo in an event name produced an event that nothing could ever receive.

This module is that contract, and it is deliberately small:

* **channels** are product surfaces, not event sources. `remediation` is a channel; the
  four `remediation.task_*` events are *kinds* on it. A screen subscribes to a channel and
  refetches one resource, rather than pattern-matching event names it half remembers;
* **every kind is declared here**, and :func:`publish` refuses a combination that is not
  declared. A publisher cannot invent a kind, so the catalogue cannot advertise something
  nothing emits;
* **existing events are classified, not renamed.** :func:`classify` maps the event names
  already in the tree onto `(channel, kind)`, so the estate, drift, remediation and graph
  code keeps working while their events become addressable. A type that classifies to
  nothing is counted and reported, not silently dropped.

Two limits are stated rather than implied:

* the per-channel ``sequence`` is a **per-process counter for coalescing**, not a resume
  token. Resume authority stays with the durable journal cursor; a sequence resets on
  restart, and treating it as an offset would silently skip events after a deploy;
* a channel being declared does not mean anything publishes it yet. :func:`catalog` reports
  ``last_event_at`` and the routed/unrouted counts so "we have a channel for that" can never
  be read as "that surface is live".
"""
from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.realtime/1"

#: the maximum number of unrouted event types remembered for the catalogue. This is a
#: debugging aid, not a history: enough to see what is emitting outside the contract.
UNROUTED_CAP = 200


@dataclass(frozen=True)
class Channel:
    """One product surface a screen can watch.

    ``resource`` is the read path a subscriber should refetch when a kind arrives — the
    reason this is a contract and not a list of strings. ``kinds`` maps a kind to the
    platform event types that produce it; an empty tuple means the kind exists only for
    direct publishers (see :func:`publish`).
    """

    name: str
    title: str
    what: str
    resource: str
    kinds: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    screens: tuple[str, ...] = ()

    def public(self) -> dict[str, Any]:
        return {
            "channel": self.name,
            "title": self.title,
            "what": self.what,
            "resource": self.resource,
            "screens": list(self.screens),
            "kinds": {
                kind: {"from_event_types": list(types)}
                for kind, types in sorted(self.kinds.items())
            },
        }


#: The channels, in the order the console reads them. Kinds are declared with the platform
#: event types that already produce them, so classification and the catalogue cannot drift
#: apart: adding a kind here is what makes ``publish(channel, kind)`` legal.
CHANNELS: tuple[Channel, ...] = (
    Channel(
        name="estate",
        title="Estate",
        what="discovery runs, coverage changes and detected estate changes",
        resource="/estate/evidence/changes",
        screens=("Live estate", "Changes", "Discovery"),
        kinds={
            "run_started": ("estate.run.started",),
            "run_finished": ("estate.run.finished",),
            "run_failed": ("estate.run.failed",),
            "plane_finished": ("estate.plane.finished",),
            "change_detected": ("estate.change.detected",),
            "coverage_lost": ("estate.coverage.lost",),
        },
    ),
    Channel(
        name="twin",
        title="Digital twin",
        what="twin snapshots, graph rebuilds and graph-store loads",
        resource="/estate/evidence/twin",
        screens=("Digital Twin", "Graph Explorer"),
        kinds={
            "snapshot": ("digital_twin.snapshot", "graph.snapshot"),
            "graph_updated": ("graph.updated",),
        },
    ),
    Channel(
        name="crypto",
        title="Cryptography",
        what="BOM projections and evidence-chain integrity",
        resource="/cbom",
        screens=("Crypto Inventory (CBOM)", "Cryptography", "Findings"),
        kinds={
            "bom_snapshot": ("technology_bom.snapshot",),
            "bom_export": ("technology_bom.export",),
            "evidence_package": ("technology_bom.evidence_package",),
            "chain_broken": ("evidence.chain_broken",),
        },
    ),
    Channel(
        name="inventory",
        title="Inventory",
        what="asset lifecycle and ownership changes",
        resource="/inventory/assets",
        screens=("Assets", "Applications", "Cloud", "Hardware"),
        kinds={
            "asset_lifecycle": ("inventory.asset_lifecycle",),
            "asset_ownership": ("inventory.asset_ownership",),
        },
    ),
    Channel(
        name="remediation",
        title="Remediation",
        what="tasks opened, accepted, completed and verified",
        resource="/remediation/tasks",
        screens=("Remediation Tasks", "Remediation Priorities"),
        kinds={
            "task_created": ("remediation.task_created", "remediation.drift_tasks_created"),
            "task_accepted": ("remediation.task_accepted",),
            "task_completed": ("remediation.task_completed",),
            "task_verified": ("remediation.task_verified",),
        },
    ),
    Channel(
        name="security",
        title="Security posture",
        what="posture drops, policy changes and cascade conditions",
        resource="/security/policy",
        screens=("Dashboard", "Policies", "Banking & SWIFT"),
        kinds={
            "posture_drop": ("security.posture_drop",),
            "policy_updated": ("security.policy_updated",),
            "cascade_changed": (
                "cascade.operational_conditions_changed",
                "cascade.blast_radius_changed",
            ),
        },
    ),
    Channel(
        name="notifications",
        title="Notifications",
        what="dispatch of notifications to their destinations",
        resource="/notifications",
        screens=("Activity",),
        kinds={
            "dispatched": ("notifications.dispatched",),
        },
    ),
    Channel(
        name="findings",
        title="Findings",
        what="findings raised, triaged and closed",
        resource="/findings",
        screens=("Findings", "Scan"),
        kinds={
            # kinds with no mapped platform event type are published directly by the code
            # that changes the surface; they exist here so that publish() accepts them
            "status_changed": (),
        },
    ),
)

CHANNEL_INDEX: dict[str, Channel] = {channel.name: channel for channel in CHANNELS}

#: event types that are deliberately not on a channel. These are operator-facing but not
#: surface state: a schedule being created does not change what any screen shows. Keeping
#: the list explicit is what lets the invariant "every emitted event is classified" hold
#: without pretending these are unhandled.
UNCHANNELLED = frozenset({
    "technology_bom.schedule",
    "technology_bom.schedule_run",
    "technology_bom.cascade",
    "retirement.registered",
    "retirement.lifted",
    "retirement.reintroduced",
})

# every event type declared anywhere in this module classifies to exactly one kind
_EVENT_ROUTES: dict[str, tuple[str, str]] = {
    event_type: (channel.name, kind)
    for channel in CHANNELS
    for kind, types in channel.kinds.items()
    for event_type in types
}

_LOCK = threading.Lock()
_SEQUENCES: dict[str, itertools.count] = {}
_COUNTS: dict[str, int] = {}
_UNROUTED: dict[str, int] = {}
_LAST: dict[str, dict[str, Any]] = {}


def channels(names: Iterable[str] | None = None) -> list[Channel]:
    """The declared channels, or the named ones. An unknown name is an error, not silence."""
    if names is None:
        return list(CHANNELS)
    wanted = [str(name).strip() for name in names if str(name).strip()]
    unknown = [name for name in wanted if name not in CHANNEL_INDEX]
    if unknown:
        raise ValueError(
            f"unknown realtime channel(s) {', '.join(sorted(unknown))}; "
            f"expected one of {', '.join(sorted(CHANNEL_INDEX))}"
        )
    return [CHANNEL_INDEX[name] for name in wanted]


def classify(event_type: str) -> tuple[str, str] | None:
    """Which channel and kind carry this platform event type, if any."""
    return _EVENT_ROUTES.get(str(event_type or ""))


def _next_sequence(channel: str) -> int:
    counter = _SEQUENCES.get(channel)
    if counter is None:
        counter = itertools.count(1)
        _SEQUENCES[channel] = counter
    return next(counter)


def stamp(event_type: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
    """Add ``channel`` / ``kind`` / ``sequence`` to an event's payload, or return None.

    Called for every platform event, including the ones emitted before this contract
    existed. It never raises and never overwrites an explicit value: a publisher that has
    already decided its channel keeps it, and an unclassifiable event is counted rather
    than given an invented channel.
    """
    try:
        route = classify(event_type)
        if route is None:
            with _LOCK:
                if event_type not in UNCHANNELLED and len(_UNROUTED) < UNROUTED_CAP:
                    _UNROUTED[str(event_type)] = _UNROUTED.get(str(event_type), 0) + 1
            return None
        channel, kind = route
        body = dict(payload or {})
        body.setdefault("channel", channel)
        body.setdefault("kind", kind)
        body.setdefault("sequence", _next_sequence(channel))
        with _LOCK:
            _COUNTS[channel] = _COUNTS.get(channel, 0) + 1
            _LAST[channel] = {
                "kind": body["kind"],
                "sequence": body["sequence"],
                "event_type": event_type,
            }
        return body
    except Exception:  # noqa: BLE001 — a routing bug must never fail an operation
        return None


def publish(
    channel: str,
    kind: str,
    *,
    detail: str,
    payload: Mapping[str, Any] | None = None,
    target_name: str | None = None,
    tenant_id: str | None = None,
    session: Any | None = None,
) -> dict[str, Any] | None:
    """Emit one domain change on a channel.

    The ``(channel, kind)`` pair must be declared. Everything else is delegated to
    :func:`api.events.platform_events.emit_platform_event`, so a published change is also a
    durable audit row and reaches cross-process subscribers — this is a vocabulary, not a
    second transport.

    ``session`` follows the same rule as the underlying emitter: a caller already inside an
    open transaction passes it, or the event lands in a different transaction from the
    change it describes.
    """
    spec = CHANNEL_INDEX.get(str(channel))
    if spec is None:
        raise ValueError(
            f"unknown realtime channel {channel!r}; expected one of "
            f"{', '.join(sorted(CHANNEL_INDEX))}"
        )
    if kind not in spec.kinds:
        raise ValueError(
            f"unknown kind {kind!r} on channel {channel!r}; expected one of "
            f"{', '.join(sorted(spec.kinds))}"
        )

    from api.events.platform_events import emit_platform_event

    return emit_platform_event(
        f"{channel}.{kind}",
        detail,
        {
            "channel": channel,
            "kind": kind,
            "sequence": _next_sequence(channel),
            **dict(payload or {}),
        },
        target_name=target_name or channel,
        tenant_id=tenant_id,
        session=session,
    )


def wants(channel_names: Iterable[str] | None, event: Mapping[str, Any]) -> bool:
    """Does this event belong to one of the channels a subscriber asked for?

    ``None`` means every routable event. Unrouted events are excluded from a filtered
    stream rather than passed through: a client that asked for ``findings`` has no use for
    an event nobody classified, and sending it invites a client to guess.
    """
    payload = event.get("payload") or {}
    channel = payload.get("channel") if isinstance(payload, Mapping) else None
    if not channel:
        return False
    if channel_names is None:
        return True
    return channel in set(channel_names)


def event_filter(channel_names: Iterable[str] | None, *, visible: Any = None):
    """A bus filter combining channel selection with the caller's visibility predicate."""
    wanted = None if channel_names is None else frozenset(channel_names)

    def _filter(event: Mapping[str, Any]) -> bool:
        if visible is not None and not visible(event):
            return False
        return wants(wanted, event)

    return _filter


def catalog(
    *,
    recent_events: Iterable[Mapping[str, Any]] | None = None,
    stats: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The channels, what each carries, and whether anything has ever arrived on it."""
    last_seen: dict[str, dict[str, Any]] = {}
    for event in recent_events or ():
        payload = event.get("payload") or {}
        channel = payload.get("channel") if isinstance(payload, Mapping) else None
        if not channel:
            continue
        last_seen[channel] = {
            "event_id": event.get("id"),
            "type": event.get("type"),
            "kind": payload.get("kind"),
            "at": event.get("ts"),
        }

    rows = []
    for channel in CHANNELS:
        last = last_seen.get(channel.name) or _LAST.get(channel.name)
        rows.append({
            **channel.public(),
            "last_event": last,
            "published_this_process": _COUNTS.get(channel.name, 0),
        })

    unrouted = dict(sorted(_UNROUTED.items(), key=lambda item: -item[1]))
    return {
        "schema": SCHEMA,
        "channels": rows,
        "stream": "/api/v1/realtime/stream",
        "subscriber_count": (stats or {}).get("subscribers"),
        "events_published": (stats or {}).get("published_total"),
        "unrouted": {
            "event_types": unrouted,
            "meaning": (
                "platform event types that carry no channel, so no surface can subscribe to "
                "them. They are still persisted and still audited; they are just not pushed "
                "anywhere addressable"
            ),
        },
        "unchannelled": sorted(UNCHANNELLED),
        "meaning": (
            "a channel is a product surface, not an event source: subscribe to one, refetch "
            "its resource when a kind arrives, and stop polling it"
        ),
        "limits": [
            "sequence is a per-process counter for coalescing, not a resume token — resume "
            "authority stays with the durable journal cursor, and a sequence restarts at 1 "
            "after a restart",
            "a declared channel is not a live one: last_event is null until something on that "
            "surface actually changes, and published_this_process counts this process only",
            "the stream is a delivery path. The estate journal remains the audit authority, so "
            "a channel stream that misses a frame is a reason to refetch, not a lost record",
        ],
    }


def reset_for_tests() -> None:
    """Forget per-process counters. Test-only: the contract itself is immutable."""
    with _LOCK:
        _SEQUENCES.clear()
        _COUNTS.clear()
        _UNROUTED.clear()
        _LAST.clear()
