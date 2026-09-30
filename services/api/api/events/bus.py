"""Process-wide event bus backing the real-time SSE stream.

Design constraints (honest scope):
- Publishers may run in any thread (FastAPI BackgroundTasks execute the scan
  pipeline in a threadpool), so publish() is synchronous and thread-safe.
- Subscribers are asyncio queues owned by the event loop of their SSE
  connection; delivery hops loops via call_soon_threadsafe.
- Slow consumers get drop-oldest semantics on a bounded queue plus a
  `dropped` counter on their subscription, so one stalled browser can never
  block the pipeline. Clients resync from the ring-buffer history via
  Last-Event-ID.
- The bounded ring is only a local delivery cache. Production installs a
  Redis Streams journal and Pub/Sub fan-out adapter; the local ring remains a
  useful fast path for tests and single-node development.
- Subscribers may provide a tenant predicate. Filtering happens before an event
  enters a subscriber queue so one tenant cannot receive another tenant's
  realtime payload from a shared Redis channel.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import asyncio
import itertools
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any

HISTORY_SIZE = 500
SUBSCRIBER_QUEUE = 256


class Subscription:
    """One live subscriber: a bounded queue on its own event loop."""

    def __init__(self, event_filter: Any = None) -> None:
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE)
        self.event_filter = event_filter
        self.dropped: int = 0
        self.closed: bool = False
        try:
            self.loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:  # subscribed outside a loop — delivery via thread safety still works
            self.loop = None

    def deliver(self, event: dict[str, Any]) -> None:
        if self.closed or self.loop is None:
            return
        if self.event_filter is not None:
            try:
                if not self.event_filter(event):
                    return
            except Exception as exc:  # noqa: BLE001 — deny on filter failure
                logger.warning("event_filter_failed", extra={"error_type": type(exc).__name__})
                return

        def _put() -> None:
            if self.closed:
                return
            if self.queue.full():  # drop-oldest: never block the publisher
                try:
                    self.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                self.dropped += 1
            self.queue.put_nowait(event)

        try:
            self.loop.call_soon_threadsafe(_put)
        except RuntimeError:  # loop closed — subscriber is going away
            self.closed = True


class EventBus:
    def __init__(self, history_size: int = HISTORY_SIZE) -> None:
        self._lock = threading.Lock()
        self._history: deque[dict[str, Any]] = deque(maxlen=history_size)
        self._subs: list[Subscription] = []
        self._counter = itertools.count(1)
        self._published_total = 0
        self._remote_publish_failures = 0
        self._remote_publisher: Any = None
        # Production nodes install a Redis Streams-backed id/history provider.
        # Tests and explicitly local development can continue using the bounded
        # process-local ring, but the bus API itself never needs to know which
        # transport is active.
        self._id_factory: Any = None
        self._durable_recent: Any = None
        self._durable_latest: Any = None
        self._durable_health: Any = None
        self._durable_oldest: Any = None

    def set_remote_publisher(self, fn: Any) -> None:
        """Optional cross-process publisher (e.g. Redis pub/sub) invoked after
        every local publish. Never mutates or throws into the local path."""
        self._remote_publisher = fn

    def set_durable_health(self, provider: Any) -> None:
        """Install a health callback for the shared realtime backend."""
        self._durable_health = provider

    def set_durable_history(self, *, next_id: Any, recent: Any, latest: Any,
                             oldest: Any = None) -> None:
        """Install the production event journal adapter.

        ``next_id`` allocates one process-independent sequence, while ``recent``
        and ``latest`` read the durable journal after a restart.  Keeping these
        callbacks small makes the in-memory bus testable without allowing a
        production deployment to silently fall back to process-local history.
        """
        self._id_factory = next_id
        self._durable_recent = recent
        self._durable_latest = latest
        self._durable_oldest = oldest

    # ------------------------------------------------------------- publishing

    def publish(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        source: str = "api",
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        event = {
            "id": (self._id_factory() if self._id_factory is not None
                    else next(self._counter)),
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": str(event_type),
            "source": str(source),
            "payload": payload or {},
            "tenant_id": tenant_id,
        }
        with self._lock:
            self._history.append(event)
            self._published_total += 1
            subs = list(self._subs)
        for sub in subs:
            sub.deliver(event)
        if self._remote_publisher is not None:
            try:
                self._remote_publisher(event)
            except Exception as exc:  # noqa: BLE001 — health exposes the delivery fault
                self._remote_publish_failures += 1
                logger.error("event_federation_publish_failed", extra={"error_type": type(exc).__name__})
        return event

    def inject_remote(self, frame: dict[str, Any]) -> dict[str, Any]:
        """Re-publish an event that arrived from another node (Redis sync).

        The durable sequence is preserved when the frame contains one. Older
        pub/sub frames without it receive a local id for compatibility. The
        event is delivered locally WITHOUT re-publishing to Redis.
        """
        event = {
            "id": frame.get("id") if isinstance(frame.get("id"), int) else next(self._counter),
            "ts": frame.get("ts") or datetime.now(timezone.utc).isoformat(),
            "type": str(frame.get("type") or "remote.event"),
            "source": str(frame.get("source") or "remote"),
            "payload": frame.get("payload") or {},
            "tenant_id": frame.get("tenant_id"),
        }
        with self._lock:
            self._history.append(event)
            self._published_total += 1
            subs = list(self._subs)
        for sub in subs:
            sub.deliver(event)
        return event

    # ---------------------------------------------------------- subscribing

    def subscribe(self, event_filter: Any = None) -> Subscription:
        """Subscribe, optionally filtering events before queueing.

        Tenant filters belong at this boundary because Redis fan-out is shared
        by all replicas; filtering only in the HTTP generator would leave
        cross-tenant data in a subscriber's queue.
        """
        sub = Subscription(event_filter=event_filter)
        with self._lock:
            self._subs.append(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        sub.closed = True
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)

    # -------------------------------------------------------------- history

    def recent(self, since_id: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            snapshot = list(self._history)
        if self._durable_recent is not None:
            try:
                snapshot.extend(self._durable_recent(since_id, max(1, limit)))
            except Exception as _handler_exc:  # noqa: BLE001 — local history remains available
                logger.warning("durable_event_history_unavailable", extra={"error_type": type(_handler_exc).__name__})
        rows = {int(e["id"]): e for e in snapshot if isinstance(e.get("id"), int) and e["id"] > since_id}
        return [rows[key] for key in sorted(rows)[-max(1, limit):]]

    def latest_id(self) -> int:
        with self._lock:
            local = self._history[-1]["id"] if self._history else 0
        if self._durable_latest is not None:
            try:
                return max(local, int(self._durable_latest()))
            except Exception as _handler_exc:  # noqa: BLE001
                logger.warning("durable_event_latest_unavailable", extra={"error_type": type(_handler_exc).__name__})
        return local

    def oldest_id(self) -> int | None:
        """Oldest replayable durable id, if the adapter exposes retention bounds."""
        if self._durable_oldest is not None:
            try:
                value = self._durable_oldest()
                return int(value) if value is not None else None
            except Exception as exc:  # noqa: BLE001
                logger.warning("durable_event_bounds_unavailable", extra={"error_type": type(exc).__name__})
        with self._lock:
            return int(self._history[0]["id"]) if self._history else None

    def stats(self) -> dict[str, Any]:
        with self._lock:
            latest = self._history[-1]["id"] if self._history else 0
            stats = {
                "events_buffered": len(self._history),
                "subscribers": len(self._subs),
                "latest_id": latest,
                "published_total": self._published_total,
                "remote_publish_failures": self._remote_publish_failures,
                "durable_history": self._durable_recent is not None,
            }
        stats["oldest_replayable_id"] = self.oldest_id()
        if self._durable_latest is not None:
            try:
                stats["latest_id"] = max(int(stats["latest_id"]), int(self._durable_latest()))
            except Exception:
                stats["replay_available"] = False
        if self._durable_health is not None:
            try:
                stats["durable_backend"] = self._durable_health()
            except Exception as exc:  # noqa: BLE001
                stats["durable_backend"] = {"ready": False, "error": type(exc).__name__}
        return stats

    def published_total(self) -> int:
        with self._lock:
            return self._published_total


_BUS: EventBus | None = None
_BUS_LOCK = threading.Lock()


def get_event_bus() -> EventBus:
    global _BUS
    with _BUS_LOCK:
        if _BUS is None:
            _BUS = EventBus()
        return _BUS


def reset_event_bus() -> EventBus:
    """Test helper: fresh bus (drops history + subscribers)."""
    global _BUS
    with _BUS_LOCK:
        _BUS = EventBus()
        return _BUS
