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
- The buffer is in-memory: history survives disconnects but not a restart,
  and events do NOT cross process boundaries. Events originating in other
  processes (the monitor daemon) are federated by the DB tailer in
  api.routers.events, which republishes them here.
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

    def __init__(self) -> None:
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE)
        self.dropped: int = 0
        self.closed: bool = False
        try:
            self.loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:  # subscribed outside a loop — delivery via thread safety still works
            self.loop = None

    def deliver(self, event: dict[str, Any]) -> None:
        if self.closed or self.loop is None:
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
        self._remote_publisher: Any = None

    def set_remote_publisher(self, fn: Any) -> None:
        """Optional cross-process publisher (e.g. Redis pub/sub) invoked after
        every local publish. Never mutates or throws into the local path."""
        self._remote_publisher = fn

    # ------------------------------------------------------------- publishing

    def publish(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        source: str = "api",
    ) -> dict[str, Any]:
        event = {
            "id": next(self._counter),
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": str(event_type),
            "source": str(source),
            "payload": payload or {},
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
            except Exception as _handler_exc:  # noqa: BLE001 — never let Redis break publishing
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass
        return event

    def inject_remote(self, frame: dict[str, Any]) -> dict[str, Any]:
        """Re-publish an event that arrived from another node (Redis sync).

        Gives it a fresh local id (so ids stay monotonic per node and
        Last-Event-ID resume is consistent) and delivers to local subscribers
        WITHOUT re-publishing to Redis (avoids an echo loop).
        """
        event = {
            "id": next(self._counter),
            "ts": frame.get("ts") or datetime.now(timezone.utc).isoformat(),
            "type": str(frame.get("type") or "remote.event"),
            "source": str(frame.get("source") or "remote"),
            "payload": frame.get("payload") or {},
        }
        with self._lock:
            self._history.append(event)
            self._published_total += 1
            subs = list(self._subs)
        for sub in subs:
            sub.deliver(event)
        return event

    # ---------------------------------------------------------- subscribing

    def subscribe(self) -> Subscription:
        sub = Subscription()
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
        rows = [e for e in snapshot if e["id"] > since_id]
        return rows[-max(1, limit):]

    def latest_id(self) -> int:
        with self._lock:
            return self._history[-1]["id"] if self._history else 0

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "events_buffered": len(self._history),
                "subscribers": len(self._subs),
                "latest_id": self._history[-1]["id"] if self._history else 0,
                "published_total": self._published_total,
            }

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
