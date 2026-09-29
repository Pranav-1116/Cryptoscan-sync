"""Cross-instance event federation via Redis pub/sub.

The in-process :class:`~api.events.bus.EventBus` only reaches SSE clients on the
*same* node. For a multi-replica deployment, each node publishes every event to
a Redis channel and subscribes to the same channel, re-publishing events from
*other* nodes into its local bus. A node ignores its own messages so there is no
echo loop, and each node still assigns its own monotonic local ids (so
Last-Event-ID resume stays per-node consistent).

Opt-in and graceful: it only activates when a Redis client is supplied. Without
Redis the bus behaves exactly as before (cross-process events still come in via
the durable DB tailer).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import json
import os
import socket
import threading
from typing import Any

CHANNEL = "zelinx:events"


def start_redis_federation(redis_client, bus, *, node_id: str | None = None):
    """Attach a :class:`RedisEventSync` to ``bus`` and begin subscribing.

    Returns the sync handle, or ``None`` if the client is unusable. Always
    opt-in (only called when ``REDIS_URL`` is configured).
    """
    identity = node_id or f"{socket.gethostname()}-{os.getpid()}"
    try:
        sync = RedisEventSync(redis_client, bus, identity)
        bus.set_remote_publisher(sync.publish)
        sync.start()
        return sync
    except Exception as _handler_exc:  # noqa: BLE001 — no Redis => keep the local bus
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None


class RedisEventSync:
    """Publish local events out and re-inject remote events into the local bus."""

    def __init__(self, redis_client, bus, node_id: str) -> None:
        self._redis = redis_client
        self._bus = bus
        self._node_id = node_id
        self._thread: threading.Thread | None = None
        self._pubsub = None

    # ---------------------------------------------------------- publishing
    def publish(self, event: dict[str, Any]) -> None:
        """Best-effort: never let a Redis outage break the local bus."""
        try:
            frame = {
                "node": self._node_id,
                "type": event.get("type"),
                "source": event.get("source"),
                "payload": event.get("payload") or {},
                "ts": event.get("ts"),
            }
            self._redis.publish(CHANNEL, json.dumps(frame, default=str))
        except Exception as _handler_exc:  # noqa: BLE001
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            pass

    # ---------------------------------------------------------- subscribing
    def start(self) -> None:
        try:
            self._pubsub = self._redis.pubsub()
            self._pubsub.subscribe(CHANNEL)
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="zelinx-redis-sync")
            self._thread.start()
        except Exception:  # noqa: BLE001 — no Redis => stay on the local bus
            self._pubsub = None

    def stop(self) -> None:
        try:
            if self._pubsub is not None:
                self._pubsub.close()
        except Exception as _handler_exc:  # noqa: BLE001
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            pass

    def _run(self) -> None:
        try:
            for msg in self._pubsub.listen():
                if msg.get("type") != "message":
                    continue
                try:
                    frame = json.loads(msg["data"])
                except (TypeError, ValueError):
                    continue
                # ignore our own echo, keep monotonic per-node ids
                if frame.get("node") == self._node_id:
                    continue
                self._bus.inject_remote(frame)
        except Exception as _handler_exc:  # noqa: BLE001 — stop the thread quietly on Redis loss
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            pass
