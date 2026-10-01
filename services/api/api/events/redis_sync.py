"""Cross-instance event federation via Redis pub/sub.

The in-process :class:`~api.events.bus.EventBus` only reaches SSE clients on the
*same* node. For a multi-replica deployment, each node writes a shared Redis
Stream journal, publishes the same frame to a Redis channel, and subscribes to
the channel to deliver low-latency events from other nodes. The stream is the
replay authority after a restart or subscriber outage; Pub/Sub is only the fast
path. Tenant metadata travels with every frame so subscribers can filter before
queueing.
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
# Redis Pub/Sub provides low-latency fan-out; the stream is the durable journal
# used for Last-Event-ID replay after an API restart or subscriber outage.
EVENT_STREAM = "zelinx:events:stream"
EVENT_SEQUENCE = "zelinx:events:sequence"
EVENT_STREAM_MAXLEN = 10_000


def start_redis_federation(redis_client, bus, *, node_id: str | None = None,
                           required: bool = False):
    """Attach a :class:`RedisEventSync` to ``bus`` and begin subscribing.

    Returns the sync handle, or ``None`` if the client is unusable. Always
    opt-in (only called when ``REDIS_URL`` is configured).
    """
    identity = node_id or f"{socket.gethostname()}-{os.getpid()}"
    try:
        sync = RedisEventSync(redis_client, bus, identity, required=required)
        bus.set_remote_publisher(sync.publish)
        bus.set_remote_publish_required(required)
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

    def __init__(self, redis_client, bus, node_id: str, *, required: bool = False) -> None:
        self._redis = redis_client
        self._bus = bus
        self._node_id = node_id
        self._required = required
        self.durable_failures = 0
        self._thread: threading.Thread | None = None
        self._pubsub = None
        self.ready = False

    # ---------------------------------------------------------- durable journal
    @staticmethod
    def _value(value: Any) -> str:
        return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)

    def next_id(self) -> int:
        """Allocate one monotonic sequence shared by every API replica."""
        try:
            return int(self._redis.incr(EVENT_SEQUENCE))
        except Exception as exc:  # noqa: BLE001
            self.durable_failures += 1
            logger.error("realtime_event_sequence_failed", extra={"error_type": type(exc).__name__})
            raise RuntimeError("Redis realtime event sequence is unavailable") from exc

    def _decode_entry(self, fields: dict[Any, Any]) -> dict[str, Any] | None:
        try:
            raw = {self._value(key): self._value(value) for key, value in fields.items()}
            return {
                "id": int(raw["id"]), "ts": raw.get("ts", ""),
                "type": raw.get("type", "remote.event"),
                "source": raw.get("source", "remote"),
                "payload": json.loads(raw.get("payload", "{}")),
                "tenant_id": raw.get("tenant_id") or None,
            }
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def recent(self, since_id: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        """Replay the bounded Redis Stream journal, independent of process memory."""
        entries = self._redis.xrange(EVENT_STREAM, min="-", max="+", count=EVENT_STREAM_MAXLEN)
        rows: list[dict[str, Any]] = []
        for _stream_id, fields in entries:
            row = self._decode_entry(fields)
            if row is not None and row["id"] > int(since_id):
                rows.append(row)
        return rows[-max(1, int(limit)):]

    def latest(self) -> int:
        return int(self._redis.get(EVENT_SEQUENCE) or 0)

    def oldest(self) -> int | None:
        entries = self._redis.xrange(EVENT_STREAM, min="-", max="+", count=1)
        if not entries:
            return None
        row = self._decode_entry(entries[0][1])
        return int(row["id"]) if row is not None else None

    def health(self) -> dict[str, Any]:
        return {
            "ready": bool(self.ready),
            "journal": EVENT_STREAM,
            "channel": CHANNEL,
            "durable_failures": self.durable_failures,
        }

    # ---------------------------------------------------------- publishing
    def publish(self, event: dict[str, Any]) -> None:
        """Write the durable journal and fan out immediately to other replicas."""
        try:
            frame = {
                "id": int(event["id"]), "node": self._node_id,
                "type": event.get("type"),
                "source": event.get("source"),
                "payload": event.get("payload") or {},
                "tenant_id": event.get("tenant_id"),
                "ts": event.get("ts"),
            }
            try:
                self._redis.xadd(
                    EVENT_STREAM,
                    {"id": str(frame["id"]), "ts": str(frame["ts"]),
                     "type": str(frame["type"]), "source": str(frame["source"]),
                     "tenant_id": str(frame["tenant_id"] or ""),
                     "payload": json.dumps(frame["payload"], default=str)},
                    maxlen=EVENT_STREAM_MAXLEN, approximate=True,
                )
            except Exception as exc:  # noqa: BLE001 — journal failure is health-visible
                self.durable_failures += 1
                logger.error("durable_event_append_failed", extra={"error_type": type(exc).__name__})
                if self._required:
                    raise RuntimeError("Redis realtime event journal is unavailable") from exc
            self._redis.publish(CHANNEL, json.dumps(frame, default=str))
        except RuntimeError:
            raise
        except Exception as exc:  # noqa: BLE001
            self.durable_failures += 1
            logger.error("realtime_event_publish_failed", extra={"error_type": type(exc).__name__})
            if self._required:
                raise RuntimeError("Redis realtime event federation is unavailable") from exc

    # ---------------------------------------------------------- subscribing
    def start(self) -> None:
        try:
            self._redis.ping()
            if self._required:
                # Readiness must prove the commands used for durable IDs and
                # replay exist, not merely that TCP/PING works.
                self._redis.get(EVENT_SEQUENCE)
                self._redis.xrange(EVENT_STREAM, min="-", max="+", count=1)
            self._bus.set_durable_history(
                next_id=self.next_id, recent=self.recent, latest=self.latest,
                oldest=self.oldest)
            self._bus.set_durable_health(self.health)
            self._pubsub = self._redis.pubsub()
            self._pubsub.subscribe(CHANNEL)
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="zelinx-redis-sync")
            self._thread.start()
            self.ready = True
        except Exception:  # noqa: BLE001 — no Redis => stay on the local bus
            self._pubsub = None
            self.ready = False

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
                # Ignore our own echo. The shared event id remains unchanged
                # when a remote frame is injected, so every replica resumes
                # from the same Last-Event-ID cursor.
                if frame.get("node") == self._node_id:
                    continue
                self._bus.inject_remote(frame)
        except Exception as _handler_exc:  # noqa: BLE001 — stop the thread quietly on Redis loss
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            pass
