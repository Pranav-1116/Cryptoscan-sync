#!/usr/bin/env python3
"""Exercise the multi-replica realtime contract without claiming deployment proof.

The drill uses the production ``EventBus`` and ``RedisEventSync`` against a
small in-process Redis protocol double. It proves shared sequence allocation,
stream replay, last-event-id recovery, and tenant filtering at the subscriber
boundary. It does not prove Redis HA, network partitions, capacity, or a
Kubernetes deployment; those remain live qualification requirements.
"""
from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from typing import Any

ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))
sys.path.extend(str(path) for path in sorted((ROOT / "services").glob("*/")) if path.is_dir())

from api.events.bus import EventBus
from api.events.redis_sync import RedisEventSync


class FakeRedis:
    def __init__(self) -> None:
        self.sequence = 0
        self.stream: list[tuple[str, dict[str, str]]] = []
        self.published: list[str] = []

    def ping(self) -> bool:
        return True

    def incr(self, key: str) -> int:
        self.sequence += 1
        return self.sequence

    def get(self, key: str) -> str:
        return str(self.sequence)

    def xadd(self, stream: str, fields: dict[str, str], **_: Any) -> str:
        self.stream.append((str(self.sequence), dict(fields)))
        return str(self.sequence)

    def xrange(self, stream: str, min: str = "-", max: str = "+", count: int | None = None):
        values = list(self.stream)
        return values[:count] if count else values

    def publish(self, channel: str, payload: str) -> int:
        self.published.append(payload)
        return 1


async def _tenant_filter_check(bus: EventBus) -> bool:
    loop = asyncio.get_running_loop()
    tenant_a = bus.subscribe(event_filter=lambda event: event.get("tenant_id") == "tenant-a")
    tenant_b = bus.subscribe(event_filter=lambda event: event.get("tenant_id") == "tenant-b")
    tenant_a.loop = loop
    tenant_b.loop = loop
    bus.inject_remote({"id": 2, "type": "crypto.observed", "source": "replica-a", "tenant_id": "tenant-a", "payload": {"algorithm": "AES"}})
    await asyncio.sleep(0)
    a = await tenant_a.queue.get()
    b_empty = tenant_b.queue.empty()
    bus.unsubscribe(tenant_a)
    bus.unsubscribe(tenant_b)
    return a["tenant_id"] == "tenant-a" and b_empty


def run() -> dict[str, Any]:
    redis = FakeRedis()
    bus_a = EventBus()
    bus_b = EventBus()
    sync_a = RedisEventSync(redis, bus_a, "replica-a", required=True)
    sync_b = RedisEventSync(redis, bus_b, "replica-b", required=True)
    bus_a.set_durable_history(next_id=sync_a.next_id, recent=sync_a.recent, latest=sync_a.latest, oldest=sync_a.oldest)
    bus_b.set_durable_history(next_id=sync_b.next_id, recent=sync_b.recent, latest=sync_b.latest, oldest=sync_b.oldest)
    bus_a.set_remote_publisher(sync_a.publish)
    event = bus_a.publish("crypto.observed", {"algorithm": "AES-GCM"}, source="scanner", tenant_id="tenant-a")
    frame = json.loads(redis.published[-1])
    bus_b.inject_remote(frame)
    replay = bus_b.recent(since_id=0, limit=10)
    filtered = asyncio.run(_tenant_filter_check(bus_b))
    checks = {
        "shared_sequence": event["id"] == 1 and frame["id"] == 1,
        "durable_stream_append": len(redis.stream) == 1,
        "cross_replica_injection": any(row.get("id") == 1 for row in replay),
        "last_event_id_replay": [row["id"] for row in bus_b.recent(since_id=1)] == [2],
        "tenant_filter_before_queue": filtered,
        "no_secret_values": "secret" not in json.dumps(redis.stream).lower(),
    }
    return {
        "schema": "cryptoscan.realtime-replica-drill/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checks": [{"name": name, "status": "PASS" if ok else "FAIL"} for name, ok in checks.items()],
        "verdict": "PASS" if all(checks.values()) else "FAIL",
        "scope": "In-process transport simulation only; no Redis HA, network partition, load, multi-host, or tenant deployment evidence.",
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["verdict"] == "PASS" else 2)
