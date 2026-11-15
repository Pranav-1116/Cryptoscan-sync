"""Redis-backed read cache — the shared tier, under the same honesty rules.

``api.cache.ReadCache`` is the in-process tier: bounded, tenant-keyed,
tag-invalidated, TTL-floored. This module is the same contract over Redis,
for deployments running several API replicas (the spec's "Redis caching —
dashboard summaries, lookup data and transient state"). One replica's
write invalidating only its own cache is how two replicas serve different
dashboards; a shared tier makes the tag invalidation cluster-wide.

Rules that do not change with the backend — they are the policy, not the
transport:

* **Never authoritative.** ``api.cache_policy`` decides what may be
  cached; evidence status, certificate expiration, asset freshness, risk
  findings, user permissions and Digital Twin state are never stored here
  either — the policy's chokepoint is backend-agnostic (pinned by test).
* **Tenant-first keys.** Callers build keys with ``ReadCache.key`` —
  the tenant part is structural, never a convention.
* **TTL is the staleness ceiling.** Every entry expires; a Redis that
  "lost" an invalidation can only be ``ttl_seconds`` wrong.
* **Bounded.** ``max_entries`` is enforced with a sampled-LRU trim on
  write (an unbounded Redis cache is a second database with worse
  semantics).
* **Fail toward the truth.** If Redis is unreachable, the read falls back
  to computing fresh and counting a ``backend_errors`` — a cache outage
  must never become a data outage.

The client is injected (boto3-style: any object with get/set/delete/keys/
zadd/zrem/zrange/expire/pipeline-ish behavior), so tests run against a
fake and production runs against the bank's Redis.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable, Iterable, Optional

from api.cache import ReadCache


class RedisReadCache:
    """ReadCache's contract over a Redis-shaped client."""

    def __init__(self, client: Any, *, ttl_seconds: float = 30.0,
                 max_entries: int = 2048, namespace: str = "rsc",
                 clock: Callable[[], float] = time.monotonic):
        if ttl_seconds <= 0 or max_entries <= 0:
            raise ValueError("ttl_seconds and max_entries are positive — the "
                             "same limits as the in-process tier")
        self.client = client
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.namespace = namespace
        self._clock = clock
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._invalidated = 0
        self._backend_errors = 0

    # ------------------------------------------------------------- key layout
    def _k(self, key: str) -> str:
        return f"{self.namespace}:v:{key}"

    def _index_key(self) -> str:
        return f"{self.namespace}:index"

    def _tag_key(self, tag: str) -> str:
        return f"{self.namespace}:tag:{tag}"

    @staticmethod
    def key(*parts: Any) -> str:
        return ReadCache.key(*parts)

    # ------------------------------------------------------------------- ops
    def get(self, key: str) -> Optional[Any]:
        try:
            raw = self.client.get(self._k(key))
        except Exception:  # noqa: BLE001 — cache outage ≠ data outage
            self._count("_backend_errors")
            return None
        if raw is None:
            self._count("_misses")
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        try:
            envelope = json.loads(raw)
        except (ValueError, TypeError):
            # A value we cannot parse is a value we must not trust.
            self._count("_misses")
            return None
        self._count("_hits")
        return envelope.get("v")

    def set(self, key: str, value: Any, *, tags: Iterable[str] = ()) -> None:
        tags = set(tags)
        envelope = json.dumps({"v": value, "t": sorted(tags)})
        try:
            pipe = self.client.pipeline() if hasattr(self.client, "pipeline") else self.client
            pipe.set(self._k(key), envelope, ex=int(self.ttl_seconds) or 1)
            # membership index for bounded trimming (score = insertion order)
            pipe.zadd(self._index_key(), {self._k(key): self._clock()})
            for tag in tags:
                pipe.zadd(self._tag_key(tag), {self._k(key): self._clock()})
            if hasattr(pipe, "execute"):
                pipe.execute()
            self._trim()
        except Exception:  # noqa: BLE001
            self._count("_backend_errors")

    def get_or_set(self, key: str, compute: Callable[[], Any],
                   *, tags: Iterable[str] = ()) -> Any:
        value = self.get(key)
        if value is not None:
            return value
        value = compute()
        self.set(key, value, tags=tags)
        return value

    def invalidate(self, *tags: str) -> int:
        dropped = 0
        for tag in tags:
            try:
                members = self.client.zrange(self._tag_key(tag), 0, -1)
                for member in members:
                    key = member.decode("utf-8") if isinstance(member, bytes) else str(member)
                    self.client.delete(key)
                    self.client.zrem(self._index_key(), key)
                    dropped += 1
                self.client.delete(self._tag_key(tag))
            except Exception:  # noqa: BLE001
                self._count("_backend_errors")
        with self._lock:
            self._invalidated += dropped
        return dropped

    def clear(self) -> None:
        try:
            for member in self.client.zrange(self._index_key(), 0, -1):
                self.client.delete(member)
            self.client.delete(self._index_key())
            # tag sets are cleaned lazily by invalidate; drop the namespace
            for member in self.client.keys(f"{self.namespace}:tag:*"):
                self.client.delete(member)
        except Exception:  # noqa: BLE001
            self._count("_backend_errors")

    def _trim(self) -> None:
        """Enforce max_entries: evict oldest first, counted like the LRU tier."""
        try:
            size = self.client.zcard(self._index_key())
            excess = int(size) - self.max_entries
            if excess <= 0:
                return
            victims = self.client.zrange(self._index_key(), 0, excess - 1)
            for victim in victims:
                self.client.delete(victim)
                self.client.zrem(self._index_key(), victim)
            with self._lock:
                self._evictions += len(victims)
        except Exception:  # noqa: BLE001
            self._count("_backend_errors")

    def _count(self, attr: str) -> None:
        with self._lock:
            setattr(self, attr, getattr(self, attr) + 1)

    def as_dict(self) -> dict:
        with self._lock:
            try:
                entries = int(self.client.zcard(self._index_key()))
            except Exception:  # noqa: BLE001
                entries = -1  # honest: unknown, never reported as 0
            return {
                "backend": "redis",
                "entries": entries,
                "max_entries": self.max_entries,
                "ttl_seconds": self.ttl_seconds,
                "hits_total": self._hits,
                "misses_total": self._misses,
                "evictions_total": self._evictions,
                "invalidated_total": self._invalidated,
                "backend_errors_total": self._backend_errors,
            }
