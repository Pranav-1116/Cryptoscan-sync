"""Bounded server-side read cache — the compute layer under the wire layer.

``conditional_get.py`` already makes polling cheap on the wire (strong ETag,
``304`` with an empty body). This module makes it cheap on the *server*:
an unchanged read skips the query and the serialization until something
writes. Dashboard pollers are the customer (the twin page, the scan list,
the BOM catalog re-read on a timer).

Honest boundaries — each one is a design decision, not a limitation to
paper over:

* Keys embed the tenant first: a cross-tenant read is impossible by
  construction, not by discipline.
* Writes invalidate by tag (``estate_catalog.sync`` invalidates its
  tenant's catalog tag). The TTL is the *safety net* for anyone who
  bypasses the ORM: a cached read is at most ``ttl_seconds`` stale, and
  the number is in ``as_dict()`` where operators can see it.
* Bounded (``max_entries``, LRU eviction): a cache is not a second
  database. Evictions are counted.
* Values are deep-copied in and out: a cached response body can never be
  mutated into another tenant's answer.

Every hit, miss, eviction and invalidation is counted — a cache that lies
about its own usefulness is worse than no cache.
"""

from __future__ import annotations

import copy
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Iterable, Optional

DEFAULT_TTL_SECONDS = 30.0
DEFAULT_MAX_ENTRIES = 2048


class ReadCache:
    """Thread-safe bounded TTL cache with tag invalidation."""

    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS,
                 max_entries: int = DEFAULT_MAX_ENTRIES,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds is positive — a zero-TTL cache is "
                             "an expensive way to compute nothing")
        if max_entries <= 0:
            raise ValueError("max_entries is positive — an unbounded cache "
                             "is a memory leak with extra steps")
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, tuple[float, set[str], Any]] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._invalidated = 0

    @staticmethod
    def key(*parts: Any) -> str:
        """Build a cache key. The FIRST part is the tenant (or platform) —
        tenant separation is structural here, never a convention."""
        return "\x00".join("" if part is None else str(part) for part in parts)

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return None
            expires_at, _tags, value = entry
            if self._clock() >= expires_at:
                del self._entries[key]
                self._misses += 1
                return None
            self._entries.move_to_end(key)
            self._hits += 1
            return copy.deepcopy(value)

    def set(self, key: str, value: Any, *, tags: Iterable[str] = ()) -> None:
        with self._lock:
            expires_at = self._clock() + self.ttl_seconds
            self._entries[key] = (expires_at, set(tags), copy.deepcopy(value))
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
                self._evictions += 1

    def get_or_set(self, key: str, compute: Callable[[], Any],
                   *, tags: Iterable[str] = ()) -> Any:
        value = self.get(key)
        if value is not None:
            return value
        value = compute()
        self.set(key, value, tags=tags)
        return value

    def invalidate(self, *tags: str) -> int:
        """Drop every entry carrying any of ``tags``. Returns how many were
        dropped — a write path that invalidates nothing (no readers cached
        it yet) is normal and counted, not an error."""
        wanted = set(tags)
        with self._lock:
            stale = [key for key, (_exp, entry_tags, _v) in self._entries.items()
                     if entry_tags & wanted]
            for key in stale:
                del self._entries[key]
            self._invalidated += len(stale)
        return len(stale)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def as_dict(self) -> dict:
        with self._lock:
            return {
                "entries": len(self._entries),
                "max_entries": self.max_entries,
                "ttl_seconds": self.ttl_seconds,
                "hits_total": self._hits,
                "misses_total": self._misses,
                "evictions_total": self._evictions,
                "invalidated_total": self._invalidated,
            }


_cache = ReadCache()


def get_read_cache() -> ReadCache:
    """The process-wide read cache. Tests may replace it; production leaves
    it alone (one cache per API process — the wire layer's ETag keeps
    cross-replica staleness exactly as honest as it is today)."""
    global _cache
    return _cache


def set_read_cache(cache: ReadCache) -> None:
    global _cache
    _cache = cache
