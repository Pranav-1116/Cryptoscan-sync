"""In-memory TTL cache for live CVE lookups. Redis optional, fail-open."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Iterable

logger = logging.getLogger(__name__)


class CveCache:
    def __init__(
        self,
        ttl_seconds: float = 3600,
        max_entries: int = 2048,
        redis_url: str | None = None,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._store: dict[str, tuple[float, Any]] = {}
        self._redis = self._connect(redis_url)

    def _connect(self, redis_url: str | None) -> Any:
        url = redis_url or os.environ.get("REDIS_URL") or os.environ.get("CRYPTOSCAN_REDIS_URL") or ""
        if not url:
            return None
        try:
            import redis

            client = redis.Redis.from_url(url, decode_responses=True)
            client.ping()
            return client
        except Exception as exc:
            logger.info("cve_cache_redis_disabled", extra={"error": str(exc)})
            return None

    def key_for(self, packages: Iterable[dict[str, Any]], *, live: bool = False) -> str:
        rows = [
            {
                "name": item.get("name"),
                "version": item.get("version"),
                "manager": item.get("manager"),
            }
            for item in packages
        ]
        payload = json.dumps({"live": bool(live), "packages": rows}, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Any | None:
        if not key:
            return None
        if self._redis is not None:
            try:
                raw = self._redis.get(f"cve:{key}")
                if raw:
                    return json.loads(raw)
            except Exception as exc:
                logger.info("cve_cache_redis_get_failed", extra={"error": str(exc)})
        hit = self._store.get(key)
        if hit is None:
            return None
        expires_at, value = hit
        if expires_at < time.time():
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        if not key:
            return
        if self._redis is not None:
            try:
                self._redis.setex(f"cve:{key}", int(self.ttl_seconds), json.dumps(value))
            except Exception as exc:
                logger.info("cve_cache_redis_set_failed", extra={"error": str(exc)})
        if len(self._store) >= self.max_entries:
            oldest = min(self._store, key=lambda item: self._store[item][0])
            self._store.pop(oldest, None)
        self._store[key] = (time.time() + self.ttl_seconds, value)

    def clear(self) -> None:
        self._store.clear()
