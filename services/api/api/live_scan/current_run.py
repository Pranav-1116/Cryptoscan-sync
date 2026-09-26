"""Shared current-scan status store for multi-instance live status.

The orchestrator keeps its authoritative run in a process-local singleton, so
only the node that ran the scan can answer `/orchestrator/status`. To let ANY
replica serve the live status in a horizontal deployment, the orchestrator
mirrors its status snapshot to this store (Redis when configured, in-memory
otherwise) and falls back to it when it has no local run. Durable scan history
is still recovered from the persisted DB snapshot / platform events.
"""

from __future__ import annotations

import json
from typing import Any

KEY = "zelinx:current_run"
TTL_SECONDS = 3600


class CurrentRunStore:
    """get/set for the latest orchestrator status snapshot."""

    def get(self) -> dict[str, Any] | None:
        raise NotImplementedError

    def set(self, status: dict[str, Any]) -> None:
        raise NotImplementedError


class MemoryCurrentRun(CurrentRunStore):
    """Default single-node store."""

    def __init__(self) -> None:
        self._value: dict[str, Any] | None = None

    def get(self) -> dict[str, Any] | None:
        return self._value

    def set(self, status: dict[str, Any]) -> None:
        self._value = status


class RedisCurrentRun(CurrentRunStore):
    """Shared store backed by a redis-py client (any Redis / Valkey / ElastiCache)."""

    def __init__(self, client) -> None:
        self._client = client

    def get(self) -> dict[str, Any] | None:
        try:
            raw = self._client.get(KEY)
            if raw is None:
                return None
            data = json.loads(raw)
            return data if isinstance(data, dict) else None
        except Exception:  # noqa: BLE001 — Redis outage => fall through to local
            return None

    def set(self, status: dict[str, Any]) -> None:
        try:
            self._client.set(KEY, json.dumps(status, default=str), ex=TTL_SECONDS)
        except Exception:  # noqa: BLE001 — never break the local path
            pass


def get_current_run_store(url: str | None) -> CurrentRunStore:
    """Return a Redis-backed store when ``url`` is set, else the in-memory one."""
    if url:
        try:
            import redis as _redis

            client = _redis.Redis.from_url(
                url, socket_timeout=2, socket_connect_timeout=2, decode_responses=True
            )
            return RedisCurrentRun(client)
        except Exception:  # noqa: BLE001
            pass
    return MemoryCurrentRun()
