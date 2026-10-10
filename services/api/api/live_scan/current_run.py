"""Shared current-scan status store for multi-instance live status.

The orchestrator owns the active execution thread, but its status snapshot
is mirrored to this store so ANY replica can answer `/orchestrator/status`.
Production uses Redis and fails closed when that shared state is unavailable;
in-memory storage is reserved for single-node development and tests. Durable
scan history is recovered from the persisted platform event log.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import json
from abc import ABC, abstractmethod
from typing import Any

KEY = "zelinx:current_run"
# Keep the last real run visible across planned restarts; terminal history is
# separately retained in the durable platform event log.
TTL_SECONDS = 86_400


class CurrentRunStore(ABC):
    """Shared get/set plus durable cancellation command state.

    ABC since round 26 (deep/17 §1.1): the base used to raise a bare
    NotImplementedError on first call, so an incomplete subclass crashed
    at runtime instead of at instantiation. get/set are the contract;
    request_cancel is shared behavior every backend inherits.
    """

    @abstractmethod
    def get(self) -> dict[str, Any] | None:
        """Return the current status snapshot, or None when no run is active."""

    @abstractmethod
    def set(self, status: dict[str, Any]) -> None:
        """Persist the status snapshot for the active tenant."""

    def request_cancel(self, scan_id: str, actor: str) -> dict[str, Any] | None:
        status = self.get()
        scan = (status or {}).get("scan") or {}
        if scan.get("scan_id") != scan_id:
            return None
        if scan.get("status") in {"completed", "failed", "cancelled"}:
            return status
        scan["cancel_requested"] = True
        scan["cancel_requested_by"] = actor
        scan["status"] = "cancelling"
        scan["error"] = "cancellation requested"
        status["scan"] = scan
        self.set(status)
        return status


def _active_tenant() -> str | None:
    try:
        from db.tenancy import current_tenant

        return current_tenant()
    except ImportError:
        # Keep the store unit-testable without the optional database package;
        # production API imports db.tenancy as part of its startup graph.
        return None


class MemoryCurrentRun(CurrentRunStore):
    """Default single-node store, still isolated when tenant scope is active."""

    def __init__(self) -> None:
        self._values: dict[str | None, dict[str, Any]] = {}

    def get(self) -> dict[str, Any] | None:
        return self._values.get(_active_tenant())

    def set(self, status: dict[str, Any]) -> None:
        scan = status.get("scan") or {}
        tenant_id = scan.get("tenant_id") or _active_tenant()
        self._values[tenant_id] = status


class RedisCurrentRun(CurrentRunStore):
    """Shared store backed by a redis-py client (any Redis / Valkey / ElastiCache)."""

    def __init__(self, client, *, strict: bool = False) -> None:
        self._client = client
        self._strict = strict

    @staticmethod
    def _key(tenant_id: str | None = None) -> str:
        owner = tenant_id or _active_tenant()
        return f"{KEY}:{owner}" if owner else KEY

    def get(self) -> dict[str, Any] | None:
        try:
            raw = self._client.get(self._key())
            if raw is None:
                return None
            data = json.loads(raw)
            return data if isinstance(data, dict) else None
        except Exception as exc:  # noqa: BLE001 — production must not claim an empty run
            logger.warning("realtime_current_run_read_failed", extra={"error_type": type(exc).__name__})
            if self._strict:
                raise RuntimeError("realtime current-run state is unavailable") from exc
            return None

    def set(self, status: dict[str, Any]) -> None:
        try:
            scan = status.get("scan") or {}
            tenant_id = scan.get("tenant_id") or _active_tenant()
            self._client.set(self._key(tenant_id), json.dumps(status, default=str), ex=TTL_SECONDS)
        except Exception as exc:  # noqa: BLE001 — strict production callers see the outage
            logger.warning("realtime_current_run_write_failed", extra={"error_type": type(exc).__name__})
            if self._strict:
                raise RuntimeError("realtime current-run state is unavailable") from exc


def get_current_run_store(url: str | None, *, required: bool = False) -> CurrentRunStore:
    """Return the shared Redis store, or an explicitly allowed local store.

    Production callers set ``required=True`` so a missing Redis dependency or
    unreachable backend fails startup rather than presenting stale/process-local
    scan state as a real fleet-wide status.
    """
    if not url:
        if required:
            raise RuntimeError("REDIS_URL is required for realtime current-run state")
        return MemoryCurrentRun()
    try:
        import redis as _redis

        client = _redis.Redis.from_url(
            url, socket_timeout=2, socket_connect_timeout=2, decode_responses=True
        )
        client.ping()
        return RedisCurrentRun(client, strict=required)
    except Exception as exc:  # noqa: BLE001
        logger.warning("realtime_current_run_store_unavailable", extra={"error_type": type(exc).__name__})
        if required:
            raise RuntimeError("realtime Redis current-run state is unavailable") from exc
        return MemoryCurrentRun()
