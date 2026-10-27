"""Durable state for the platform control-plane engine.

The API engine is a computation object, not an authority. Its last discovery
inputs and drift baseline live here so a restart or another replica can rebuild
the same deterministic view. Redis is mandatory in production; the small
process-local fallback exists only for tests and explicitly non-production
single-node development.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any

KEY_PREFIX = "zelinx:platform:state"
_LOCAL: dict[str, dict[str, Any]] = {}
_LOCK = threading.Lock()
_REDIS = None
_REDIS_URL: str | None = None


def _tenant_id() -> str | None:
    try:
        from db.tenancy import current_tenant

        return current_tenant()
    except ImportError:
        # Pure state-unit tests can exercise this module without the database
        # package; the API deployment always has db.tenancy available.
        return None


def _key() -> str:
    tenant = _tenant_id()
    return f"{KEY_PREFIX}:{tenant}" if tenant else KEY_PREFIX


def _settings_values() -> tuple[str, str]:
    try:
        from api.config.settings import get_settings

        settings = get_settings()
        return settings.ENVIRONMENT, settings.REDIS_URL or ""
    except Exception:
        return os.getenv("ENVIRONMENT", "development"), os.getenv("REDIS_URL", "")


def _production() -> bool:
    return _settings_values()[0].lower() in {"production", "prod"}


def _client():
    global _REDIS, _REDIS_URL
    from api.config.settings import get_settings
    from shared_models.redis_connection import connection_settings, connection_fingerprint, verified_redis_client
    config = connection_settings(get_settings(), "platform_state")
    identity = connection_fingerprint(config)
    if not config.REDIS_URL:
        if _production():
            raise RuntimeError("REDIS_URL is required for platform state")
        return None
    if _REDIS is not None and _REDIS_URL == identity:
        return _REDIS
    try:
        client = verified_redis_client(config, decode_responses=True)
        client.ping()
        previous = _REDIS
        _REDIS, _REDIS_URL = client, identity
        if previous is not None:
            previous.close()
        return client
    except Exception as exc:
        if _production():
            raise RuntimeError("Redis platform state is unavailable") from exc
        return None


def load() -> dict[str, Any]:
    client = _client()
    if client is None:
        with _LOCK:
            return dict(_LOCAL.get(_key()) or {})
    try:
        raw = client.get(_key())
        if not raw:
            return {}
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception as exc:  # noqa: BLE001
        if _production():
            raise RuntimeError("Redis platform state read failed") from exc
        with _LOCK:
            return dict(_LOCAL.get(_key()) or {})


def save(state: dict[str, Any]) -> None:
    value = json.dumps(state, default=str, separators=(",", ":"))
    client = _client()
    if client is None:
        with _LOCK:
            _LOCAL[_key()] = json.loads(value)
        return
    try:
        # No TTL: the last known platform view is durable until explicitly
        # replaced, and an unavailable integration remains represented as such.
        client.set(_key(), value)
    except Exception as exc:  # noqa: BLE001
        if _production():
            raise RuntimeError("Redis platform state write failed") from exc
        with _LOCK:
            _LOCAL[_key()] = json.loads(value)
