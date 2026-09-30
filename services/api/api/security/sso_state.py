"""Shared one-time state for SAML login correlation.

AuthnRequest ids are CSRF/replay state, not an in-memory application cache.
Production stores them in Redis with a short TTL so the ACS can run on any API
replica. A bounded local fallback remains for tests and offline development;
production never silently falls back when Redis is configured or required.
"""
from __future__ import annotations

import os
from collections import OrderedDict

from api.config.settings import get_settings

_PREFIX = "zelinx:sso:saml:request:"
_TTL_SECONDS = 600
_MAX_LOCAL = 256
_LOCAL: "OrderedDict[str, None]" = OrderedDict()
_REDIS = None
_REDIS_URL = ""


def _client():
    global _REDIS, _REDIS_URL
    settings = get_settings()
    url = (settings.REDIS_URL or os.environ.get("REDIS_URL", "")).strip()
    if not url:
        if settings.is_production:
            raise RuntimeError("REDIS_URL is required for SAML login state")
        return None
    if _REDIS is not None and _REDIS_URL == url:
        return _REDIS
    try:
        import redis

        client = redis.Redis.from_url(
            url, socket_timeout=2, socket_connect_timeout=2, decode_responses=True
        )
        client.ping()
        _REDIS, _REDIS_URL = client, url
        return client
    except Exception as exc:  # noqa: BLE001
        if settings.is_production:
            raise RuntimeError("Redis SAML login state is unavailable") from exc
        return None


def remember(request_id: str) -> None:
    client = _client()
    if client is not None:
        if not client.set(f"{_PREFIX}{request_id}", "1", ex=_TTL_SECONDS, nx=True):
            raise RuntimeError("SAML request id collision")
        return
    _LOCAL[request_id] = None
    while len(_LOCAL) > _MAX_LOCAL:
        _LOCAL.popitem(last=False)


def contains(request_id: str) -> bool:
    client = _client()
    if client is not None:
        return bool(client.get(f"{_PREFIX}{request_id}"))
    return request_id in _LOCAL


def consume(request_id: str) -> bool:
    """Atomically consume where Redis supports GETDEL; never replays an id."""
    client = _client()
    if client is not None:
        try:
            return bool(client.getdel(f"{_PREFIX}{request_id}"))
        except AttributeError:
            value = client.get(f"{_PREFIX}{request_id}")
            if value:
                client.delete(f"{_PREFIX}{request_id}")
            return bool(value)
    present = request_id in _LOCAL
    _LOCAL.pop(request_id, None)
    return present
