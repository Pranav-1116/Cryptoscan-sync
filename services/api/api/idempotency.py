"""Idempotent writes (gap analysis §B).

"Writes are idempotent using Idempotency-Key or request fingerprints."

A caller may send ``Idempotency-Key: <opaque>`` with a write. The first
request executes and its response is stored under (tenant, user, path, key);
a replay with the same key returns the stored response with
``idempotent_replay: true`` instead of executing the write again. A replay
with the same key but a DIFFERENT body is refused as a conflict — never
silently served the wrong stored answer.

Honest scope (same as the rate limiter): single-process in-memory store.
Deployments running multiple API processes must add a shared store; the
contract tests pin the semantics.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any


_TTL_SECONDS = 24 * 3600
_MAX_ENTRIES = 4096

# (tenant, user, path, key) -> (fingerprint, stored_at, status, body)
_STORE: dict[tuple[str, str, str, str], tuple[str, float, int, Any]] = {}


def reset_idempotency_store() -> None:
    _STORE.clear()


def _fingerprint(body: Any) -> str:
    canonical = json.dumps(body, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def idempotent_write(scope: dict, path: str, key: str | None, body: Any) -> tuple[int, Any] | None:
    """Check the store before executing a write.

    Returns ``None`` when the write should execute (and the caller must then
    call :func:`record`), or ``(status, stored_body)`` for a replay.
    Raises ``ConflictError`` when the same key arrives with a different body.
    """
    if not key:
        return None
    now = time.time()
    for stale in [k for k, v in _STORE.items() if now - v[1] > _TTL_SECONDS]:
        _STORE.pop(stale, None)
    state = scope.get("state") or {}
    tenant = str(state.get("tenant_id") or state.get("user_id") or "-")
    user = str(state.get("user_id") or "-")
    store_key = (tenant, user, path, key)
    fingerprint = _fingerprint(body)
    hit = _STORE.get(store_key)
    if hit is None:
        return None
    stored_fingerprint, _, status, stored_body = hit
    if stored_fingerprint != fingerprint:
        raise ConflictError(
            "Idempotency-Key was already used with a different request body")
    return status, stored_body


def record(scope: dict, path: str, key: str | None, body: Any, status: int, response: Any) -> None:
    if not key:
        return
    if len(_STORE) >= _MAX_ENTRIES:
        _STORE.clear()  # bounded: drop oldest cohort wholesale, honest and simple
    state = scope.get("state") or {}
    tenant = str(state.get("tenant_id") or state.get("user_id") or "-")
    user = str(state.get("user_id") or "-")
    _STORE[(tenant, user, path, key)] = (_fingerprint(body), time.time(), status, response)


class ConflictError(ValueError):
    """Same Idempotency-Key, different request body — refused, not served."""
