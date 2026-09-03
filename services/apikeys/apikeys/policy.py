"""Deterministic machine API-key platform policy (no AI/ML).

A machine key may be constrained beyond its human RBAC roles:

* **endpoint scopes** — a whitelist of API path prefixes the key may reach
  (e.g. ``["/findings", "/scans/runtime-findings"]``). An empty scope list
  means "all endpoints the roles allow" (backwards compatible).
* **HTTP method allowlist** — e.g. a read-only CI/SIEM key is ``GET`` only.
* **rate quota** — requests per minute, enforced as a deterministic fixed
  window. ``0`` means "no explicit key-level cap" (the global limiter still
  applies).

All matching is exact/prefix string logic — fully reproducible and auditable.
The quota counter is in-process (the documented topology is single-process;
multi-replica deployments front the API with a shared limiter).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from enum import Enum

API_PREFIX = "/api/v1"
_SCOPE_RE = re.compile(r"^/[a-z0-9][a-z0-9_/{}.-]*$", re.IGNORECASE)
_VALID_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


class DenyReason(str, Enum):
    SCOPE = "scope_denied"
    METHOD = "method_denied"
    QUOTA = "quota_exceeded"


@dataclass(frozen=True)
class KeyPolicy:
    scopes: tuple[str, ...] = ()
    methods: tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
    rate_per_minute: int = 0  # 0 == no key-level cap

    @staticmethod
    def from_row(row) -> "KeyPolicy":
        """Build a policy from an ApiKey ORM row (or any object with the fields)."""
        scopes = tuple(s for s in (getattr(row, "scopes_list", []) or []) if s)
        methods = tuple(m.upper() for m in (getattr(row, "method_list", []) or []) if m)
        if not methods:
            methods = tuple(sorted(_VALID_METHODS))
        rpm = int(getattr(row, "rate_per_minute", 0) or 0)
        return KeyPolicy(scopes=scopes, methods=methods, rate_per_minute=rpm)


def normalize_scopes(raw) -> list[str]:
    """Validate/normalize a list of scope path prefixes. Raises ValueError."""
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [p.strip() for p in raw.split(",") if p.strip()]
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        p = str(item).strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        # accept both "/api/v1/findings" and "/findings"
        if p.startswith(API_PREFIX):
            p = p[len(API_PREFIX):]
        p = p.rstrip("/") or "/"
        if not _SCOPE_RE.match(p) and p != "/":
            raise ValueError(f"invalid scope path: {item!r}")
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def normalize_methods(raw) -> list[str]:
    """Validate a list of HTTP methods. Raises ValueError."""
    if raw is None or raw == []:
        return []
    if isinstance(raw, str):
        raw = [m.strip() for m in raw.split(",") if m.strip()]
    out: set[str] = set()
    for item in raw:
        m = str(item).strip().upper()
        if m not in _VALID_METHODS:
            raise ValueError(f"invalid HTTP method: {item!r}")
        out.add(m)
    return sorted(out)


def normalize_rate(value) -> int:
    """Rate per minute: 0 (uncapped) or a positive int bounded to a sane max."""
    if value is None:
        return 0
    v = int(value)
    if v < 0:
        raise ValueError("rate_per_minute must be >= 0")
    return min(v, 1_000_000)


def _resource_path(path: str) -> str:
    """Strip the /api/v1 prefix and a trailing slash for matching."""
    p = path
    if p.startswith(API_PREFIX):
        p = p[len(API_PREFIX):]
    return p.rstrip("/") or "/"


def path_in_scope(path: str, scopes) -> bool:
    """True if ``path`` is allowed by the scope whitelist.

    Empty scopes => unrestricted. A scope matches when the resource path equals
    the scope or sits beneath it (prefix segment boundary), so ``/findings``
    grants ``/findings`` and ``/findings/123/ack`` but not ``/findingsx``.
    """
    resource = _resource_path(path)
    normed = normalize_scopes(list(scopes) if scopes else [])
    if not normed:
        return True
    for scope in normed:
        if scope == "/":
            return True
        if resource == scope or resource.startswith(scope + "/"):
            return True
    return False


def method_allowed(method: str, methods) -> bool:
    allowed = {m.upper() for m in (methods or [])}
    if not allowed:
        return True  # no method restriction
    return method.upper() in allowed


@dataclass
class Authorization:
    allowed: bool
    reason: DenyReason | None = None
    detail: str = ""
    quota_remaining: int | None = None
    quota_reset_at: float | None = None


class FixedWindowQuota:
    """Deterministic fixed-window request counter per key.

    Not thread-safe-by-design beyond the GIL; the API process is asyncio single
    -threaded. Window resets every 60s. Returns remaining/reset metadata.
    """

    WINDOW = 60.0

    def __init__(self) -> None:
        self._hits: dict[str, tuple[int, float]] = {}  # key_id -> (count, window_start)

    def check_and_consume(self, key_id: str, limit: int, *, now: float | None = None) -> tuple[bool, int, float]:
        """Return (allowed, remaining, reset_at_epoch). Limit 0 => unlimited."""
        moment = now if now is not None else time.time()
        if limit <= 0:
            return True, 10**9, moment + self.WINDOW
        count, start = self._hits.get(key_id, (0, moment))
        if moment - start >= self.WINDOW:
            count, start = 0, moment
        count += 1
        self._hits[key_id] = (count, start)
        reset_at = start + self.WINDOW
        remaining = max(0, limit - count)
        return (count <= limit, remaining, reset_at)

    def reset(self, key_id: str | None = None) -> None:
        if key_id is None:
            self._hits.clear()
        else:
            self._hits.pop(key_id, None)


#: process-wide quota window (single-process topology; see module docstring)
_QUOTA = FixedWindowQuota()


def get_quota_window() -> FixedWindowQuota:
    return _QUOTA


def authorize(
    *,
    key_id: str,
    method: str,
    path: str,
    policy: KeyPolicy,
    quota: FixedWindowQuota | None = None,
    now: float | None = None,
) -> Authorization:
    """Evaluate scope -> method -> quota in order. Fail-closed and deterministic."""
    if not path_in_scope(path, policy.scopes):
        return Authorization(False, DenyReason.SCOPE,
                             f"API key scope does not permit {method} {_resource_path(path)}")
    if not method_allowed(method, policy.methods):
        return Authorization(False, DenyReason.METHOD,
                             f"API key may not use HTTP method {method.upper()}")
    window = quota or _QUOTA
    allowed, remaining, reset_at = window.check_and_consume(
        key_id, policy.rate_per_minute, now=now
    )
    if not allowed:
        return Authorization(False, DenyReason.QUOTA,
                             f"API key rate quota exceeded ({policy.rate_per_minute}/min)",
                             quota_remaining=0, quota_reset_at=reset_at)
    return Authorization(True, quota_remaining=remaining, quota_reset_at=reset_at)
