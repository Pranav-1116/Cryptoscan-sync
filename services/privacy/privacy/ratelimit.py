"""Four-layer resource / rate limiting for scanning (spec §15–§18, §19).

Not just API rate limiting. A successful enterprise scan stack controls load at
every layer so ZELNX can never become a denial-of-service source:

* Layer 1 — user/API           (per-subject request budgets)
* Layer 2 — scanner            (per-scanner concurrency, rps, rpm, conns, timeouts)
* Layer 3 — target-specific    (production low, test high, HSM very conservative)
* Layer 4 — global & tenant    (tenant/env/scanner/target/infra caps)

:class:`RateLimiter` is a pure, time-aware token bucket that tracks spend per
key and reports :class:`RateLimitState`. It never calls a network — production
deploys it on top of Redis, but the decision logic is deterministic and
unit-testable in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from time import time
from typing import Any


@dataclass
class Limits:
    """Budget per layer; ``0``/``None`` means unlimited (but never for safety)."""

    # Layer 1 — user/API
    user_requests_per_minute: int = 100
    user_heavy_per_minute: int = 10
    user_export_per_minute: int = 5
    # Layer 2 — scanner
    max_concurrency: int = 50
    requests_per_second: int = 20
    requests_per_minute: int = 300
    max_connections: int = 100
    timeout_seconds: int = 5
    retry_limit: int = 2
    # Layer 3 — target-specific multiplier (applied to scanner budget)
    target_production_factor: float = 0.5      # 50% of scanner budget on prod
    target_hsm_factor: float = 0.1             # 10% on HSM
    target_dev_factor: float = 1.0
    # Layer 4 — global / tenant / env / infra
    tenant_active_scans: int = 20
    environment_concurrent_scanners: int = 5
    scanner_concurrent_targets: int = 100
    global_scanner_workers: int = 10_000

    def to_dict(self) -> dict[str, Any]:
        """Serialize the budget cap set (for API responses / policy echoes)."""
        import dataclasses
        return {f.name: getattr(self, f.name) for f in dataclasses.fields(self)}


@dataclass
class RateLimitState:
    allowed: bool
    layer: str
    key: str
    budget: float
    remaining: float
    reset_after: float          # seconds until the bucket window resets
    reason: str = ""

    @property
    def limited(self) -> bool:
        return not self.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed, "layer": self.layer, "key": self.key,
            "budget": self.budget, "remaining": self.remaining,
            "reset_after": self.reset_after, "reason": self.reason,
        }


@dataclass
class _Bucket:
    tokens: float
    last: float
    capacity: float
    per_second: float           # refill rate


def _refill(b: _Bucket, now: float) -> None:
    elapsed = max(0.0, now - b.last)
    b.tokens = min(b.capacity, b.tokens + elapsed * b.per_second)
    b.last = now


class BucketStore:
    """Persistent backend for the 4-layer token buckets.

    The :class:`RateLimiter` delegates each spend to a store so the exact same
    decision logic runs against a local dict (single node) or a shared Redis
    backend (N replicas sharing one budget). The atomicity of a spend is the
    store's responsibility — Redis uses a Lua script; memory is a plain
    read-modify-write under the process GIL (adequate for a single node).
    """

    def spend(self, layer: str, key: str, cost: float, capacity: float,
              per_second: float, now: float) -> RateLimitState:
        raise NotImplementedError

    def snapshot(self) -> dict[str, dict[str, float]]:
        raise NotImplementedError


class MemoryBucketStore(BucketStore):
    """Default single-node store: the original in-memory token-bucket dict."""

    def __init__(self, state: dict[str, _Bucket] | None = None) -> None:
        self._buckets: dict[str, _Bucket] = state or {}

    def spend(self, layer: str, key: str, cost: float, capacity: float,
              per_second: float, now: float) -> RateLimitState:
        bkey = f"{layer}:{key}"
        b = self._buckets.get(bkey)
        if b is None:
            b = _Bucket(tokens=capacity, last=now, capacity=capacity,
                        per_second=max(per_second, 1e-6))
            self._buckets[bkey] = b
        _refill(b, now)
        if b.tokens >= cost:
            b.tokens -= cost
            return RateLimitState(True, layer, key, capacity, b.tokens, 0.0)
        reset_after = (cost - b.tokens) / b.per_second
        return RateLimitState(False, layer, key, capacity, b.tokens,
                              round(reset_after, 3), reason=f"{layer} budget exhausted")

    def snapshot(self) -> dict[str, dict[str, float]]:
        out: dict[str, dict[str, float]] = {}
        for k, b in self._buckets.items():
            layer, _, key = k.partition(":")
            out.setdefault(layer, {})[key] = round(b.tokens, 3)
        return out


#: Lua script for an atomic refill + spend against one Redis hash key.
#: KEYS[1] = bucket hash (fields: tokens, last); ARGV = capacity, per_sec, cost, now.
#: Returns {allowed(0/1), tokens, reset_after}.
_SPEND_LUA = """
local tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens'))
local last = tonumber(redis.call('HGET', KEYS[1], 'last'))
local cap = tonumber(ARGV[1])
local per_sec = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
if tokens == nil then tokens = cap end
if last == nil or last == 0 then last = now end
local elapsed = math.max(0, now - last)
tokens = math.min(cap, tokens + elapsed * per_sec)
local allowed = 0
local reset_after = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  reset_after = (cost - tokens) / per_sec
end
redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'last', tostring(now))
redis.call('EXPIRE', KEYS[1], math.ceil(60 + reset_after))
return {allowed, tostring(tokens), tostring(reset_after)}
"""


class RedisBucketStore(BucketStore):
    """Shared store backed by a redis-py client (any Redis / Valkey / ElastiCache).

    Each bucket is one hash; the atomic refill+spend is a single Lua script so
    concurrent spends on different replicas decrement the SAME counter. Enabled
    by passing a redis client to :class:`RateLimiter` — never built by default,
    so a deployment without Redis keeps the exact in-memory behaviour.
    """

    def __init__(self, client) -> None:
        self._client = client
        self._script = client.register_script(_SPEND_LUA)

    def spend(self, layer: str, key: str, cost: float, capacity: float,
              per_second: float, now: float) -> RateLimitState:
        bkey = f"zelinx:rt:{layer}:{key}"
        allowed, tokens, reset_after = self._script(
            keys=[bkey],
            args=[capacity, max(per_second, 1e-6), cost, now],
        )
        allowed = bool(int(allowed))
        return RateLimitState(allowed, layer, key, capacity, float(tokens),
                              round(float(reset_after), 3),
                              "" if allowed else f"{layer} budget exhausted")

    def snapshot(self) -> dict[str, dict[str, float]]:
        # Best-effort: Redis does not expose the full key set cheaply.
        return {}


class RateLimiter:
    """Deterministic token-bucket limiter across four layers.

    ``store`` defaults to a :class:`MemoryBucketStore` so the behaviour is
    identical to the original single-node limiter. Pass a
    :class:`RedisBucketStore` (or any :class:`BucketStore`) to share budgets
    across API replicas.
    """

    def __init__(self, limits: Limits | None = None, *, clock=None,
                 store: BucketStore | None = None,
                 state: dict[str, _Bucket] | None = None) -> None:
        self.limits = limits or Limits()
        self._clock = clock or time
        self._store: BucketStore = store or MemoryBucketStore(state)

    def _spend(self, layer: str, key: str, cost: float, capacity: float, per_second: float) -> RateLimitState:
        return self._store.spend(layer, key, cost, capacity, per_second, self._clock())

    # -------------------------------------------------------------- Layer 1
    def user_api(self, subject: str, *, route: str = "", cost: int = 1) -> RateLimitState:
        heavy = any(x in route.lower() for x in ("heavy", "export", "report", "harvest"))
        if heavy:
            return self._spend("user:heavy", subject, cost, self.limits.user_heavy_per_minute,
                               self.limits.user_heavy_per_minute / 60)
        if "export" in route.lower():
            return self._spend("user:export", subject, cost, self.limits.user_export_per_minute,
                               self.limits.user_export_per_minute / 60)
        return self._spend("user:api", subject, cost, self.limits.user_requests_per_minute,
                           self.limits.user_requests_per_minute / 60)

    # -------------------------------------------------------------- Layer 2
    def scanner(self, scanner: str, *, cost: int = 1) -> RateLimitState:
        return self._spend("scanner:rps", scanner, cost, self.limits.requests_per_second,
                           self.limits.requests_per_second)

    def scanner_concurrency(self, scanner: str, active: int, *, max_targets: int | None = None) -> RateLimitState:
        cap = max_targets or self.limits.max_concurrency
        allowed = active < cap
        return RateLimitState(allowed, "scanner:concurrency", scanner, cap,
                              max(0, cap - active), 0.0,
                              "" if allowed else f"scanner concurrency {active}/{cap} exceeded")

    # -------------------------------------------------------------- Layer 3
    def target(self, target: str, *, kind: str = "", concurrency: int = 1) -> RateLimitState:
        k = str(target).lower()
        factor = self.limits.target_production_factor
        if kind in ("hsm", "hardware_security_module") or "hsm" in k:
            factor = self.limits.target_hsm_factor
        elif any(x in k for x in ("dev", "test", "sandbox", "staging")):
            factor = self.limits.target_dev_factor
        capacity = max(1.0, self.limits.requests_per_second * factor)
        return self._spend("target", k, concurrency, capacity, capacity)

    # -------------------------------------------------------------- Layer 4
    def active_scans(self, tenant: str, active: int) -> RateLimitState:
        allowed = active < self.limits.tenant_active_scans
        return RateLimitState(allowed, "tenant:active_scans", tenant, self.limits.tenant_active_scans,
                              max(0, self.limits.tenant_active_scans - active), 0.0,
                              "" if allowed else f"tenant active scans {active}/{self.limits.tenant_active_scans} exceeded")

    def env_scanners(self, tenant: str, env: str, active: int) -> RateLimitState:
        allowed = active < self.limits.environment_concurrent_scanners
        return RateLimitState(allowed, "env:scanners", f"{tenant}:{env}", self.limits.environment_concurrent_scanners,
                              max(0, self.limits.environment_concurrent_scanners - active), 0.0,
                              "" if allowed else f"environment scanners {active}/{self.limits.environment_concurrent_scanners} exceeded")

    def targets(self, scanner: str, active: int) -> RateLimitState:
        allowed = active < self.limits.scanner_concurrent_targets
        return RateLimitState(allowed, "scanner:targets", scanner, self.limits.scanner_concurrent_targets,
                              max(0, self.limits.scanner_concurrent_targets - active), 0.0,
                              "" if allowed else f"scanner targets {active}/{self.limits.scanner_concurrent_targets} exceeded")

    def global_workers(self, active: int) -> RateLimitState:
        allowed = active < self.limits.global_scanner_workers
        return RateLimitState(allowed, "infra:workers", "*", self.limits.global_scanner_workers,
                              max(0, self.limits.global_scanner_workers - active), 0.0,
                              "" if allowed else f"global workers {active}/{self.limits.global_scanner_workers} exceeded")

    def snapshot(self) -> dict[str, dict[str, float]]:
        return self._store.snapshot()
