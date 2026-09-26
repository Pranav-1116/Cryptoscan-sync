"""Rate-limiter bucket-store abstraction tests.

The default :class:`MemoryBucketStore` must behave exactly as the original
single-node limiter did (so nothing regresses). The Redis path is exercised with
a stubbed redis client — it verifies the wiring (Lua script registered, invoked
with the right keys/args) since a live Redis is not available in CI here.
"""

from __future__ import annotations

from privacy.ratelimit import Limits, MemoryBucketStore, RateLimiter, RedisBucketStore, BucketStore


def test_memory_store_default_exhausts_budget():
    rl = RateLimiter(limits=Limits(user_requests_per_minute=2))
    assert rl.user_api("alice").allowed is True
    assert rl.user_api("alice").allowed is True
    denied = rl.user_api("alice")
    assert denied.allowed is False
    assert denied.limited is True


def test_memory_store_snapshot_shapes_by_layer():
    rl = RateLimiter(limits=Limits())
    rl.scanner("nmap")
    snap = rl.snapshot()
    assert "scanner" in snap
    assert any("nmap" in k for k in snap["scanner"])


def test_default_store_is_memory():
    rl = RateLimiter(limits=Limits())
    assert isinstance(rl._store, MemoryBucketStore)


class _FakeScript:
    def __init__(self, client):
        self.client = client
        self.calls: list[list] = []

    def __call__(self, *, keys, args):
        self.calls.append([keys, args])
        # simulate the Lua decision: refill is trivial with now=args[3]; allow if
        # tokens >= cost. Start full (tokens=capacity) on first call.
        cap, per_sec, cost, now = args
        if not hasattr(self, "_tokens"):
            self._tokens = float(cap)
        self._tokens = min(float(cap), self._tokens)
        if self._tokens >= float(cost):
            self._tokens -= float(cost)
            return [1, str(self._tokens), "0.0"]
        return [0, str(self._tokens), "1.0"]


class _FakeRedis:
    def __init__(self):
        self.scripts: list[str] = []
        self._script = _FakeScript(self)

    def register_script(self, source: str):
        self.scripts.append(source)
        return self._script


def test_redis_store_registers_lua_and_spends():
    client = _FakeRedis()
    store = RedisBucketStore(client)
    assert parseable_spend_lua(client) is True
    rl = RateLimiter(limits=Limits(user_requests_per_minute=10), store=store)
    st = rl.user_api("alice")
    assert st.allowed is True
    # the script was invoked with a namespaced key + the capacity/refill args
    keys, args = client._script.calls[-1]
    assert keys[0].startswith("zelinx:rt:user:api:")
    assert "alice" in keys[0]
    assert len(args) == 4


def parseable_spend_lua(client) -> bool:
    return any("HSET" in s and "EXPIRE" in s for s in client.scripts)


def test_rate_limiter_accepts_custom_store():
    class OnceStore(BucketStore):
        def __init__(self):
            self.spends = 0

        def spend(self, layer, key, cost, capacity, per_second, now):
            self.spends += 1
            from privacy.ratelimit import RateLimitState
            return RateLimitState(True, layer, key, capacity, capacity - cost, 0.0)

        def snapshot(self):
            return {}

    store = OnceStore()
    rl = RateLimiter(limits=Limits(), store=store)
    assert rl.scanner("x").allowed is True
    assert store.spends == 1
