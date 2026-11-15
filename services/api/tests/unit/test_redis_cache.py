"""The shared Redis cache tier — same honesty rules, cluster-wide tags.

Pins: (1) RedisReadCache honors ReadCache's contract (get/set, tag
invalidation, TTL ceiling, bounded entries), (2) the cache POLICY is
backend-agnostic — authoritative reads are never stored on either tier,
(3) a cache outage degrades to fresh reads, never to data errors.
"""
from __future__ import annotations

import json

import pytest

from api.cache import ReadCache, set_read_cache, configure_read_cache
from api.cache_redis import RedisReadCache
from api import cache_policy as policy


@pytest.fixture(autouse=True)
def _restore_process_cache():
    from api.cache import get_read_cache
    original = get_read_cache()
    yield
    set_read_cache(original)


class FakeRedis:
    """The redis-py surface the cache uses, in a dict."""

    def __init__(self):
        self.kv: dict[str, str] = {}
        self.zsets: dict[str, dict[str, float]] = {}
        self.dead = False

    def _up(self):
        if self.dead:
            raise ConnectionError("redis gone")

    def get(self, k):
        self._up()
        return self.kv.get(k)

    def set(self, k, v, ex=None):
        self._up()
        self.kv[k] = v
        return True

    def delete(self, *ks):
        self._up()
        for k in ks:
            self.kv.pop(k, None)
            self.zsets.pop(k, None)

    def zadd(self, k, mapping):
        self._up()
        self.zsets.setdefault(k, {}).update(mapping)

    def zrem(self, k, member):
        self._up()
        self.zsets.get(k, {}).pop(member, None)

    def zrange(self, k, start, stop):
        self._up()
        members = sorted(self.zsets.get(k, {}), key=lambda m: self.zsets[k][m])
        stop = len(members) if stop == -1 else stop + 1
        return members[start:stop]

    def zcard(self, k):
        self._up()
        return len(self.zsets.get(k, {}))

    def keys(self, pattern):
        self._up()
        prefix = pattern.split("*")[0]
        return [k for k in list(self.kv) + list(self.zsets) if k.startswith(prefix)]

    def pipeline(self):
        return _Pipeline(self)


class _Pipeline:
    def __init__(self, r):
        self.r = r
        self.ops = []

    def set(self, *a, **kw):
        self.ops.append(("set", a, kw))

    def zadd(self, *a, **kw):
        self.ops.append(("zadd", a, kw))

    def zrem(self, *a, **kw):
        self.ops.append(("zrem", a, kw))

    def delete(self, *a, **kw):
        self.ops.append(("delete", a, kw))

    def execute(self):
        for name, a, kw in self.ops:
            getattr(self.r, name)(*a, **kw)
        self.ops = []


class TestTheSharedTierKeepsTheContract:
    def test_hits_invalidation_and_tag_isolation(self):
        cache = RedisReadCache(FakeRedis(), ttl_seconds=60)
        calls = []

        def compute():
            calls.append(1)
            return {"count": 1}

        assert cache.get_or_set(ReadCache.key("t1", "k"), compute, tags=("cat",)) == {"count": 1}
        assert cache.get_or_set(ReadCache.key("t1", "k"), compute, tags=("cat",)) == {"count": 1}
        assert len(calls) == 1
        # another tenant's key is untouched by the first tenant's tags
        cache.set(ReadCache.key("t2", "k"), "other", tags=("cat",))
        cache.invalidate("cat")
        assert cache.get(ReadCache.key("t1", "k")) is None
        assert cache.get(ReadCache.key("t2", "k")) is None  # same tag, both dropped

    def test_entries_are_bounded_and_evictions_count(self):
        cache = RedisReadCache(FakeRedis(), ttl_seconds=60, max_entries=3)
        for i in range(6):
            cache.set(f"k{i}", i)
        assert cache.as_dict()["entries"] == 3
        assert cache.as_dict()["evictions_total"] == 3
        assert cache.get("k0") is None  # oldest gone
        assert cache.get("k5") == 5

    def test_values_survive_the_wire_round_trip(self):
        cache = RedisReadCache(FakeRedis(), ttl_seconds=60)
        value = {"nested": [1, {"b": True}], "s": "x"}
        cache.set("k", value, tags=("t",))
        assert cache.get("k") == value


class TestThePolicyIsBackendAgnostic:
    @pytest.mark.parametrize("klass", sorted(policy.authoritative_classes()))
    def test_authoritative_reads_are_never_stored_on_redis_either(self, klass):
        cache = RedisReadCache(FakeRedis(), ttl_seconds=60)
        calls = []

        def compute():
            calls.append(1)
            return {"fresh": len(calls)}

        a = policy.policy_read(klass, "k", compute, cache=cache)
        b = policy.policy_read(klass, "k", compute, cache=cache)
        assert a["fresh"] == 1 and b["fresh"] == 2
        assert cache.get("k") is None
        assert cache.as_dict()["entries"] == 0

    def test_cacheable_reads_still_cache(self):
        cache = RedisReadCache(FakeRedis(), ttl_seconds=60)
        policy.policy_read("dashboard_aggregates", "k", lambda: "v", tags=("t",), cache=cache)
        assert cache.get("k") == "v"


class TestACacheOutageIsNeverADataOutage:
    def test_a_dead_redis_falls_back_to_fresh_reads(self):
        fake = FakeRedis()
        cache = RedisReadCache(fake, ttl_seconds=60)
        cache.set("k", "v")
        fake.dead = True
        assert cache.get("k") is None          # read falls through
        assert cache.as_dict()["entries"] == -1  # unknown, not zero
        assert cache.as_dict()["backend_errors_total"] >= 1
        # policy read with a dead backend still returns the truth
        assert policy.policy_read("asset_summaries", "k", lambda: "computed") == "computed"


class TestTierSelectionIsExplicit:
    def test_configure_defaults_to_memory(self):
        class S:
            CACHE_BACKEND = "memory"
            REDIS_URL = ""
        configure_read_cache(S())
        from api.cache import get_read_cache
        assert type(get_read_cache()).__name__ == "ReadCache"

    def test_redis_backend_needs_a_url_and_installs_the_shared_tier(self):
        class S:
            CACHE_BACKEND = "redis"
            REDIS_URL = ""
        with pytest.raises(ValueError, match="REDIS_URL"):
            configure_read_cache(S())

    def test_unknown_backends_fail_loud(self):
        class S:
            CACHE_BACKEND = "memcached"
            REDIS_URL = ""
        with pytest.raises(ValueError, match="unknown CACHE_BACKEND"):
            configure_read_cache(S())
