"""Server-side read cache: tenant-structural keys, TTL honesty, bounded
entries, tag invalidation at writes."""

from __future__ import annotations

import copy

import pytest

from api.cache import ReadCache, get_read_cache, set_read_cache


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestReadCache:

    def test_hits_and_misses_are_counted(self):
        cache = ReadCache(clock=FakeClock())
        assert cache.get("k") is None
        cache.set("k", {"n": 1})
        assert cache.get("k") == {"n": 1}
        assert cache.get("k") == {"n": 1}
        body = cache.as_dict()
        assert body["hits_total"] == 2 and body["misses_total"] == 1

    def test_the_ttl_is_a_staleness_ceiling(self):
        clock = FakeClock()
        cache = ReadCache(ttl_seconds=30, clock=clock)
        cache.set("k", "v")
        clock.advance(29)
        assert cache.get("k") == "v"
        clock.advance(2)  # past the ceiling: the read is gone, not stale
        assert cache.get("k") is None
        assert cache.as_dict()["misses_total"] == 1

    def test_the_cache_is_bounded_and_evictions_count(self):
        cache = ReadCache(max_entries=2, clock=FakeClock())
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)  # pushes "a" out (LRU)
        assert cache.get("a") is None
        assert cache.get("c") == 3
        assert cache.as_dict()["evictions_total"] == 1

    def test_invalidation_drops_only_tagged_entries(self):
        cache = ReadCache(clock=FakeClock())
        cache.set("t1-assets", "A", tags=("catalog:tenant-1",))
        cache.set("t2-assets", "B", tags=("catalog:tenant-2",))
        dropped = cache.invalidate("catalog:tenant-1")
        assert dropped == 1
        assert cache.get("t1-assets") is None
        assert cache.get("t2-assets") == "B"
        assert cache.as_dict()["invalidated_total"] == 1

    def test_keys_are_tenant_structural(self):
        cache = ReadCache(clock=FakeClock())
        key_a = cache.key("catalog-assets", "tenant-1", None, None)
        key_b = cache.key("catalog-assets", "tenant-2", None, None)
        assert key_a != key_b  # the tenant is in the key, not in a convention
        cache.set(key_a, {"assets": ["t1"]})
        assert cache.get(key_b) is None
        assert cache.get(key_a) == {"assets": ["t1"]}

    def test_values_cannot_be_mutated_into_another_answer(self):
        cache = ReadCache(clock=FakeClock())
        original = {"assets": ["a"]}
        cache.set("k", original)
        original["assets"].append("mutated-after-set")
        served = cache.get("k")
        served["assets"].append("mutated-after-get")
        assert cache.get("k") == {"assets": ["a"]}

    def test_get_or_set_computes_once(self):
        cache = ReadCache(clock=FakeClock())
        calls = []

        def compute():
            calls.append(1)
            return {"expensive": True}

        assert cache.get_or_set("k", compute) == {"expensive": True}
        assert cache.get_or_set("k", compute) == {"expensive": True}
        assert len(calls) == 1

    def test_limits_must_be_real(self):
        with pytest.raises(ValueError):
            ReadCache(ttl_seconds=0)
        with pytest.raises(ValueError):
            ReadCache(max_entries=0)

    def test_as_dict_names_the_staleness_ceiling_for_operators(self):
        body = ReadCache(ttl_seconds=7, clock=FakeClock()).as_dict()
        assert body["ttl_seconds"] == 7 and body["entries"] == 0


class TestCatalogWiring:

    def test_sync_invalidates_the_tenant_catalog_tag(self, monkeypatch):
        """estate_catalog.sync is the catalogue's write chokepoint: when it
        commits, every cached read of that tenant's catalogue must go."""
        import api.cache as cache_module
        from api import estate_catalog

        fresh = ReadCache(clock=FakeClock())
        monkeypatch.setattr(cache_module, "get_read_cache", lambda: fresh)
        set_read_cache(fresh)
        try:
            tag = estate_catalog.catalog_tag("tenant_001")
            fresh.set("k1", "stale", tags=(tag,))
            fresh.set("k2", "other-tenant",
                      tags=(estate_catalog.catalog_tag("tenant_002"),))

            class _StubGraph:
                """Empty graph: every accessor the catalog touches returns []."""

                def __getattr__(self, name):
                    return lambda *a, **k: []

            class _StubResult:
                def scalars(self):
                    return []

            class _StubDB:
                def execute(self, stmt):
                    return _StubResult()

                def commit(self):
                    pass

            estate_catalog.sync(_StubDB(), _StubGraph(),
                                tenant_id="tenant_001", complete=True)
            assert fresh.get("k1") is None, "the write dropped the cached read"
            assert fresh.get("k2") == "other-tenant", (
                "only the written tenant's cache is invalidated")
        finally:
            set_read_cache(ReadCache())

    def test_the_process_cache_is_replaceable_only_explicitly(self):
        original = get_read_cache()
        replacement = ReadCache(clock=FakeClock())
        set_read_cache(replacement)
        try:
            assert get_read_cache() is replacement
        finally:
            set_read_cache(original)
