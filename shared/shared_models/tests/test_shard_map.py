"""Shard map: directory-first resolution, stable hash fallback, and the
refusal to move data or rehash silently."""

from __future__ import annotations

import pytest

from shared_models.shard_map import ShardMap


class TestResolution:

    def test_directory_entries_win(self):
        shard_map = ShardMap(["a", "b"], directory={"tenant_001": "b"})
        assert shard_map.resolve("tenant_001") == "b"

    def test_fallback_is_deterministic_forever(self):
        shard_map = ShardMap(["a", "b", "c"])
        first = shard_map.resolve("tenant_007")
        for _ in range(20):
            assert shard_map.resolve("tenant_007") == first

    def test_fallback_spreads_across_shards(self):
        shard_map = ShardMap(["a", "b", "c"])
        homes = {shard_map.resolve(f"tenant-{i}") for i in range(50)}
        assert homes == {"a", "b", "c"}, "the ring actually spreads tenants"

    def test_the_platform_estate_never_lands_on_a_lottery_ticket(self):
        shard_map = ShardMap(["a", "b"], platform_shard="a")
        assert shard_map.resolve(None) == "a"
        for _ in range(10):
            assert shard_map.resolve(None) == "a"

    def test_a_move_is_a_cutover_not_a_rehash(self):
        shard_map = ShardMap(["a", "b"], hash_buckets=64)
        tenant = "tenant_009"
        original = shard_map.resolve(tenant)
        target = "b" if original == "a" else "a"
        shard_map.move(tenant, target)
        for _ in range(10):
            assert shard_map.resolve(tenant) == target, (
                "after the cutover every process resolves to the new shard")
        # Unmoved fallback tenants are untouched by someone else's move.
        assert shard_map.resolve("tenant_010") == shard_map.resolve("tenant_010")


class TestHonestyRules:

    def test_an_empty_map_is_a_black_hole_not_a_deployment(self):
        with pytest.raises(ValueError, match="at least one shard"):
            ShardMap([])

    def test_a_directory_entry_may_not_name_a_shard_that_does_not_exist(self):
        with pytest.raises(ValueError, match="unknown shards"):
            ShardMap(["a"], directory={"tenant_001": "ghost"})

    def test_a_move_may_not_name_a_shard_that_does_not_exist(self):
        shard_map = ShardMap(["a"])
        with pytest.raises(ValueError, match="unknown shard"):
            shard_map.move("tenant_001", "ghost")

    def test_the_config_that_would_rehash_is_named_not_hidden(self):
        shard_map = ShardMap(["a", "b"], hash_buckets=16)
        body = shard_map.as_dict()
        assert body["hash_buckets"] == 16
        assert "rehash" in body["note"]
        assert "never moves data" in body["note"]

    def test_tenants_on_reports_the_directory_honestly(self):
        shard_map = ShardMap(["a", "b"], directory={"t1": "b", "t2": "b"})
        assert shard_map.tenants_on("b") == ["t1", "t2"]
        assert shard_map.tenants_on("a") == []
