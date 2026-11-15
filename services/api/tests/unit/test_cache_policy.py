"""Cache policy contracts: what may be cached, and what must never be.

Pins the two lists from the infrastructure spec verbatim (they are policy,
so they may change only deliberately) and the chokepoint behavior: a cached
value must never override an authoritative record.
"""
from __future__ import annotations

import pytest

from api.cache import ReadCache
from api import cache_policy as policy


@pytest.fixture(autouse=True)
def _clean_ledger():
    policy.reset_policy_stats()
    yield
    policy.reset_policy_stats()


class TestTheTwoListsAreTheSpecsTwoLists:
    def test_cacheable_is_exactly_the_six_good_candidates(self):
        # "Dashboard aggregate counts, technology category summaries, static
        # policy definitions, vendor reference metadata, frequently requested
        # read-only asset summaries, user interface configuration."
        assert policy.cacheable_classes() == {
            "dashboard_aggregates", "category_summaries", "policy_definitions",
            "vendor_reference", "asset_summaries", "ui_configuration",
        }

    def test_authoritative_is_exactly_the_six_be_careful_items(self):
        # "Current evidence status, certificate expiration, asset freshness,
        # risk findings, user permissions, Digital Twin state."
        assert policy.authoritative_classes() == {
            "evidence_status", "certificate_expiration", "asset_freshness",
            "risk_findings", "user_permissions", "twin_state",
        }

    def test_the_lists_never_overlap(self):
        assert not (policy.cacheable_classes() & policy.authoritative_classes())


class TestCacheableReadsAreCached:
    def test_a_cacheable_read_hits_the_cache_the_second_time(self):
        cache = ReadCache(ttl_seconds=60)
        calls = []

        def compute():
            calls.append(1)
            return {"count": 7}

        first = policy.policy_read("dashboard_aggregates", "k1", compute,
                                   tags=("t1",), cache=cache)
        second = policy.policy_read("dashboard_aggregates", "k1", compute,
                                    tags=("t1",), cache=cache)
        assert first == second == {"count": 7}
        assert len(calls) == 1  # computed once, served twice

    def test_tag_invalidation_forces_recompute(self):
        cache = ReadCache(ttl_seconds=60)
        calls = []

        def compute():
            calls.append(1)
            return {"n": len(calls)}

        policy.policy_read("asset_summaries", "k", compute, tags=("cat",), cache=cache)
        cache.invalidate("cat")
        fresh = policy.policy_read("asset_summaries", "k", compute, tags=("cat",), cache=cache)
        assert fresh["n"] == 2  # the write's invalidation was honored


class TestAuthoritativeReadsAreNeverCached:
    @pytest.mark.parametrize("klass", sorted(policy.authoritative_classes()))
    def test_every_be_careful_item_is_computed_on_every_call(self, klass):
        cache = ReadCache(ttl_seconds=60)
        calls = []

        def compute():
            calls.append(1)
            return {"fresh": len(calls)}

        a = policy.policy_read(klass, "k", compute, cache=cache)
        b = policy.policy_read(klass, "k", compute, cache=cache)
        assert a == {"fresh": 1} and b == {"fresh": 2}
        assert len(calls) == 2
        assert cache.get("k") is None  # nothing was ever stored

    def test_a_permission_change_is_visible_immediately(self):
        # user_permissions: a revoked permission must never be served from a
        # cache. Simulate the record changing under the read.
        cache = ReadCache(ttl_seconds=60)
        granted = {"role": "ciso"}

        def current_permissions():
            return dict(granted)

        before = policy.policy_read("user_permissions", "u1", current_permissions, cache=cache)
        granted["role"] = "revoked"  # the authoritative record changed
        after = policy.policy_read("user_permissions", "u1", current_permissions, cache=cache)
        assert before["role"] == "ciso" and after["role"] == "revoked"

    def test_stale_evidence_status_is_never_served(self):
        cache = ReadCache(ttl_seconds=60)
        status = {"state": "VERIFIED"}

        def current_status():
            return dict(status)

        policy.policy_read("evidence_status", "e1", current_status, cache=cache)
        status["state"] = "TAMPERED"
        after = policy.policy_read("evidence_status", "e1", current_status, cache=cache)
        assert after["state"] == "TAMPERED"
        assert cache.get("e1") is None


class TestUnknownClassesFailTowardTheTruth:
    def test_an_unclassified_read_is_never_stored(self):
        cache = ReadCache(ttl_seconds=60)
        calls = []

        def compute():
            calls.append(1)
            return "v"

        policy.policy_read("some_new_surface", "k", compute, cache=cache)
        policy.policy_read("some_new_surface", "k", compute, cache=cache)
        assert len(calls) == 2
        assert cache.get("k") is None
        assert policy.policy_stats()["refused_unknown_classes"] == {"some_new_surface": 2}

    def test_may_cache_is_false_for_everything_not_on_the_list(self):
        assert policy.may_cache("dashboard_aggregates") is True
        assert policy.may_cache("risk_findings") is False
        assert policy.may_cache("") is False
        assert policy.may_cache("ASSET_SUMMARIES") is False  # exact names only


class TestTheLedgerIsHonest:
    def test_reads_are_counted_by_class(self):
        cache = ReadCache(ttl_seconds=60)
        policy.policy_read("ui_configuration", "k", lambda: "x", cache=cache)
        policy.policy_read("ui_configuration", "k", lambda: "x", cache=cache)
        policy.policy_read("twin_state", "k", lambda: "y", cache=cache)
        stats = policy.policy_stats()
        assert stats["cacheable_reads"] == 2
        assert stats["cacheable_hits"] == 1
        assert stats["authoritative_reads"] == 1
