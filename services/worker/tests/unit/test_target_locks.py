"""Target-scoped scan locks — "prevent conflicting jobs" (§10).

Two jobs on the same target must not run underneath each other: they
duplicate findings and race on shared state. These tests pin the
coordination semantics: one winner per target, a conflict that names the
holder (never a silent drop), an expired holder that is stealable (a dead
worker must not wedge its target), and tenants that never contend.
"""
from datetime import datetime, timedelta, timezone

import pytest

from db.target_lock import (
    TargetLocked,
    acquire_target_lock,
    lock_stats,
    release_target_lock,
    target_key_for,
    target_scan_lock,
)


@pytest.fixture
def db(test_db):
    return test_db


def _now(offset_seconds: int = 0) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)


class TestAcquireSemantics:

    def test_same_target_one_winner_the_loser_is_told_who_holds(self, db):
        first = acquire_target_lock(db, "tenant_001", "repo#main", "job-1",
                                    now=_now())
        second = acquire_target_lock(db, "tenant_001", "repo#main", "job-2",
                                     now=_now())
        assert first["acquired"] is True
        assert second["acquired"] is False
        assert second["owner"] == "job-1"
        assert "locked by job-1" in second["reason"]

    def test_different_tenants_never_contend(self, db):
        mine = acquire_target_lock(db, "tenant_001", "repo#main", "job-1")
        theirs = acquire_target_lock(db, "tenant_002", "repo#main", "job-2")
        assert mine["acquired"] is True and theirs["acquired"] is True

    def test_the_platform_estate_collides_with_itself(self, db):
        # NULL tenants never collide in a unique index — the module
        # normalizes to "" so platform-owned jobs still exclude each other.
        first = acquire_target_lock(db, None, "repo#main", "job-1")
        second = acquire_target_lock(db, None, "repo#main", "job-2")
        assert first["acquired"] is True
        assert second["acquired"] is False

    def test_reentrant_same_owner_refreshes(self, db):
        acquire_target_lock(db, "tenant_001", "repo#main", "job-1",
                            ttl_seconds=60, now=_now(-500))
        again = acquire_target_lock(db, "tenant_001", "repo#main", "job-1",
                                    ttl_seconds=900, now=_now())
        assert again["acquired"] is True


class TestExpiryAndRelease:

    def test_an_expired_holder_is_stolen(self, db):
        dead = acquire_target_lock(db, "tenant_001", "repo#main", "job-dead",
                                   ttl_seconds=60, now=_now(-500))
        assert dead["acquired"] is True
        steal = acquire_target_lock(db, "tenant_001", "repo#main", "job-2",
                                    now=_now())
        assert steal["acquired"] is True and steal["stole"] is True
        assert steal["previous_owner"] == "job-dead"

    def test_a_live_holder_is_never_stolen(self, db):
        acquire_target_lock(db, "tenant_001", "repo#main", "job-1",
                            ttl_seconds=900, now=_now())
        other = acquire_target_lock(db, "tenant_001", "repo#main", "job-2",
                                    now=_now())
        assert other["acquired"] is False and "stole" not in other

    def test_release_frees_the_target_for_the_next_job(self, db):
        acquire_target_lock(db, "tenant_001", "repo#main", "job-1")
        assert release_target_lock(db, "tenant_001", "repo#main", "job-1") is True
        nxt = acquire_target_lock(db, "tenant_001", "repo#main", "job-2")
        assert nxt["acquired"] is True

    def test_a_foreign_owner_cannot_release_our_lock(self, db):
        acquire_target_lock(db, "tenant_001", "repo#main", "job-1")
        assert release_target_lock(db, "tenant_001", "repo#main", "job-2") is False
        assert acquire_target_lock(db, "tenant_001", "repo#main",
                                   "job-3")["acquired"] is False


class TestContextManagerAndStats:

    def test_the_context_releases_after_the_run(self, db):
        with target_scan_lock(db, "tenant_001", "repo#main", "job-1") as held:
            assert held["acquired"] is True
            conflict = acquire_target_lock(db, "tenant_001", "repo#main", "job-2")
            assert conflict["acquired"] is False
        assert acquire_target_lock(db, "tenant_001", "repo#main",
                                   "job-2")["acquired"] is True

    def test_a_conflict_raises_target_locked_with_the_holder(self, db):
        acquire_target_lock(db, "tenant_001", "repo#main", "job-1")
        with pytest.raises(TargetLocked) as excinfo:
            with target_scan_lock(db, "tenant_001", "repo#main", "job-2"):
                pass  # pragma: no cover
        assert excinfo.value.result["owner"] == "job-1"

    def test_the_lock_counters_are_not_silent(self, db):
        before = lock_stats()
        acquire_target_lock(db, "tenant_001", "repo#main", "job-1")
        acquire_target_lock(db, "tenant_001", "repo#main", "job-2")
        after = lock_stats()
        assert after["acquired"] == before["acquired"] + 1
        assert after["conflicts"] == before["conflicts"] + 1

    def test_target_key_is_repo_and_branch(self):
        job = type("J", (), {})()
        job.target_repo = "https://github.com/org/repo"
        job.target_branch = "release"
        assert target_key_for(job) == "https://github.com/org/repo#release"
