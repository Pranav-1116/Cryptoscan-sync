"""Durable API-key quota windows (§4.8, round 59).

The process-local counter multiplied every limit by the replica count.
The DB-backed counter must prove: two independent sessions (two
"replicas") enforce ONE shared window; the window rolls over; authorize()
enforces through it; and the in-memory counter's per-process behavior —
the reason this exists — is pinned as the contrast.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register every table
from api.quota import DbQuotaWindow, window_start_for
from apikeys.policy import DenyReason, FixedWindowQuota, KeyPolicy, authorize
from db.connection.session import Base
from db.models.api_key_quota_window import ApiKeyQuotaWindow


def _replica(file_or_memory: str):
    engine = create_engine(
        file_or_memory,
        connect_args={"check_same_thread": False} if file_or_memory == "sqlite:///:memory:" else {},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    return session, engine


def test_two_replicas_enforce_one_shared_window(tmp_path):
    """The multi-replica contract: replica A exhausts the limit, replica
    B — a different process with an EMPTY local state — is denied."""
    shared = f"sqlite:///{tmp_path / 'quota.db'}"
    replica_a, engine_a = _replica(shared)
    replica_b, engine_b = _replica(shared)

    quota_a = DbQuotaWindow(replica_a)
    quota_b = DbQuotaWindow(replica_b)
    assert quota_a.check_and_consume("key-1", 2, now=1001.0)[0] is True
    assert quota_a.check_and_consume("key-1", 2, now=1002.0)[0] is True
    # replica B's FIRST request this process: denied by A's consumption
    allowed, remaining, reset_at = quota_b.check_and_consume("key-1", 2, now=1003.0)
    assert allowed is False
    assert remaining == 0
    assert reset_at == 1020.0
    engine_a.dispose()
    engine_b.dispose()


def test_the_process_local_counter_cannot_do_this():
    """The contrast, pinned: two in-process counters on the same key each
    allow the full limit — the bug the durable backend fixes."""
    quota_a, quota_b = FixedWindowQuota(), FixedWindowQuota()
    assert quota_a.check_and_consume("key-1", 2, now=1001.0)[0] is True
    assert quota_a.check_and_consume("key-1", 2, now=1002.0)[0] is True
    # a second process would count from zero — limit silently doubled
    assert quota_b.check_and_consume("key-1", 2, now=1003.0)[0] is True


def test_window_rolls_over_and_prunes_old_rows(tmp_path):
    session, engine = _replica(f"sqlite:///{tmp_path / 'roll.db'}")
    quota = DbQuotaWindow(session)
    assert quota.check_and_consume("k", 1, now=1001.0) == (True, 0, 1020.0)
    assert quota.check_and_consume("k", 1, now=1019.9)[0] is False
    # past the boundary: a fresh window
    assert quota.check_and_consume("k", 1, now=1020.1) == (True, 0, 1080.0)
    # far future: the old windows were pruned, only the current one remains
    quota.check_and_consume("k", 1, now=2000.0)
    rows = session.execute(select(ApiKeyQuotaWindow)).scalars().all()
    assert len(rows) == 1
    assert rows[0].window_start == window_start_for(2000.0)
    engine.dispose()


def test_reset_clears_the_shared_count(tmp_path):
    session, engine = _replica(f"sqlite:///{tmp_path / 'reset.db'}")
    quota = DbQuotaWindow(session)
    quota.check_and_consume("k", 1, now=1001.0)
    assert quota.check_and_consume("k", 1, now=1002.0)[0] is False
    quota.reset("k")
    assert quota.check_and_consume("k", 1, now=1003.0)[0] is True
    engine.dispose()


def test_authorize_enforces_quota_through_the_db_backend(tmp_path):
    """The enforcement path: authorize() with the durable backend denies
    with QUOTA once the shared window is exhausted — same contract as
    the in-memory counter, one count for all replicas."""
    session, engine = _replica(f"sqlite:///{tmp_path / 'authz.db'}")
    quota = DbQuotaWindow(session)
    policy = KeyPolicy(scopes=("/findings",), rate_per_minute=2)
    shared = {"path": "/findings", "method": "GET", "key_id": "key-1", "policy": policy}

    first = authorize(quota=quota, now=1001.0, **shared)
    second = authorize(quota=quota, now=1002.0, **shared)
    third = authorize(quota=quota, now=1003.0, **shared)
    assert first.allowed and second.allowed
    assert third.allowed is False
    assert third.reason is DenyReason.QUOTA
    assert "quota" in third.detail.lower() or "rate" in third.detail.lower()
    engine.dispose()


def test_unlimited_keys_never_write_quota_rows(tmp_path):
    """limit 0 == no cap: no row is written (nothing to count)."""
    session, engine = _replica(f"sqlite:///{tmp_path / 'unl.db'}")
    quota = DbQuotaWindow(session)
    allowed, remaining, _ = quota.check_and_consume("k", 0, now=1001.0)
    assert allowed and remaining >= 10**8
    assert session.execute(select(ApiKeyQuotaWindow)).scalars().all() == []
    engine.dispose()


@pytest.mark.parametrize("moment,expected", [
    (0.0, 0.0), (59.9, 0.0), (60.0, 60.0), (1001.0, 960.0), (1020.0, 1020.0),
])
def test_window_alignment_is_epoch_minute(moment, expected):
    assert window_start_for(moment) == expected
