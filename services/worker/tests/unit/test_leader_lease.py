"""Leader lease: exactly-one-scans across N monitor daemons."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from worker.monitor.lease import LeaderLease, ensure_lease_table

NOW = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


def _factory():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    maker = sessionmaker(bind=engine, expire_on_commit=False)
    ensure_lease_table(maker())
    return maker


def test_first_daemon_acquires_second_stands_by():
    sessions = _factory()
    alpha = LeaderLease(sessions, ttl_seconds=60, holder="az1:1", clock=lambda: NOW)
    beta = LeaderLease(sessions, ttl_seconds=60, holder="az2:2", clock=lambda: NOW)
    assert alpha.heartbeat() is True
    assert alpha.is_leader
    assert beta.heartbeat() is False          # live lease held by alpha
    assert beta.is_leader is False


def test_takeover_after_ttl_expiry():
    sessions = _factory()
    alpha = LeaderLease(sessions, ttl_seconds=60, holder="az1:1", clock=lambda: NOW)
    assert alpha.heartbeat() is True
    # az1 dies; az2 keeps heartbeating — after expiry it takes over
    later = NOW + timedelta(seconds=61)
    beta = LeaderLease(sessions, ttl_seconds=60, holder="az2:2", clock=lambda: later)
    assert beta.heartbeat() is True
    assert beta.is_leader
    # alpha comes back (was partitioned) and must NOT steal the live lease
    alpha_late = LeaderLease(sessions, ttl_seconds=60, holder="az1:1", clock=lambda: later + timedelta(seconds=1))
    assert alpha_late.heartbeat() is False


def test_graceful_release_is_instant_failover():
    sessions = _factory()
    alpha = LeaderLease(sessions, ttl_seconds=3600, holder="az1:1", clock=lambda: NOW)  # long TTL
    assert alpha.heartbeat() is True
    alpha.release()
    immediately = LeaderLease(sessions, ttl_seconds=3600, holder="az2:2",
                              clock=lambda: NOW + timedelta(seconds=1))
    assert immediately.heartbeat() is True   # no TTL wait after a clean SIGTERM


def test_renewal_keeps_leadership_and_heartbeat_error_steps_down():
    sessions = _factory()
    alpha = LeaderLease(sessions, ttl_seconds=60, holder="az1:1", clock=lambda: NOW)
    assert alpha.heartbeat() is True
    assert alpha.heartbeat() is True          # renewal
    # DB gone -> heartbeat raises, daemon must assume standby (never double-run)
    def exploding():
        raise RuntimeError("db failover in progress")
    broken = LeaderLease(exploding, ttl_seconds=60, holder="az1:1", clock=lambda: NOW)
    broken._leader = True
    try:
        broken.heartbeat()
        assert False, "expected the DB error to propagate to the loop's try/except"
    except RuntimeError:
        assert broken.is_leader is False


def test_loop_standby_does_not_tick_and_leader_drains_on_stop():
    """Standby daemons idle; on SIGTERM the leader releases the lease."""
    from worker.monitor.engine import MonitorEngine
    from worker.monitor.loop import MonitorLoop

    sessions = _factory()
    ticks = []

    def engine_factory(session):
        class _Engine(MonitorEngine):
            def tick(self):
                ticks.append(1)
                return {"ran": 0, "results": []}
        return _Engine(session)

    lease = LeaderLease(sessions, ttl_seconds=60, holder="az1:1", clock=lambda: NOW)
    assert lease.heartbeat() is True
    loop = MonitorLoop(engine_factory, session_factory=sessions, tick_seconds=0.01,
                       lease=lease)
    loop.request_stop()                       # stop before first iteration
    loop.run_forever()
    assert loop.lease.is_leader is False      # released on shutdown

    standby_lease = LeaderLease(sessions, ttl_seconds=60, holder="az2:2",
                                clock=lambda: NOW + timedelta(seconds=1))
    standby = MonitorLoop(engine_factory, session_factory=sessions, tick_seconds=0.01,
                          lease=standby_lease)
    standby.request_stop()
    standby.run_forever()
    assert ticks == []                        # standby never scanned (leader holds lease)
