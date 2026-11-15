"""Dependency-edge history in Cassandra: append-only, tenant-bound, as-of.

PostgreSQL stays authoritative; this store is the rebuildable timeline
projection. These tests also pin the isolation contract from the fake's
side: no statement may read or write without a tenant binding.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from graph_engine.history.edge_history import CassandraEdgeHistory, edge_key, event_id_for
from graph_engine.testing.fake_cassandra import FakeCassandraSession, TenantIsolationError

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _history(session=None):
    return CassandraEdgeHistory(session or FakeCassandraSession())


def _event(at: datetime | None = None, **overrides):
    event = {
        "subject": "payments-api",
        "relation": "CALLS",
        "object": "ledger-db",
        "occurred_at": at or T0,
        "event_type": "OBSERVED",
        "lifecycle_state": "ACTIVE",
        "lifecycle_revision": "r1",
    }
    event.update(overrides)
    return event


def test_append_then_history_orders_newest_first():
    store = _history()
    store.append_event("t1", _event(T0))
    store.append_event("t1", _event(T0 + timedelta(hours=1), lifecycle_revision="r2",
                                   lifecycle_state="STALE", event_type="STATE_CHANGE"))
    rows = store.history("t1", "payments-api", "ledger-db", "CALLS")
    assert [row["lifecycle_revision"] for row in rows] == ["r2", "r1"]
    assert rows[0]["event_type"] == "STATE_CHANGE"
    assert rows[0]["edge_id"] == edge_key("payments-api", "CALLS", "ledger-db")


def test_reapplying_the_same_event_is_idempotent():
    store = _history()
    first = store.append_event("t1", _event())
    second = store.append_event("t1", _event())
    assert first["event_id"] == second["event_id"] == event_id_for(first)
    assert len(store.history("t1", "payments-api", "ledger-db", "CALLS")) == 1


def test_as_of_reconstructs_the_edge_state_at_a_point_in_time():
    store = _history()
    store.append_event("t1", _event(T0, lifecycle_state="ACTIVE"))
    store.append_event("t1", _event(T0 + timedelta(days=1), lifecycle_state="EXPIRED",
                                   event_type="STATE_CHANGE"))
    at = store.as_of("t1", "payments-api", "ledger-db", "CALLS", T0 + timedelta(hours=2))
    assert at["lifecycle_state"] == "ACTIVE"
    later = store.as_of("t1", "payments-api", "ledger-db", "CALLS", T0 + timedelta(days=2))
    assert later["lifecycle_state"] == "EXPIRED"
    assert store.as_of("t1", "payments-api", "ledger-db", "CALLS",
                       T0 - timedelta(days=1)) is None


def test_since_and_until_bound_the_timeline():
    store = _history()
    for day in range(3):
        store.append_event("t1", _event(T0 + timedelta(days=day)))
    rows = store.history("t1", "payments-api", "ledger-db", "CALLS",
                         since=T0, until=T0 + timedelta(hours=1))
    assert len(rows) == 1


def test_cross_tenant_reads_are_invisible_even_on_the_same_edge():
    store = _history()
    store.append_event("t1", _event())
    store.append_event("t2", _event(lifecycle_revision="other"))
    rows = store.history("t1", "payments-api", "ledger-db", "CALLS")
    assert [row["lifecycle_revision"] for row in rows] == ["r1"]
    assert store.history("t2", "payments-api", "ledger-db", "CALLS")[0]["lifecycle_revision"] == "other"


def test_statements_without_a_tenant_binding_are_rejected_by_the_store_double():
    session = FakeCassandraSession()
    with pytest.raises(TenantIsolationError):
        session.execute(
            "SELECT * FROM ks.dependency_edge_events WHERE edge_id = %(edge_id)s",
            {"edge_id": "x"},
        )
    with pytest.raises(TenantIsolationError):
        session.execute(
            "-- cryptoscan.query=edge_history\n"
            "SELECT * FROM ks.dependency_edge_events WHERE edge_id = %(edge_id)s",
            {"edge_id": "x", "tenant_id": "t1"},
        )


def test_purge_edge_drops_only_that_edges_timeline():
    store = _history()
    store.append_event("t1", _event())
    store.append_event("t1", _event(T0, subject="other-api"))
    store.purge_edge("t1", "payments-api", "ledger-db", "CALLS")
    assert store.history("t1", "payments-api", "ledger-db", "CALLS") == []
    assert len(store.history("t1", "other-api", "ledger-db", "CALLS")) == 1


def test_validation_rejects_unsafe_identities_and_bad_events():
    store = _history()
    with pytest.raises(ValueError):
        store.append_event("t1;DROP", _event())
    with pytest.raises(ValueError):
        store.append_event("t1", _event(occurred_at=None))
    with pytest.raises(ValueError):
        store.append_event("t1", _event(event_type="MAYBE"))
    with pytest.raises(ValueError):
        CassandraEdgeHistory(FakeCassandraSession(), keyspace="bad-keyspace")


def test_schema_apply_reports_tagged_statements():
    store = _history()
    info = store.apply_schema()
    assert [tag for tag in info["applied"]] == [
        "-- cryptoscan.query=history_schema_keyspace",
        "-- cryptoscan.query=history_schema_table",
    ]
    assert store.session.schema_applied == ["history_schema_keyspace", "history_schema_table"]
