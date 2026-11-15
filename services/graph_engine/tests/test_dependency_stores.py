"""The three-store dependency-graph plane: one-way projection, parity, honest health.

PostgreSQL stays the authoritative source of truth. Cassandra (edge history)
and Elasticsearch (dependency search) hold derived, rebuildable projections
of the same edges — same identities everywhere, no duplicate authoritative
records. Projection flows one way: stores never write back, and the
authoritative payload is never mutated.
"""

from __future__ import annotations

import copy

from graph_engine.core.dependency_stores import (
    dependency_stores_health,
    edge_history_store,
    dependency_search_store,
    sync_dependency_stores,
)
from graph_engine.core.engine import GraphEngine
from graph_engine.history.edge_history import CassandraEdgeHistory, edge_key
from graph_engine.testing.fake_cassandra import FakeCassandraSession
from graph_engine.testing.fake_elastic import FakeElasticClient
from graph_engine.search.dependency_search import ElasticDependencySearch


def _stores():
    history = CassandraEdgeHistory(FakeCassandraSession())
    search = ElasticDependencySearch(FakeElasticClient())
    search.apply_schema()
    return history, search


def _payload():
    return {
        "systems": [{"id": "payments-api", "name": "Payments API"},
                    {"id": "ledger-db", "name": "Ledger DB"}],
        "assets": [{"id": "asset-1", "algorithm": "AES", "system_id": "ledger-db"}],
        "edges": [{"parent_id": "payments-api", "child_id": "ledger-db",
                   "relation": "CALLS", "lifecycle_state": "ACTIVE",
                   "lifecycle_revision": "r1"}],
    }


def test_sync_projects_edges_into_history_and_documents_into_search():
    history, search = _stores()
    report = sync_dependency_stores(_payload(), history=history, search=search, tenant_id="t1")
    assert report["synced"] is True
    # Two edges in the canonical universe: the declared CALLS plus the
    # scanner-derived USES edge the engine draws from the asset row.
    assert report["history"]["written"] == 2
    assert report["search"] == {"systems": 2, "assets": 1, "edges": 2}
    rows = history.history("t1", "payments-api", "ledger-db", "CALLS")
    assert rows[0]["event_type"] == "OBSERVED" and rows[0]["lifecycle_state"] == "ACTIVE"
    uses = history.history("t1", "ledger-db", "asset:asset-1", "USES")
    assert uses and uses[0]["event_type"] == "OBSERVED"
    assert search.count("t1") == 5


def test_projection_is_one_way_and_never_mutates_the_authoritative_payload():
    history, search = _stores()
    payload = _payload()
    pristine = copy.deepcopy(payload)
    sync_dependency_stores(payload, history=history, search=search, tenant_id="t1")
    assert payload == pristine


def test_sync_stamps_one_tenant_across_both_stores():
    history, search = _stores()
    report = sync_dependency_stores(_payload(), history=history, search=search)
    # No tenant plane in this test process: the single stamping point is 'platform'.
    assert report["tenant"] == "platform"
    assert history.history("platform", "payments-api", "ledger-db", "CALLS")
    assert search.count("platform") == 5
    assert search.count("t1") == 0


def test_unconfigured_stores_are_reported_never_faked(monkeypatch):
    monkeypatch.setattr("graph_engine.core.dependency_stores.edge_history_store", lambda: None)
    monkeypatch.setattr("graph_engine.core.dependency_stores.dependency_search_store", lambda: None)
    report = sync_dependency_stores(_payload(), tenant_id="t1")
    assert report["history"] == {"written": 0, "reason": "cassandra_unconfigured"}
    assert report["search"] == {"reason": "elasticsearch_unconfigured"}
    assert report["synced"] is False


def test_same_edge_identities_across_engine_history_and_search():
    history, search = _stores()
    payload = _payload()
    sync_dependency_stores(payload, history=history, search=search, tenant_id="t1")

    engine = GraphEngine().build(**payload)
    vis = engine.to_vis()
    engine_keys = {
        edge_key(edge["from"], edge["label"], edge["to"])
        for edge in vis["edges"]
    }
    history_keys = {
        row["edge_id"] for row in history.session.rows
    }
    search_keys = {
        doc["identity"] for doc in search.client.docs.values() if doc["kind"] == "edge"
    }
    assert engine_keys == history_keys == search_keys == {
        "payments-api::CALLS::ledger-db",
        "ledger-db::USES::asset:asset-1",
    }


def test_rebuild_from_the_authoritative_payload_is_idempotent():
    from datetime import datetime, timezone

    history, search = _stores()
    payload = _payload()
    when = datetime(2026, 10, 16, tzinfo=timezone.utc)
    sync_dependency_stores(payload, history=history, search=search, tenant_id="t1", now=when)
    assert search.purge_tenant("t1") == 5
    history.purge_edge("t1", "payments-api", "ledger-db", "CALLS")
    history.purge_edge("t1", "ledger-db", "asset:asset-1", "USES")
    assert search.count("t1") == 0 and history.history("t1", "payments-api", "ledger-db", "CALLS") == []
    sync_dependency_stores(payload, history=history, search=search, tenant_id="t1", now=when)
    assert search.count("t1") == 5
    assert len(history.history("t1", "payments-api", "ledger-db", "CALLS")) == 1


def test_health_reports_both_stores_honestly():
    history, search = _stores()
    health = dependency_stores_health(history=history, search=search)
    assert health["cassandra"]["ok"] and health["cassandra"]["configured"]
    assert health["elasticsearch"]["ok"] and health["elasticsearch"]["configured"]
    health = dependency_stores_health(history=None, search=None)
    assert not health["cassandra"]["ok"] and not health["elasticsearch"]["ok"]
    assert health["cassandra"]["required"] is False  # optional until configured


def test_history_events_carry_the_lifecycle_fields_of_the_authoritative_edge():
    history, search = _stores()
    payload = _payload()
    payload["edges"][0].update({"lifecycle_reason": "expired cert", "observed_at": "2026-10-01T00:00:00Z"})
    sync_dependency_stores(payload, history=history, search=search, tenant_id="t1")
    row = history.as_of("t1", "payments-api", "ledger-db", "CALLS", "2026-10-02T00:00:00Z")
    assert row["lifecycle_reason"] == "expired cert"
    assert row["lifecycle_revision"] == "r1"
