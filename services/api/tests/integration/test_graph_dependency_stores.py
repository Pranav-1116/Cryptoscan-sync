"""Dependency-store reads: /graph/search and /graph/history.

Elasticsearch (dependency search) and Cassandra (edge history) are
projections of the authoritative relational inventory. These tests pin both
the projection-backed path (through test doubles) and the honest fallbacks:
an unconfigured store is reported, never faked.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from graph_engine.core import dependency_stores
from graph_engine.history.edge_history import CassandraEdgeHistory
from graph_engine.search.dependency_search import ElasticDependencySearch
from graph_engine.testing.fake_cassandra import FakeCassandraSession
from graph_engine.testing.fake_elastic import FakeElasticClient


def _search_store():
    store = ElasticDependencySearch(FakeElasticClient())
    store.apply_schema()
    return store


def _history_store():
    return CassandraEdgeHistory(FakeCassandraSession())


class TestGraphDependencySearch:
    @pytest.mark.asyncio
    async def test_search_serves_from_the_elasticsearch_projection(
            self, authenticated_client: AsyncClient, monkeypatch):
        store = _search_store()
        store.index_system("platform", {"id": "payments-api", "name": "Payments API"})
        monkeypatch.setattr(dependency_stores, "dependency_search_store", lambda *a, **k: store)
        response = await authenticated_client.get("/api/v1/graph/search", params={"q": "Payments"})
        assert response.status_code == 200
        body = response.json()
        assert body["configured"] is True and body["backend"] == "elasticsearch"
        assert body["hits"][0]["identity"] == "payments-api"

    @pytest.mark.asyncio
    async def test_search_falls_back_to_the_authoritative_graph_when_unconfigured(
            self, authenticated_client: AsyncClient, monkeypatch):
        monkeypatch.setattr(dependency_stores, "dependency_search_store", lambda *a, **k: None)
        response = await authenticated_client.get("/api/v1/graph/search", params={"q": "anything"})
        assert response.status_code == 200
        body = response.json()
        assert body["configured"] is False and body["backend"] == "memory"
        assert body["hits"] == [] and body["total"] == 0  # empty estate, not a fake one

    @pytest.mark.asyncio
    async def test_search_rejects_unknown_kind_filters(self, authenticated_client: AsyncClient):
        response = await authenticated_client.get("/api/v1/graph/search", params={"kind": "banana"})
        assert response.status_code == 422


class TestGraphDependencyHistory:
    @pytest.mark.asyncio
    async def test_history_serves_the_timeline_from_the_cassandra_projection(
            self, authenticated_client: AsyncClient, monkeypatch):
        store = _history_store()
        store.append_event("platform", {
            "subject": "payments-api", "object": "ledger-db", "relation": "CALLS",
            "occurred_at": "2026-10-01T00:00:00Z", "event_type": "STATE_CHANGE",
            "lifecycle_state": "EXPIRED", "lifecycle_revision": "r2",
        })
        monkeypatch.setattr(dependency_stores, "edge_history_store", lambda *a, **k: store)
        response = await authenticated_client.get("/api/v1/graph/history", params={
            "subject_id": "payments-api", "object_id": "ledger-db", "relation": "CALLS"})
        assert response.status_code == 200
        body = response.json()
        assert body["configured"] is True and body["backend"] == "cassandra"
        assert body["count"] == 1
        assert body["events"][0]["lifecycle_state"] == "EXPIRED"

        as_of = await authenticated_client.get("/api/v1/graph/history", params={
            "subject_id": "payments-api", "object_id": "ledger-db", "relation": "CALLS",
            "at": "2026-10-02T00:00:00Z"})
        assert as_of.json()["state"]["lifecycle_revision"] == "r2"

    @pytest.mark.asyncio
    async def test_history_reports_unconfigured_without_fabricating_a_timeline(
            self, authenticated_client: AsyncClient, monkeypatch):
        monkeypatch.setattr(dependency_stores, "edge_history_store", lambda *a, **k: None)
        response = await authenticated_client.get("/api/v1/graph/history", params={
            "subject_id": "payments-api", "object_id": "ledger-db"})
        assert response.status_code == 200
        body = response.json()
        assert body["configured"] is False and body["events"] == []
        assert body["reason"] == "cassandra_unconfigured"
        assert body["backend"] is None
