"""Dependency search over the Elasticsearch projection: text lookup, tenants, rebuild.

PostgreSQL stays authoritative; this store is the searchable projection.
These tests also pin the isolation contract from the fake's side: no query
may run without a tenant filter.
"""

from __future__ import annotations

import copy

import pytest

from graph_engine.search.dependency_search import (
    ElasticDependencySearch, doc_from_edge, doc_id,
)
from graph_engine.testing.fake_elastic import FakeElasticClient, TenantIsolationError


def _store():
    client = FakeElasticClient()
    store = ElasticDependencySearch(client)
    store.apply_schema()
    return store


def _payload():
    return {
        "systems": [
            {"id": "payments-api", "name": "Payments API", "environment": "prod",
             "criticality": "tier-1", "owner": "alice", "compliance_scopes": ["PCI"]},
            {"id": "ledger-db", "name": "Ledger DB", "environment": "prod"},
        ],
        "assets": [
            {"id": "asset-1", "algorithm": "AES", "purpose": "data at rest",
             "system_id": "ledger-db", "file_path": "/srv/ledger/app.conf"},
        ],
        "edges": [
            {"parent_id": "payments-api", "child_id": "ledger-db", "relation": "CALLS",
             "lifecycle_state": "ACTIVE", "lifecycle_revision": "r1"},
        ],
    }


def test_apply_schema_is_idempotent_and_declares_mapping():
    client = FakeElasticClient()
    store = ElasticDependencySearch(client)
    assert store.apply_schema()["created"] == store.index
    assert store.apply_schema()["created"] is None
    assert client.indices.mappings[store.index]["mappings"]["properties"]["tenant_id"]["type"] == "keyword"


def test_index_payload_projects_nodes_and_edges_with_stable_ids():
    store = _store()
    counts = store.index_payload("t1", _payload())
    assert counts == {"systems": 2, "assets": 1, "edges": 1}
    assert store.count("t1") == 4
    first = store.search("t1", "Payments")
    again = store.index_payload("t1", _payload())
    assert again == counts and store.count("t1") == 4  # upsert, not duplicate


def test_search_finds_by_text_and_filters_by_kind():
    store = _store()
    store.index_payload("t1", _payload())
    hits = store.search("t1", "ledger")
    kinds = sorted(hit["kind"] for hit in hits["hits"])
    assert "edge" in kinds and "system" in kinds and "asset" in kinds
    only_edges = store.search("t1", "ledger", kind="edge")
    assert only_edges["hits"] and all(hit["kind"] == "edge" for hit in only_edges["hits"])


def test_search_is_tenant_scoped_across_identical_estates():
    store = _store()
    store.index_payload("t1", _payload())
    store.index_payload("t2", _payload())
    hits = store.search("t1", "Payments")
    assert hits["hits"] and all(hit["tenant_id"] == "t1" for hit in hits["hits"])
    assert store.count("t1") == 4 and store.count("t2") == 4


def test_queries_without_a_tenant_filter_are_rejected_by_the_store_double():
    client = FakeElasticClient()
    with pytest.raises(TenantIsolationError):
        client.search("cryptoscan-dependency-graph",
                      {"query": {"bool": {"filter": [{"term": {"kind": "edge"}}]}}})


def test_dependents_of_surfaces_the_object_side_edges():
    store = _store()
    store.index_payload("t1", _payload())
    result = store.dependents_of("t1", "ledger-db")
    assert result["total"] == 1
    assert result["edges"][0]["subject_id"] == "payments-api"
    assert result["edges"][0]["relation"] == "CALLS"


def test_purge_tenant_rebuilds_without_touching_other_tenants():
    store = _store()
    store.index_payload("t1", _payload())
    store.index_payload("t2", _payload())
    assert store.purge_tenant("t1") == 4
    assert store.count("t1") == 0 and store.count("t2") == 4
    store.index_payload("t1", _payload())
    assert store.count("t1") == 4


def test_projection_never_mutates_the_authoritative_payload():
    store = _store()
    payload = _payload()
    pristine = copy.deepcopy(payload)
    store.index_payload("t1", payload)
    assert payload == pristine


def test_edge_docs_carry_lifecycle_fields_from_the_authoritative_edge():
    doc = doc_from_edge("t1", {"from": "system:a", "to": "system:b", "label": "CALLS",
                               "lifecycle_state": "EXPIRED", "lifecycle_revision": "r7"})
    assert doc["lifecycle_state"] == "EXPIRED" and doc["lifecycle_revision"] == "r7"
    assert doc["identity"] == "a::CALLS::b"
    assert doc_id("t1", "edge", doc["identity"]) == "t1::edge::a::CALLS::b"


def test_validation_rejects_blank_tenants_and_identityless_docs():
    store = _store()
    with pytest.raises(ValueError):
        store.search("  ", "x")
    with pytest.raises(ValueError):
        store.index_edge("t1", {"from": "", "to": "b", "label": "CALLS"})
