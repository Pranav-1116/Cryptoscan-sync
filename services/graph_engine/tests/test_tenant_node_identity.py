"""Per-tenant node identity in the Neo4j write layer (round 35).

Contract tests over the real Cypher templates (what runs against a real
Neo4j) plus behavioral tests through the fake driver for row stamping
and tenant-safe pruning.
"""

from __future__ import annotations


from graph_engine.builders import cypher_writes
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.testing.fake_driver import FakeDriver

NODE_MERGES = [
    cypher_writes.MERGE_SYSTEMS,
    cypher_writes.MERGE_ASSETS,
    cypher_writes.MERGE_PROCESSES,
    cypher_writes.MERGE_OWNERS,
    cypher_writes.MERGE_SCOPES,
    cypher_writes.MERGE_VENDORS,
    cypher_writes.MERGE_CERTS,
    cypher_writes.MERGE_CLOUD,
    cypher_writes.MERGE_NETWORK,
    cypher_writes.MERGE_CONTAINERS,
]

EDGE_MERGES = [
    cypher_writes.MERGE_USES,
    cypher_writes.MERGE_CALLS,
    cypher_writes.MERGE_SUPPORTS,
    cypher_writes.MERGE_OWNED_BY,
    cypher_writes.MERGE_COMPLY,
    cypher_writes.MERGE_VENDOR_EDGE,
    cypher_writes.MERGE_SECURED_BY,
    cypher_writes.MERGE_DEPLOYED_ON,
    cypher_writes.MERGE_CONNECTS_TO,
    cypher_writes.MERGE_RUNS,
]


def test_every_node_merge_keys_on_tenant():
    for template in NODE_MERGES:
        assert "MERGE (" in template
        # identity map carries tenant_id alongside the business id
        assert "tenant_id: row.tenant_id}" in template, template[:60]
        # and the stamp is set explicitly (upgrade safety)
        assert "tenant_id = row.tenant_id" in template, template[:60]


def test_every_edge_merge_matches_tenanted_endpoints():
    for template in EDGE_MERGES:
        matches = [line for line in template.splitlines() if line.strip().startswith("MATCH (")]
        assert matches, template[:60]
        for line in matches:
            assert "tenant_id: row.tenant_id" in line, line


def test_prune_is_tenant_scoped_and_migrates_legacy_nodes():
    prune = cypher_writes.PRUNE_KIND
    # prunes only within the syncing tenant
    assert "n.tenant_id = $tenant" in prune
    assert "NOT n.{prop} IN $ids" in prune
    # un-stamped legacy nodes are cleaned on a platform sync (migration)
    assert "n.tenant_id IS NULL AND $tenant = 'platform'" in prune
    # a tenant sync never touches other tenants' nodes: no OR-branch
    # deletes without matching $tenant or being un-stamped


def test_sync_stamps_every_row_with_the_tenant():
    store = Neo4jGraphStore(FakeDriver(), database="neo4j")
    result = store.sync(
        systems=[{"id": "sys-1", "name": "Core", "environment": "prod"}],
        assets=[{"id": "asset-1", "system_id": "sys-1", "algorithm": "RSA"}],
        edges=[{"parent_id": "sys-1", "child_id": "sys-1", "relation": "CALLS"}],
    )
    assert result["written"] >= 3
    graph = store.driver.graph
    system = next(n for n in graph.nodes.values() if n["_label"] == "System")
    assert system["tenant_id"] == "platform"  # no tenant scope -> platform
    asset = next(n for n in graph.nodes.values() if n["_label"] == "CryptoAsset")
    assert asset["tenant_id"] == "platform"


def test_prune_cannot_cross_tenants():
    store = Neo4jGraphStore(FakeDriver(), database="neo4j")
    # tenant A syncs two systems; tenant B syncs one — same node kind
    store.sync(systems=[
        {"id": "sys-a1", "name": "A1", "environment": "prod"},
        {"id": "sys-a2", "name": "A2", "environment": "prod"},
    ])
    # simulate tenant B's nodes living in the same store
    store.driver.graph.upsert("System", "sys-b1", {
        "system_id": "sys-b1", "name": "B1", "tenant_id": "tenant-b"})
    # tenant A re-syncs with only sys-a1 — A2 is a ghost, B's node is not
    store.sync(systems=[
        {"id": "sys-a1", "name": "A1", "environment": "prod"},
    ])
    graph = store.driver.graph
    ids = {n.get("system_id") for n in graph.nodes.values()}
    assert "sys-a2" in ids  # retained evidence: absence is not deletion
    assert "sys-b1" in ids  # tenant B untouched


def test_platform_sync_cleans_unstamped_legacy_nodes():
    store = Neo4jGraphStore(FakeDriver(), database="neo4j")
    # pre-upgrade graph: node without tenant_id
    store.driver.graph.upsert("System", "legacy-1", {"system_id": "legacy-1", "name": "old"})
    # first platform sync of the same id re-merges tenanted and prunes
    # the un-stamped duplicate (self-migration)
    store.sync(systems=[{"id": "legacy-1", "name": "new", "environment": "prod"}])
    systems = [n for n in store.driver.graph.nodes.values() if n["_label"] == "System"]
    assert len(systems) == 1
    assert systems[0]["tenant_id"] == "platform"
    assert systems[0]["name"] == "new"
