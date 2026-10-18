"""Round 20 (reports 03/09): ghost-node pruning on sync, NetworkResource
sync on the Neo4j path (was a latent TypeError — store.sync never accepted
the payload key), and collection meta passthrough."""

from __future__ import annotations

from graph_engine.core.store import Neo4jGraphStore
from graph_engine.testing.fake_driver import FakeDriver


def _sync(store, systems, **extra):
    return store.sync(
        collection={"outcome": "COMPLETE", "truncated": False},
        systems=[{"id": s, "name": s} for s in systems],
        edges=[],
        **extra,
    )


def test_system_absence_never_erases_relationship_evidence():
    driver = FakeDriver()
    store = Neo4jGraphStore(driver, database="neo4j")
    _sync(store, ["web", "pay", "db"])
    assert store.counts()["nodes"] >= 3

    # Absence alone must not detach-delete System relationship history
    result = _sync(store, ["web", "pay"])
    assert result["pruned"] == 0
    assert driver.graph.nodes.get(("System", "db")) is not None
    # survivors still present
    assert driver.graph.nodes.get(("System", "web")) is not None
    assert driver.graph.nodes.get(("System", "pay")) is not None


def test_prune_never_touches_kinds_absent_from_the_sync():
    driver = FakeDriver()
    store = Neo4jGraphStore(driver, database="neo4j")
    store.sync(
        collection={"outcome": "COMPLETE", "truncated": False},
        systems=[{"id": "web", "name": "web"}],
        assets=[{"id": "a1", "algorithm": "RSA", "system_id": "web"}],
        edges=[],
    )
    # a systems-only sync (assets=()) must NOT prune assets
    result = _sync(store, ["web"])
    # asset untouched: empty merge rows mean "not in this sync"
    assert driver.graph.nodes.get(("CryptoAsset", "a1")) is not None
    assert result["pruned"] == 0


def test_prune_removes_ghost_assets_when_assets_present():
    driver = FakeDriver()
    store = Neo4jGraphStore(driver, database="neo4j")
    store.sync(
        collection={"outcome": "COMPLETE", "truncated": False},
        systems=[{"id": "web", "name": "web"}],
        assets=[{"id": "a1", "algorithm": "RSA", "system_id": "web"},
                {"id": "a2", "algorithm": "DES", "system_id": "web"}],
        edges=[],
    )
    # a2 retracted: next sync carrying a1 must prune a2's ghost
    result = store.sync(
        collection={"outcome": "COMPLETE", "truncated": False},
        systems=[{"id": "web", "name": "web"}],
        assets=[{"id": "a1", "algorithm": "RSA", "system_id": "web"}],
        edges=[],
    )
    assert result["pruned"] == 1
    assert driver.graph.nodes.get(("CryptoAsset", "a2")) is None
    assert driver.graph.nodes.get(("CryptoAsset", "a1")) is not None


def test_network_resources_sync_neo4j_path():
    """The payload key existed but store.sync rejected it — latent TypeError
    on any real-Neo4j deployment since network_resources shipped."""
    driver = FakeDriver()
    store = Neo4jGraphStore(driver, database="neo4j")
    store.sync(
        collection={"outcome": "COMPLETE", "truncated": False},
        systems=[{"id": "web", "name": "web"}],
        edges=[],
        network_resources=[
            {"id": "edge-tls", "name": "edge gateway", "endpoint": "api.example.com:443",
             "system_ids": ["web"]},
        ],
    )
    assert driver.graph.nodes.get(("NetworkResource", "edge-tls")) is not None
    connects = driver.graph.outgoing("System", "web", "CONNECTS_TO")
    assert ("NetworkResource", "edge-tls") in connects
    # ghost network resource pruned on the next sync (kind present, id absent)
    store.sync(
        collection={"outcome": "COMPLETE", "truncated": False},
        systems=[{"id": "web", "name": "web"}],
        edges=[],
        network_resources=[{"id": "other-tls", "endpoint": "x:443", "system_ids": ["web"]}],
    )
    assert driver.graph.nodes.get(("NetworkResource", "edge-tls")) is None


def test_collection_meta_carried_not_synced():
    driver = FakeDriver()
    store = Neo4jGraphStore(driver, database="neo4j")
    result = store.sync(
        systems=[{"id": "web", "name": "web"}],
        edges=[],
        collection={"systems_total": 1, "systems_truncated": False},
    )
    assert result["collection"] == {"systems_total": 1, "systems_truncated": False}
    # no node kind named "collection" ever lands in the graph
    assert all("collection" not in key[0].lower() for key in driver.graph.nodes)


def test_engine_build_accepts_collection_meta():
    from graph_engine.core.engine import GraphEngine

    engine = GraphEngine().build(
        systems=[{"id": "web", "name": "web"}],
        edges=[],
        collection={"systems_total": 1},
    )
    assert engine.collection_meta == {"systems_total": 1}
    assert engine.counts()["nodes"] >= 1


# --------------------------------------------------------------------------- #
# Round 21 (report 03): ContainerImage nodes reach the graph
# --------------------------------------------------------------------------- #

def test_container_images_sync_and_prune_neo4j_path():
    driver = FakeDriver()
    store = Neo4jGraphStore(driver, database="neo4j")
    store.sync(
        collection={"outcome": "COMPLETE", "truncated": False},
        systems=[{"id": "web", "name": "web"}],
        edges=[],
        container_images=[
            {"id": "img-1", "target": "nginx:1.25", "package_count": 42,
             "library_count": 7, "vuln_count": 3, "system_ids": ["web"]},
        ],
    )
    node = driver.graph.nodes.get(("ContainerImage", "img-1"))
    assert node is not None and node["name"] == "nginx:1.25"
    assert node["vuln_count"] == 3
    runs = driver.graph.outgoing("System", "web", "RUNS")
    assert ("ContainerImage", "img-1") in runs
    # next sync without img-1 (but with another image, so the kind is
    # present) must prune the ghost
    store.sync(
        collection={"outcome": "COMPLETE", "truncated": False},
        systems=[{"id": "web", "name": "web"}],
        edges=[],
        container_images=[
            {"id": "img-2", "target": "redis:7", "system_ids": []},
        ],
    )
    assert driver.graph.nodes.get(("ContainerImage", "img-1")) is None
    assert driver.graph.nodes.get(("ContainerImage", "img-2")) is not None


def test_container_images_memory_engine():
    from graph_engine.core.engine import GraphEngine

    engine = GraphEngine().build(
        systems=[{"id": "web", "name": "web"}],
        edges=[],
        container_images=[
            {"id": "img-1", "target": "nginx:1.25", "vuln_count": 3,
             "system_ids": ["web"]},
        ],
    )
    node = engine.nodes.get("container:img-1")
    assert node is not None
    assert node["kind"] == "ContainerImage"
    assert node["vuln_count"] == 3
    assert ("container:img-1", "RUNS") in engine.out["system:web"]
