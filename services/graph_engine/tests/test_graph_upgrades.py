"""Graph upgrades: reverse dependents, shortest path, crypto hotspots, structural diff."""

from __future__ import annotations

from graph_engine.core.engine import QUANTUM_VULNERABLE_RE, GraphEngine
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.testing.fake_driver import FakeDriver


def _payload(**overrides):
    base = dict(
        systems=[
            {"id": "pay", "name": "payment-api", "criticality": "TIER-1", "compliance_scopes": ["PCI-DSS"]},
            {"id": "db", "name": "customer-db"},
            {"id": "mail", "name": "email-service"},
            {"id": "web", "name": "web-frontend"},
        ],
        assets=[
            {"id": "a1", "algorithm": "RSA-2048", "system_id": "pay", "confidence": "HIGH"},
            {"id": "a2", "algorithm": "ECDSA-P256", "system_id": "pay", "confidence": "HIGH"},
            {"id": "a3", "algorithm": "AES-128-ECB", "system_id": "db", "confidence": "HIGH"},
            {"id": "a4", "algorithm": "ChaCha20-Poly1305", "system_id": "mail", "confidence": "HIGH"},
        ],
        edges=[
            {"parent_id": "web", "child_id": "pay", "relation": "CALLS"},
            {"parent_id": "pay", "child_id": "db", "relation": "CALLS"},
            {"parent_id": "db", "child_id": "mail", "relation": "CALLS"},
        ],
        processes=[],
        owners=[],
    )
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# classifier
# --------------------------------------------------------------------------- #

def test_quantum_classifier_uses_word_boundaries():
    assert QUANTUM_VULNERABLE_RE.search("RSA-2048")
    assert QUANTUM_VULNERABLE_RE.search("ECDSA-P256")
    assert QUANTUM_VULNERABLE_RE.search("X25519")
    assert QUANTUM_VULNERABLE_RE.search("secp256k1")
    assert QUANTUM_VULNERABLE_RE.search("Diffie-Hellman")
    assert not QUANTUM_VULNERABLE_RE.search("AES-128-ECB")  # EC inside ECB must NOT match
    assert not QUANTUM_VULNERABLE_RE.search("AES-256-GCM")
    assert not QUANTUM_VULNERABLE_RE.search("HMAC-SHA256")
    assert not QUANTUM_VULNERABLE_RE.search("ChaCha20-Poly1305")


# --------------------------------------------------------------------------- #
# dependents (reverse blast radius)
# --------------------------------------------------------------------------- #

def test_memory_dependents_reverse_traversal():
    graph = GraphEngine().build(**_payload())
    result = graph.dependents("db", hops=5)
    names = [(row["name"], row["hops"]) for row in result["systems"]]
    # web calls pay calls db: both upstream of db
    assert ("payment-api", 1) in names
    assert ("web-frontend", 2) in names
    assert result["nodes_visited"] == 3
    assert result["backend"] == "memory"


def test_memory_dependents_of_asset_jumps_to_using_system():
    graph = GraphEngine().build(**_payload())
    result = graph.dependents("a1", hops=5)  # asset used by pay; web is upstream of pay
    assert result["start"] == "pay"
    assert [row["name"] for row in result["systems"]] == ["web-frontend"]


def test_memory_dependents_unknown_and_leaf():
    graph = GraphEngine().build(**_payload())
    assert graph.dependents("nope")["nodes_visited"] == 0
    leaf = graph.dependents("web")  # nothing calls the frontend
    assert leaf["systems"] == [] and leaf["nodes_visited"] == 1


def test_store_dependents_via_fake_driver():
    store = Neo4jGraphStore(FakeDriver(), database="neo4j")
    store.sync(**_payload())
    result = store.dependents("db", hops=5)
    names = {row["name"] for row in result["systems"]}
    assert names == {"payment-api", "web-frontend"}
    assert result["backend"] == "neo4j"
    assert store.dependents("nope")["nodes_visited"] == 0


# --------------------------------------------------------------------------- #
# shortest path
# --------------------------------------------------------------------------- #

def test_memory_shortest_path_downstream_and_unreachable():
    graph = GraphEngine().build(**_payload())
    hit = graph.shortest_path("web", "mail")
    assert hit["reachable"] is True
    assert hit["hops"] == 3
    assert hit["path"] == ["web-frontend", "payment-api", "customer-db", "email-service"]
    miss = graph.shortest_path("mail", "web")  # edges point the other way
    assert miss["reachable"] is False and miss["hops"] is None and miss["path"] == []
    up = graph.shortest_path("mail", "web", direction="upstream")
    assert up["reachable"] is True and up["hops"] == 3


def test_memory_shortest_path_same_node_and_unknown():
    graph = GraphEngine().build(**_payload())
    same = graph.shortest_path("pay", "payment-api")  # id and name resolve to one node
    assert same["reachable"] is True and same["hops"] == 0 and len(same["path"]) == 1
    unknown = graph.shortest_path("pay", "ghost")
    assert unknown["resolved_start"] is True and unknown["resolved_target"] is False
    assert unknown["reachable"] is False


def test_store_shortest_path_via_fake_driver():
    store = Neo4jGraphStore(FakeDriver(), database="neo4j")
    store.sync(**_payload())
    hit = store.shortest_path("web", "db")
    assert hit["reachable"] is True
    assert hit["path"] == ["web-frontend", "payment-api", "customer-db"]
    up = store.shortest_path("db", "web", direction="upstream")
    assert up["reachable"] is True and up["hops"] == 2
    miss = store.shortest_path("db", "web")  # downstream: not reachable
    assert miss["reachable"] is False


# --------------------------------------------------------------------------- #
# crypto hotspots
# --------------------------------------------------------------------------- #

def test_memory_hotspots_rank_vulnerable_concentration():
    graph = GraphEngine().build(**_payload())
    result = graph.crypto_hotspots()
    assert result["count"] == 3  # pay, db, mail have assets; web has none
    top = result["hotspots"][0]
    assert top["name"] == "payment-api"
    assert top["quantum_vulnerable_assets"] == 2
    assert top["vulnerable_algorithms"] == ["ECDSA-P256", "RSA-2048"]
    # AES-ECB is weak against quantum? No: symmetric only loses margin -> not counted vulnerable
    db_row = next(row for row in result["hotspots"] if row["name"] == "customer-db")
    assert db_row["quantum_vulnerable_assets"] == 0 and db_row["total_assets"] == 1
    assert "ranking" in result


def test_store_hotspots_via_fake_driver():
    store = Neo4jGraphStore(FakeDriver(), database="neo4j")
    store.sync(**_payload())
    result = store.crypto_hotspots()
    assert result["backend"] == "neo4j"
    assert result["hotspots"][0]["system_id"] == "pay"
    assert result["hotspots"][0]["vulnerable_algorithms"] == ["ECDSA-P256", "RSA-2048"]
    names = [row["name"] for row in result["hotspots"]]
    assert "web-frontend" not in names  # no assets -> not a hotspot


def test_hotspots_empty_graph():
    assert GraphEngine().crypto_hotspots()["count"] == 0


# --------------------------------------------------------------------------- #
# structural diff
# --------------------------------------------------------------------------- #

def test_diff_detects_added_and_removed():
    before = GraphEngine().build(**_payload())
    after = GraphEngine().build(**_payload(edges=[{"parent_id": "web", "child_id": "pay"}]))  # pay->db, db->mail dropped
    result = before.diff(after)
    assert result["changed"] is True
    assert result["counts"]["edges_removed"] == 2
    assert result["counts"]["nodes_removed"] == 0
    assert ("system:pay", "system:db", "CALLS") in result["edges_removed"]


def test_diff_identical_graphs_reports_no_change():
    graph = GraphEngine().build(**_payload())
    twin = GraphEngine().build(**_payload())
    result = graph.diff(twin)
    assert result["changed"] is False
    assert result["counts"] == {"nodes_added": 0, "nodes_removed": 0, "edges_added": 0, "edges_removed": 0}


def test_diff_new_system_and_asset():
    before = GraphEngine().build(**_payload())
    after = GraphEngine().build(
        **_payload(
            systems=_payload()["systems"] + [{"id": "cache", "name": "redis-cache"}],
            edges=[
                {"parent_id": "pay", "child_id": "db"},
                {"parent_id": "db", "child_id": "mail"},
                {"parent_id": "web", "child_id": "pay"},
                {"parent_id": "pay", "child_id": "cache"},
            ],
        )
    )
    result = before.diff(after)
    assert "system:cache" in result["nodes_added"]
    assert ("system:pay", "system:cache", "CALLS") in result["edges_added"]


# --------------------------------------------------------------------------- #
# blast radius unchanged (regression)
# --------------------------------------------------------------------------- #

def test_forward_blast_radius_still_works():
    graph = GraphEngine().build(**_payload())
    radius = graph.blast_radius("pay", hops=5)
    names = [row["name"] for row in radius["systems"]]
    assert names == ["customer-db", "email-service"]
