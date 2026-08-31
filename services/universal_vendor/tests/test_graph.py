"""Universal vendor dependency graph tests (spec §21)."""

from __future__ import annotations

from universal_vendor.graph import VendorGraph, build_graph
from universal_vendor.models import AssetType, UniversalObservation


def _graph_with_cross_vendor_path():
    graph = VendorGraph()
    graph.add_node("cisco-r1", vendor="Cisco", product="IOS-XE",
                   asset_type=AssetType.ROUTER.value)
    graph.add_node("pa-fw1", vendor="Palo Alto", product="PAN-OS",
                   asset_type=AssetType.FIREWALL.value)
    graph.add_node("f5-lb1", vendor="F5", product="BIG-IP",
                   asset_type=AssetType.LOAD_BALANCER.value)
    graph.add_node("aws-app", vendor="AWS", product="EC2",
                   asset_type=AssetType.APPLICATION.value)
    graph.add_node("az-db", vendor="Microsoft", product="Azure SQL",
                   asset_type=AssetType.DATABASE.value)
    graph.add_edge("cisco-r1", "pa-fw1", "TLS_TO")
    graph.add_edge("pa-fw1", "f5-lb1", "PROTECTS")
    graph.add_edge("f5-lb1", "aws-app", "PROXIES_TO")
    graph.add_edge("aws-app", "az-db", "DEPENDS_ON")
    return graph


def test_cross_vendor_paths():
    graph = _graph_with_cross_vendor_path()
    paths = graph.paths("cisco-r1", "az-db")
    assert len(paths) == 1
    assert paths[0] == ["cisco-r1", "pa-fw1", "f5-lb1", "aws-app", "az-db"]


def test_neighbors_undirected():
    graph = _graph_with_cross_vendor_path()
    neighbors = graph.neighbors("pa-fw1")
    ids = {n["asset_id"] for n in neighbors}
    assert ids == {"cisco-r1", "f5-lb1"}
    assert {n["relationship"] for n in neighbors} <= {"TLS_TO", "PROTECTS"}


def test_build_graph_from_observations_and_deps():
    obs = [
        UniversalObservation(vendor="F5", product="BIG-IP",
                             asset_id="lb1", asset_type=AssetType.LOAD_BALANCER.value),
        UniversalObservation(vendor="NGINX", product="NGINX",
                             asset_id="nginx1", asset_type=AssetType.LOAD_BALANCER.value),
    ]
    deps = [
        {"asset_id": "lb1", "target_asset": "nginx1", "relationship": "PROXIES_TO"},
    ]
    graph = build_graph(obs, dependencies=deps)
    assert graph.node_count() == 2
    assert graph.edge_count() == 1
    assert graph.nodes()[0]["vendor"] == "F5"


def test_relationship_types_include_spec():
    graph = VendorGraph()
    graph.add_edge("idp1", "app1", "SIGNS_WITH")
    graph.add_edge("app1", "ca1", "TRUSTS")
    graph.add_edge("app1", "algo", "USES_ALGORITHM")
    rels = {e["relationship"] for e in graph.edges()}
    assert rels == {"SIGNS_WITH", "TRUSTS", "USES_ALGORITHM"}


def test_no_path_returns_empty():
    graph = VendorGraph()
    graph.add_node("a")
    graph.add_node("b")
    assert graph.paths("a", "b") == []
