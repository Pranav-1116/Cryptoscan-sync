"""Enterprise layer — dependency graph, blast radius, geo model, simulation.

Spec areas 9, 10, 22, 23, 24: the network crypto dependency graph with Neo4j
export, network-wide blast radius classes, the geographic/international model
and the migration simulator wired to the dependency graph.
"""

from __future__ import annotations

import pytest

from network_scanner.enterprise.blast_radius import IMPACT_KINDS, blast_radius
from network_scanner.enterprise.geo import DEFAULT_GEOGRAPHY, GeoLocation, GeographyModel
from network_scanner.enterprise.simulation import MigrationSimulator, MigrationStep
from network_scanner.enterprise.topology import RELATIONSHIPS, GraphEdge, NetworkGraph


class TestGraph:
    def test_relationships_cover_spec(self) -> None:
        for rel in ("CONNECTED_TO", "ROUTES_TO", "PROTECTS", "TERMINATES_TLS_FOR",
                    "DEPENDS_ON", "AUTHENTICATES_TO", "USES_CERTIFICATE", "USES_VPN",
                    "USES_IPSEC", "USES_TLS"):
            assert rel in RELATIONSHIPS

    def test_add_nodes_and_edges(self) -> None:
        graph = NetworkGraph()
        graph.add_node("router-1")
        graph.add_node("vpn-gw")
        graph.add_edge("router-1", "vpn-gw", "USES_IPSEC")
        assert graph.nodes() == ["router-1", "vpn-gw"]
        assert graph.edges()[0].relationship == "USES_IPSEC"

    def test_add_edges_from_dicts(self) -> None:
        graph = NetworkGraph()
        count = graph.add_edges([
            {"from": "a", "to": "b", "relationship": "CONNECTED_TO"},
            {"from": "b", "to": "c", "relationship": "TERMINATES_TLS_FOR"},
        ])
        assert count == 2

    def test_dependents_transitive(self) -> None:
        graph = NetworkGraph()
        # internet -> lb -> app -> db ; cert chain via USES_CERTIFICATE
        graph.add_edge("internet", "lb", "CONNECTED_TO")
        graph.add_edge("lb", "app", "TERMINATES_TLS_FOR")
        graph.add_edge("app", "db", "DEPENDS_ON")
        graph.add_edge("lb", "cert:abc", "USES_CERTIFICATE")
        graph.add_edge("db", "cert:def", "USES_CERTIFICATE")
        # dependents are transitive (everything upstream)
        assert graph.dependents("cert:abc") == ["internet", "lb"]
        assert graph.dependents("cert:def") == ["app", "db", "internet", "lb"]
        assert graph.dependents("lb") == ["internet"]
        assert graph.dependencies("internet") == ["app", "cert:abc", "cert:def", "db", "lb"]

    def test_crypto_path(self) -> None:
        graph = NetworkGraph()
        graph.add_edge("router", "vpn-gw", "USES_IPSEC", crypto={"protocol": "IPsec",
                                                                 "encryption": "AES-GCM"})
        graph.add_edge("vpn-gw", "app", "TERMINATES_TLS_FOR", crypto={"tls": "1.3"})
        path = graph.crypto_path("router", "app")
        assert path[0]["relationship"] == "USES_IPSEC"
        assert path[0]["crypto"]["encryption"] == "AES-GCM"
        assert path[1]["relationship"] == "TERMINATES_TLS_FOR"

    def test_cypher_export(self) -> None:
        graph = NetworkGraph()
        graph.add_node('router "core"')
        graph.add_edge("router", "vpn-gw", "USES_IPSEC")
        cypher = graph.to_neo4j_cypher()
        assert 'MERGE (n:NetworkAsset {identity: "router \\"core\\""});' in cypher
        assert 'MERGE (a)-[:USES_IPSEC]->(b);' in cypher

    def test_edge_counts(self) -> None:
        graph = NetworkGraph()
        graph.add_edge("a", "b", "CONNECTED_TO")
        graph.add_edge("a", "c", "CONNECTED_TO")
        graph.add_edge("c", "d", "USES_TLS")
        assert graph.edge_counts() == {"CONNECTED_TO": 2, "USES_TLS": 1}

    def test_invalid_relationship_rejected(self) -> None:
        graph = NetworkGraph()
        with pytest.raises(ValueError):
            graph.add_edge("a", "b", "HOLDS_HANDS")

    def test_graph_edge_dataclass(self) -> None:
        edge = GraphEdge("a", "b", "CONNECTED_TO", metadata={"x": 1})
        assert edge.to_dict()["source"] == "a"
        assert edge.to_dict()["target"] == "b"
        assert edge.metadata == {"x": 1}


class TestBlastRadius:
    def _graph(self) -> NetworkGraph:
        graph = NetworkGraph()
        graph.add_edge("lb-1", "api-gw", "TERMINATES_TLS_FOR")
        graph.add_edge("api-gw", "core-app", "TERMINATES_TLS_FOR")
        graph.add_edge("core-app", "db-1", "DEPENDS_ON")
        graph.add_edge("lb-1", "cert:shared", "USES_CERTIFICATE")
        graph.add_edge("api-gw", "cert:shared", "USES_CERTIFICATE")
        graph.add_edge("core-app", "cert:shared", "USES_CERTIFICATE")
        # db-1 depends on core-app, which depends on the cert -> indirect
        graph.add_edge("db-1", "core-app", "DEPENDS_ON")
        return graph

    def test_impact_kinds_defined(self) -> None:
        assert IMPACT_KINDS == ("DIRECT", "INDIRECT", "BUSINESS", "NETWORK", "GEOGRAPHIC")

    def test_direct_and_indirect(self) -> None:
        graph = self._graph()
        result = blast_radius(graph, "cert:shared",
                              asset_attributes={
                                  "lb-1": {"device_type": "load_balancer", "criticality": "CRITICAL"},
                                  "api-gw": {"device_type": "gateway", "criticality": "HIGH"},
                                  "core-app": {"device_type": "application", "criticality": "CRITICAL"},
                                  "db-1": {"device_type": "database", "criticality": "CRITICAL"},
                              })
        assert result["direct_impact"] == ["api-gw", "core-app", "lb-1"]
        assert "db-1" in result["indirect_impact"]
        assert result["impact_counts"]["DIRECT"] == 3
        assert result["impact_counts"]["NETWORK"] >= 1

    def test_business_units_and_geo(self) -> None:
        graph = self._graph()
        result = blast_radius(graph, "cert:shared",
                              business_map={"lb-1": "Retail", "core-app": "Payments"},
                              geo_map={"lb-1": "DXB-DC-1", "core-app": "DXB-DC-1", "db-1": "MAA-DC-1"})
        assert "Retail" in result["business_impact"]
        assert "Payments" in result["business_impact"]
        assert "DXB-DC-1" in result["geographic_impact"]

    def test_critical_assets_flagged(self) -> None:
        graph = self._graph()
        result = blast_radius(graph, "cert:shared",
                              asset_attributes={"core-app": {"criticality": "CRITICAL"}})
        assert "core-app" in result["critical_assets_impacted"]

    def test_blast_radius_ignores_container_types(self) -> None:
        graph = NetworkGraph()
        graph.add_edge("lb", "cert:x", "USES_CERTIFICATE")
        graph.add_edge("pod", "lb", "DEPENDS_ON")
        result = blast_radius(graph, "cert:x",
                              asset_attributes={"pod": {"device_type": "container"}})
        assert "pod" not in result["network_impact"]["devices"]


class TestGeography:
    def test_default_geography(self) -> None:
        model = GeographyModel()
        assert len(model.locations) == len(DEFAULT_GEOGRAPHY)
        assert model.locations[0].country == "UAE"

    def test_location_for_asset_by_region(self) -> None:
        model = GeographyModel()
        geo = model.location_for_asset({"location": "DXB-DC-1", "network_zone": "dxb"})
        assert geo is not None and geo.country == "UAE"

    def test_exposure_by_geography(self) -> None:
        model = GeographyModel()
        graph = NetworkGraph()
        graph.add_node("edge-dxb")
        graph.add_node("edge-mum")
        graph.add_edge("edge-dxb", "core", "CONNECTED_TO")
        assets = [
            {"asset_identity": "edge-dxb", "location": "Dubai", "criticality": "CRITICAL"},
            {"asset_identity": "edge-mum", "location": "Chennai", "criticality": "HIGH"},
            {"asset_identity": "nowhere", "location": "Atlantis", "criticality": "LOW"},
        ]
        issues = {"edge-dxb": ["WEAK_TLS_VERSION"], "edge-mum": []}
        exposure = model.exposure_by_geography(graph, assets=assets, asset_issues=issues)
        assert exposure["by_country"]["UAE"]["assets"] == 1
        assert exposure["by_country"]["UAE"]["assets_with_issues"] == 1
        assert exposure["by_country"]["India"]["assets"] == 1
        assert "Atlantis" not in exposure["by_country"]
        assert exposure["by_region"]["UAE/Dubai"]["issue_count"] == 1

    def test_custom_locations(self) -> None:
        model = GeographyModel([GeoLocation("Japan", "Tokyo", "TYO-DC-1")])
        geo = model.location_for_asset({"location": "TYO-DC-1"})
        assert geo and geo.country == "Japan"

    def test_to_dict(self) -> None:
        model = GeographyModel([GeoLocation("UAE", "Dubai", "DXB-DC-1",
                                            cloud_region="me-central-1",
                                            business_unit="Retail",
                                            network_zones=["dxb-app", "dxb-db"])])
        data = model.to_dict()[0]
        assert data["cloud_region"] == "me-central-1"
        assert data["business_unit"] == "Retail"
        assert data["network_zones"] == ["dxb-app", "dxb-db"]


class TestMigrationSimulator:
    def _graph(self) -> NetworkGraph:
        graph = NetworkGraph()
        graph.add_edge("internet", "lb", "CONNECTED_TO")
        graph.add_edge("lb", "app", "TERMINATES_TLS_FOR")
        graph.add_edge("app", "db", "DEPENDS_ON")
        return graph

    def test_compatible_migration(self) -> None:
        graph = self._graph()
        simulator = MigrationSimulator(
            graph,
            hardware_capability={"lb": "SUPPORTED", "app": "SUPPORTED"},
        )
        result = simulator.evaluate([
            MigrationStep(algorithm="RSA", replacement="ML-KEM-768", protocol="TLS", asset="lb"),
        ])
        assert result["verdict"] == "COMPATIBLE"
        assert result["paths_evaluated"] >= 1
        assert result["rollback_feasible"] is True
        assert result["max_packet_overhead_bytes"] > 0

    def test_blocked_by_hardware(self) -> None:
        graph = self._graph()
        simulator = MigrationSimulator(graph, hardware_capability={"lb": "UNSUPPORTED"})
        result = simulator.evaluate([
            MigrationStep(algorithm="RSA", replacement="ML-KEM-768", asset="lb"),
        ])
        assert result["verdict"] == "BLOCKED"
        assert any("hardware unsupported" in b for b in result["blockers"])

    def test_non_hybrid_blocks_rollback(self) -> None:
        graph = self._graph()
        simulator = MigrationSimulator(graph)
        result = simulator.evaluate([
            MigrationStep(algorithm="RSA", replacement="ML-KEM-768", asset="lb", hybrid=False),
        ])
        assert result["verdict"] == "BLOCKED"
        assert result["rollback_feasible"] is False

    def test_no_affected_paths(self) -> None:
        graph = NetworkGraph()
        graph.add_node("isolated")
        simulator = MigrationSimulator(graph)
        result = simulator.evaluate([MigrationStep(algorithm="RSA", replacement="ML-KEM-768", asset="isolated")])
        assert result["verdict"] == "NO_AFFECTED_PATHS"

    def test_path_impact_metrics(self) -> None:
        graph = self._graph()
        simulator = MigrationSimulator(graph, hardware_capability={"app": "SUPPORTED"})
        result = simulator.evaluate([MigrationStep(algorithm="ECDH", replacement="X25519MLKEM768", asset="app")])
        impact = result["paths"][0]
        assert impact["compatible"] is True
        assert impact["mtu_impact"] <= 0
        assert impact["packet_overhead_bytes"] > 0
        assert impact["latency_delta_percent"] >= 0
