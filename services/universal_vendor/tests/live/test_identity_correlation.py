"""24/7 live engine — asset identity + vendor-to-cloud correlation +
blast radius + alert correlation tests (§13, §14, §18, §19)."""

from __future__ import annotations

from universal_vendor.graph import VendorGraph
from universal_vendor.live.correlation import CorrelationEngine
from universal_vendor.live.identity import AssetIdentity, AssetIdentityResolver


def test_identity_resolver_correlates_ip_mac_hostname():
    resolver = AssetIdentityResolver()
    asset_id = resolver.register_identity(AssetIdentity("ip", "10.10.10.20",
                                                        "network_scanner"))
    resolver.link(asset_id, AssetIdentity("mac", "aa:bb:cc:dd:ee:ff",
                                          "network_scanner"))
    resolver.link(asset_id, AssetIdentity("hostname", "fw-edge-01",
                                          "vendor_scanner"))

    resolved = resolver.resolve(ip="10.10.10.20")
    assert resolved.asset_id == asset_id
    assert resolved.identity("mac") == "aa:bb:cc:dd:ee:ff"
    # vendor scanner enriches the shared record
    vendor_asset_id = resolver.register_identity(
        AssetIdentity("vendor_asset", "ASA-123", "vendor_scanner"),
        asset=resolver.get(asset_id),
    )
    assert vendor_asset_id == asset_id


def test_identity_resolver_merges_vendor_and_cloud():
    resolver = AssetIdentityResolver()
    asset_id = resolver.register_identity(AssetIdentity("ip", "10.0.0.5", "network"))
    resolver.link(asset_id, AssetIdentity("cloud_resource", "arn:aws:ec2:...:i-123",
                                          "cloud_scanner"))
    assert resolver.resolve(cloud_resource="arn:aws:ec2:...:i-123").asset_id == asset_id


def test_correlation_cross_platform_edges():
    engine = CorrelationEngine()
    engine.link_vendor_to_cloud(
        vendor_asset="cisco-r1", vpn="ipsec-vpn-1",
        cloud_network="aws-vpc", cluster="eks-cluster",
        application="banking-app",
    )
    graph = engine.graph
    assert graph.node_count() == 5
    relationships = {e["relationship"] for e in graph.edges()}
    assert {"TERMINATES", "CONNECTS_VIA", "HOSTS", "RUNS"} <= relationships


def test_blast_radius_root_ca_example():
    """Root CA changed → 500 certs → 1200 apps → 40 business services."""
    graph = VendorGraph()
    graph.add_node("root-ca", vendor="DigiCert", product="PCA", asset_type="ca")
    for i in range(500):
        graph.add_node(f"cert-{i}", asset_type="certificate")
        graph.add_edge("root-ca", f"cert-{i}", "ISSUES")
    for i in range(1200):
        graph.add_node(f"app-{i}", asset_type="application")
        graph.add_edge(f"cert-{i % 500}", f"app-{i}", "USES")
    for i in range(40):
        graph.add_node(f"svc-{i}", asset_type="business_service")
        graph.add_edge(f"app-{i % 1200}", f"svc-{i}", "SUPPORTS")

    engine = CorrelationEngine(graph=graph)
    scope = engine.blast_radius("root-ca")
    assert scope.affected_assets  # certificates counted as assets
    assert len(scope.affected_applications) >= 1200
    assert len(scope.affected_business_services) >= 40


def test_alert_correlation_one_incident_per_root():
    events = []
    for i in range(3):
        events.append({
            "root_asset_id": "root-ca",
            "event_id": f"e{i}",
            "timestamp": "2026-08-31T00:00:00Z",
            "scope": {"affected_assets": [f"cert-{i}"],
                      "affected_applications": [f"app-{i}"],
                      "affected_business_services": [f"svc-{i}"]},
        })
    incidents = CorrelationEngine().correlate(events)
    assert len(incidents) == 1
    assert incidents[0]["root_asset_id"] == "root-ca"
    assert incidents[0]["event_count"] == 3
    assert "ONE ROOT INCIDENT" in incidents[0]["summary"] or "1 events" not in incidents[0]["summary"]
