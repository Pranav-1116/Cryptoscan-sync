"""ZELNX §13 dependency graph + §14 multi-cloud + §15 unified posture."""

from __future__ import annotations

from cloud_scanner.enterprise.asset_inventory import AssetInventoryBuilder
from cloud_scanner.enterprise.certificate_discovery import CertificateDiscovery
from cloud_scanner.enterprise.dependency_graph import CloudDependencyGraph, RELATION_KINDS
from cloud_scanner.enterprise.encryption_discovery import EncryptionDiscovery
from cloud_scanner.enterprise.key_discovery import KeyDiscovery
from cloud_scanner.enterprise.kubernetes_crypto import KubernetesCryptoDiscovery
from cloud_scanner.enterprise.multi_cloud import MultiCloudDiscovery
from cloud_scanner.enterprise.network_crypto import NetworkCryptoDiscovery
from cloud_scanner.enterprise.pki_intelligence import PkiIntelligenceEngine
from cloud_scanner.enterprise.posture import PostureEngine
from cloud_scanner.enterprise.serverless_crypto import ServerlessCryptoDiscovery
from cloud_scanner.enterprise.tls_discovery import TlsDiscovery

from zelix_fixtures import all_providers


def _inventories():
    entries = [p.to_provider_entry() for p in all_providers()]
    return {
        "workloads": AssetInventoryBuilder(entries).discover(),
        "keys": KeyDiscovery(entries).discover(),
        "certificates": CertificateDiscovery(entries).discover(),
        "pki": PkiIntelligenceEngine(entries).discover(),
        "encryption": EncryptionDiscovery(entries).discover(),
        "network": NetworkCryptoDiscovery(entries).discover(),
        "tls": TlsDiscovery(entries).discover(),
        "kubernetes": KubernetesCryptoDiscovery(entries).discover(),
        "serverless": ServerlessCryptoDiscovery(entries).discover(),
    }


# ------------------------------------------------------------------ §13 graph


def test_graph_builds_typed_relations():
    inv = _inventories()
    graph = CloudDependencyGraph()
    graph.build_from_workloads(inv["workloads"].workloads,
                               keys=inv["keys"].keys,
                               certificates=inv["certificates"].certificates,
                               endpoints=inv["tls"].endpoints)
    relations = {edge.relation for edge in graph.edges()}
    assert {"RUNS_ON", "USES_KEY", "USES_CERTIFICATE", "EXPOSED_BY",
            "TERMINATES_TLS"} <= relations


def test_graph_uses_key_edges():
    inv = _inventories()
    graph = CloudDependencyGraph()
    graph.build_from_workloads(inv["workloads"].workloads,
                               keys=inv["keys"].keys)
    uses = graph.by_relation("USES_KEY")
    assert any(e.source == "i-0001" and e.target == "arn:aws:kms:key-1" for e in uses)
    assert any(e.source == "lambda-pay" and e.target == "arn:aws:kms:key-1" for e in uses)
    assert any(e.source == "gke-bank" and e.target == "gcp-kms://ring-1/key-1" for e in uses)


def test_graph_exposed_by_and_terminates_tls():
    inv = _inventories()
    graph = CloudDependencyGraph()
    graph.build_from_workloads(inv["workloads"].workloads, endpoints=inv["tls"].endpoints)
    exposed = graph.by_relation("EXPOSED_BY")
    assert any(e.source == "payments-api" and e.target == "api.bank.example" for e in exposed)
    terminated = graph.by_relation("TERMINATES_TLS")
    assert any(e.source == "api.bank.example"
               and e.target == "arn:aws:acm:cert-1" for e in terminated)


def test_graph_dependents_transitive():
    graph = CloudDependencyGraph()
    graph.add_edge("payments-api", "api.bank.example", "EXPOSED_BY")
    graph.add_edge("api.bank.example", "arn:aws:acm:cert-1", "TERMINATES_TLS")
    dependents = graph.dependents("arn:aws:acm:cert-1", transitive=True)
    assert set(dependents) == {"payments-api", "api.bank.example"}


def test_graph_dependencies_transitive():
    graph = CloudDependencyGraph()
    graph.add_edge("payments-api", "api.bank.example", "EXPOSED_BY")
    graph.add_edge("api.bank.example", "arn:aws:acm:cert-1", "TERMINATES_TLS")
    assert graph.dependencies("payments-api") == ["api.bank.example", "arn:aws:acm:cert-1"]


def test_graph_builds_from_tunnel_rows():
    inv = _inventories()
    graph = CloudDependencyGraph()
    for tunnel in inv["network"].tunnels:
        graph.add_edge(tunnel.source, tunnel.target, tunnel.kind,
                       provider=tunnel.provider, account=tunnel.account)
    assert graph.by_relation("VPN_TUNNEL")
    assert graph.summary()["nodes"] == 4


def test_graph_skips_invalid_relations_and_empty_nodes():
    graph = CloudDependencyGraph()
    graph.build_from_rows([
        {"source": "a", "target": "b", "relation": "NOT_A_RELATION"},
        {"source": "", "target": "b", "relation": "USES_KEY"},
        {"source": "a", "target": "", "relation": "USES_KEY"},
    ])
    assert graph.edges() == []
    assert graph.nodes() == []


def test_graph_summary_counts():
    graph = CloudDependencyGraph()
    graph.add_edge("app", "key-1", "USES_KEY")
    graph.add_edge("app", "cert-1", "USES_CERTIFICATE")
    summary = graph.summary()
    assert summary["nodes"] == 3
    assert summary["edges"] == 2
    assert summary["by_relation"]["USES_KEY"] == 1
    assert summary["by_relation"]["USES_CERTIFICATE"] == 1


def test_all_relation_kinds_are_registered():
    assert set(RELATION_KINDS) == {
        "RUNS_ON", "USES_KEY", "USES_CERTIFICATE", "EXPOSED_BY",
        "TERMINATES_TLS", "STORED_IN", "CONNECTS_TO",
    }


# ------------------------------------------------------------------ §14 multi-cloud


def test_multi_cloud_relationships():
    mc = MultiCloudDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    assert mc.count() == 2
    assert all(rel.kind == "API_RELATIONSHIP" for rel in mc.relationships)


def test_multi_cloud_chain_aws_to_azure_to_gcp():
    mc = MultiCloudDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    chain = {rel.source: rel for rel in mc.relationships}
    assert chain["payments-api"].target_provider == "azure"
    assert chain["azure-apis"].target_provider == "gcp"
    assert chain["azure-apis"].crypto_dependencies == ["TLS1.3", "mTLS"]


def test_multi_cloud_summary():
    mc = MultiCloudDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    summary = mc.summary()
    assert summary["relationships"] == 2
    assert summary["by_kind"]["API_RELATIONSHIP"] == 2


# ------------------------------------------------------------------ §15 posture


def test_posture_unified_metrics():
    inv = _inventories()
    posture = PostureEngine(
        keys=inv["keys"], certificates=inv["certificates"], pki=inv["pki"],
        encryption=inv["encryption"], network=inv["network"], tls=inv["tls"],
        kubernetes=inv["kubernetes"], serverless=inv["serverless"],
    ).evaluate()
    unified = posture.metrics
    assert unified["vulnerable_assets"] >= 2  # rds unencrypted + legacy endpoint
    assert unified["weak_algorithms"] >= 1  # vpn-2 ipsec weak + weak chains
    assert unified["expiring_certificates"] == 1
    assert unified["non_rotating_keys"] == 2
    assert unified["externally_exposed_crypto"] >= 2  # legacy endpoint + cf-1 profile
    assert unified["pqc_migration_candidates"] >= 1  # rsa kex endpoints
    assert unified["total_assets"] > 0


def test_posture_per_provider_breakdown():
    inv = _inventories()
    posture = PostureEngine(
        keys=inv["keys"], certificates=inv["certificates"], pki=inv["pki"],
        encryption=inv["encryption"], network=inv["network"], tls=inv["tls"],
        kubernetes=inv["kubernetes"], serverless=inv["serverless"],
    ).evaluate()
    by_provider = {p.provider: p for p in posture.providers.values()}
    assert set(by_provider) == {"aws", "azure", "gcp"}
    assert by_provider["aws"].non_rotating_keys == 1
    assert by_provider["gcp"].non_rotating_keys == 1
    assert by_provider["aws"].expiring_certificates == 1


def test_posture_unknown_configurations():
    inv = _inventories()
    posture = PostureEngine(
        keys=inv["keys"], certificates=inv["certificates"], pki=inv["pki"],
        encryption=inv["encryption"], network=inv["network"], tls=inv["tls"],
        kubernetes=inv["kubernetes"], serverless=inv["serverless"],
    ).evaluate()
    assert posture.metrics["unknown_crypto_configurations"] >= 0
    assert "total_assets" in posture.metrics


def test_posture_to_dict_shape():
    posture = PostureEngine().evaluate()
    payload = posture.to_dict()
    assert "unified" in payload and "by_provider" in payload
    assert len(payload["by_provider"]) == 3
