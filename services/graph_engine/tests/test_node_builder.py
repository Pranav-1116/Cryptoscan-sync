from graph_engine.builders.node_builder import NodeBuilder


def test_node_builder_links_assets_to_systems():
    builder = NodeBuilder()
    engine = builder.build(
        systems=[{"id": "pay", "name": "payments", "compliance_scopes": ["PCI-DSS"]}],
        assets=[{"id": "a1", "algorithm": "AES", "purpose": "ENCRYPTION", "system_id": "pay"}],
        edges=[{"parent_id": "pay", "child_id": "web"}],
    )
    crypto = engine.crypto_for_system("pay")
    assert crypto["count"] == 1
    assert engine.counts()["nodes"] >= 2
