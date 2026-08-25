from graph_engine.core.store import Neo4jGraphStore
from graph_engine.migrations.migrator import apply_migrations, load_migration_files
from graph_engine.testing.fake_driver import FakeDriver


def _payload():
    return dict(
        systems=[
            {"id": "pay", "name": "payment-api", "compliance_scopes": ["PCI-DSS"]},
            {"id": "db", "name": "customer-db", "criticality": "TIER-1"},
            {"id": "mail", "name": "email-service"},
            {"id": "stripe", "name": "stripe-api"},
        ],
        assets=[{"id": "a1", "algorithm": "RSA-2048", "system_id": "pay", "confidence": "HIGH"}],
        edges=[
            {"parent_id": "pay", "child_id": "db", "relation": "CALLS"},
            {"parent_id": "db", "child_id": "mail", "relation": "CALLS"},
            {"parent_id": "pay", "child_id": "stripe", "relation": "CALLS"},
        ],
        processes=[
            {
                "id": "bp1",
                "name": "Payment Processing",
                "revenue_daily": 2_100_000,
                "customer_count": 1_800_000,
                "system_ids": ["pay"],
            }
        ],
        owners=[{"id": "sarah", "name": "Sarah Chen", "system_ids": ["pay"]}],
        vendors=[{"id": "v1", "name": "Stripe Inc.", "system_ids": ["stripe"]}],
    )


def test_fake_neo4j_blast_radius_and_impact():
    driver = FakeDriver()
    store = Neo4jGraphStore(driver, database="neo4j")
    store.apply_schema()
    synced = store.sync(**_payload())
    assert synced["backend"] == "neo4j"
    assert synced["nodes"] >= 8
    radius = store.blast_radius("pay", hops=5)
    names = [row["name"] for row in radius["systems"]]
    assert names[:2] == ["customer-db", "stripe-api"]
    assert "email-service" in names
    assert radius["backend"] == "neo4j"
    impact = store.business_impact("pay")
    assert impact["total_revenue_at_risk"] == 2_100_000
    assert impact["total_customers_at_risk"] == 1_800_000
    assert "Payment Processing" in impact["affected_processes"]
    assert "Sarah Chen" in impact["business_owners"]
    assert "PCI-DSS" in impact["compliance_scopes"]
    scopes = store.compliance_inheritance("pay")
    assert "PCI-DSS" in scopes["scopes"]
    path = store.vendor_path("pay")
    assert path["vendor"] == "Stripe Inc."
    assert path["hops"] >= 1
    crypto = store.crypto_for_system("pay")
    assert crypto["count"] == 1
    assert crypto["assets"][0]["algorithm"] == "RSA-2048"
    vis = store.to_vis()
    assert vis["backend"] == "neo4j"
    assert vis["nodes"]
    assert vis["edges"]


def test_migrator_loads_three_versions():
    files = load_migration_files()
    assert [path.name for path in files] == [
        "0001_create_constraints.cypher",
        "0002_create_indexes.cypher",
        "0003_add_business_process_nodes.cypher",
    ]
    driver = FakeDriver()
    result = apply_migrations(driver.session().run)
    assert result["count"] == 3
