from graph_engine.core.engine import GraphEngine


def test_blast_radius_and_revenue():
    graph = GraphEngine().build(
        systems=[
            {"id": "pay", "name": "payment-api", "compliance_scopes": ["PCI-DSS"]},
            {"id": "db", "name": "customer-db", "criticality": "TIER-1"},
            {"id": "mail", "name": "email-service"},
        ],
        edges=[
            {"parent_id": "pay", "child_id": "db", "relation": "CALLS"},
            {"parent_id": "db", "child_id": "mail", "relation": "CALLS"},
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
    )
    radius = graph.blast_radius("pay", hops=5)
    names = [row["name"] for row in radius["systems"]]
    assert names == ["customer-db", "email-service"]
    assert radius["systems"][0]["hops"] == 1
    impact = graph.business_impact("pay")
    assert impact["total_revenue_at_risk"] == 2_100_000
    assert impact["total_customers_at_risk"] == 1_800_000
    assert "Payment Processing" in impact["affected_processes"]
    assert "Sarah Chen" in impact["business_owners"]
    assert "PCI-DSS" in impact["compliance_scopes"]
    vis = graph.to_vis()
    assert len(vis["nodes"]) >= 4
    assert vis["edges"]
    assert vis["backend"] == "memory"
    assert graph.compliance_inheritance("pay")["scopes"] == ["PCI-DSS"]
    crypto = graph.crypto_for_system("pay")
    assert crypto["count"] == 0
