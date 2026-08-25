from business_context.core.enricher import enrich_assets, priority_score


def test_priority_score_weights_revenue():
    high = priority_score(revenue_daily=2_000_000, customer_count=1_000_000, compliance_fail=True, technical_severity="CRITICAL")
    low = priority_score(revenue_daily=0, customer_count=0, compliance_fail=False, technical_severity="LOW")
    assert high > low


def test_enrich_assets_attaches_context():
    rows = enrich_assets(
        [{"id": "a1", "algorithm": "RSA", "compliance_status": "FAIL", "system_id": "pay"}],
        systems=[{"id": "pay", "name": "payment-api", "asset_ids": ["a1"], "compliance_scopes": ["PCI-DSS"]}],
        processes=[{"id": "p", "name": "Payments", "revenue_daily": 1000, "customer_count": 10, "system_ids": ["pay"]}],
        owners=[{"id": "o", "name": "Sarah", "system_ids": ["pay"]}],
    )
    ctx = rows[0]["business_context"]
    assert ctx["total_revenue_at_risk"] == 1000
    assert ctx["priority"] in {"P0", "P1"}
    assert "Sarah" in ctx["business_owners"]
