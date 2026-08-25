from reporting.analytics import build_analytics, pqc_forecast


def test_analytics_roll_up():
    report = build_analytics(
        assets=[
            {
                "id": "a1",
                "algorithm": "RSA",
                "system_id": "pay",
                "compliance_status": "FAIL",
                "created_at": "2024-01-02T00:00:00Z",
                "extra": {
                    "business_context": {"total_revenue_at_risk": 1000, "total_customers_at_risk": 10, "priority": "P0"},
                    "quantum_risk": {"risk_category": "CRITICAL", "quantum_risk_score": 90},
                },
            }
        ],
        findings=[{"algorithm": "RSA", "compliance_status": "FAIL", "created_at": "2024-01-02"}],
        systems=[{"id": "pay", "name": "payment-api", "owner": "Finance", "current_agility_score": 20}],
        quantum={"vulnerable_count": 10, "pqc_ready_count": 1, "overall_hndl_risk": "HIGH"},
    )
    assert report["trends"]
    assert report["heatmap"][0]["unit"] == "Finance"
    assert report["recommendations"][0]["rank"] == 1
    assert report["executive"]["totals"]["assets"] == 1
    forecast = pqc_forecast(vulnerable=100, migrated=10, monthly_rate=0.04, deadline_months=12)
    assert forecast["status"] == "AT_RISK"
