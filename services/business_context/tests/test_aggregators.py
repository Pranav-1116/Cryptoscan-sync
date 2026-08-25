from business_context.aggregators.metrics import min_sla, sum_customers, sum_revenue, union_scopes
from business_context.alerts.stakeholder import notify_stakeholders, render_template
from business_context.prioritization.scorer import priority_label, rank_assets


def test_aggregators_sum_and_union():
    processes = [
        {"revenue_daily": 100, "customer_count": 10, "sla_uptime": 99.9},
        {"revenue_daily": 50, "customer_count": 5, "sla_uptime": 99.99},
    ]
    assert sum_revenue(processes) == 150
    assert sum_customers(processes) == 15
    assert min_sla(processes) == 99.9
    assert union_scopes([{"compliance_scopes": ["PCI-DSS", "HIPAA"]}, {"compliance_scopes": ["PCI-DSS"]}]) == [
        "PCI-DSS",
        "HIPAA",
    ]


def test_priority_label_and_rank():
    assert priority_label(10, compliance_fail=True, revenue_daily=100) == "P0"
    ranked = rank_assets(
        [
            {"id": "a", "business_context": {"priority_score": 1}},
            {"id": "b", "business_context": {"priority_score": 9}},
        ]
    )
    assert ranked[0]["id"] == "b"


def test_stakeholder_renders_owner_and_exec_templates():
    sent = notify_stakeholders(
        [
            {
                "algorithm": "RSA",
                "file_path": "Pay.java",
                "compliance_status": "FAIL",
                "business_context": {
                    "priority": "P0",
                    "business_owners": ["Sarah"],
                    "affected_processes": ["Payments"],
                    "total_revenue_at_risk": 2_000_000,
                    "total_customers_at_risk": 100,
                    "compliance_scopes": ["PCI-DSS"],
                },
            }
        ]
    )
    assert sent
    assert "Sarah" in sent[0]["body"]
    assert sent[0]["executive_body"]
    assert "Action required" in render_template("business_owner_alert.txt", owner_name="A", process_name="P")
