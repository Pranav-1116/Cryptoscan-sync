from business_context.aggregators.customer_aggregator import sum_customers
from business_context.aggregators.revenue_aggregator import sum_revenue
from business_context.alerts.business_owner_notifier import notify_owners
from business_context.alerts.executive_notifier import notify_executives
from business_context.alerts.stakeholder_alerter import StakeholderAlerter
from business_context.config.settings import load_settings
from business_context.core.enrichment_runner import run_enrichment
from business_context.models.business_context import BusinessContext
from business_context.models.business_owner import BusinessOwner
from business_context.models.business_process import BusinessProcess
from business_context.prioritization.priority_score import PriorityScore


def test_named_aggregators_and_notifiers():
    processes = [{"revenue_daily": 10, "customer_count": 2, "name": "Pay", "system_ids": ["pay"]}]
    assert sum_revenue(processes) == 10
    assert sum_customers(processes) == 2
    ranked = run_enrichment(
        [{"id": "a1", "algorithm": "RSA", "compliance_status": "FAIL", "system_id": "pay"}],
        systems=[{"id": "pay", "name": "payments", "compliance_scopes": ["PCI-DSS"]}],
        processes=processes,
        owners=[{"id": "o1", "name": "Sarah", "system_ids": ["pay"]}],
    )
    assert ranked
    assets = [
        {
            "algorithm": "RSA",
            "file_path": "Pay.java",
            "business_context": {
                "priority": "P0",
                "business_owners": ["Sarah"],
                "affected_processes": ["Pay"],
                "total_revenue_at_risk": 2_000_000,
                "total_customers_at_risk": 10,
            },
        }
    ]
    sent = notify_owners(assets)
    assert sent
    assert notify_executives(assets)
    alerts = StakeholderAlerter().alert(assets)
    assert alerts
    score = PriorityScore.compute(revenue_daily=2_000_000, customer_count=10, compliance_fail=True)
    assert score.label == "P0"
    assert score.to_dict()["priority_score"] > 0
    ctx = BusinessContext.from_asset(assets[0])
    assert ctx.priority == "P0"
    assert BusinessProcess.from_mapping(processes[0]).name == "Pay"
    assert BusinessOwner.from_mapping({"name": "Sarah", "system_ids": ["pay"]}).name == "Sarah"
    assert load_settings().alert_on_p0 is True
