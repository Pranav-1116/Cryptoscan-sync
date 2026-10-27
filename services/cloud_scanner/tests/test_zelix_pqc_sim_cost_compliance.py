"""ZELNX §16 PQC readiness + §17 migration simulation + §18 cost + §19 compliance."""

from __future__ import annotations

import pytest

from cloud_scanner.enterprise.compliance_mapping import (
    COMPLIANT,
    NON_COMPLIANT,
    NOT_APPLICABLE,
    ComplianceMappingEngine,
    ComplianceRule,
    UNKNOWN,
)
from cloud_scanner.enterprise.cost_intelligence import (
    ASSUMED,
    ESTIMATED,
    PROVIDER_REPORTED,
    CostIntelligenceEngine,
)
from cloud_scanner.enterprise.certificate_discovery import CertificateDiscovery
from cloud_scanner.enterprise.dependency_graph import CloudDependencyGraph
from cloud_scanner.enterprise.key_discovery import KeyDiscovery
from cloud_scanner.enterprise.migration_simulation import CloudMigrationSimulator
from cloud_scanner.enterprise.pqc_readiness import (
    BLOCKED,
    HYBRID_READY,
    MIGRATION_REQUIRED,
    PQC_READY,
    UNKNOWN as PQC_UNKNOWN,
    CloudPqcReadinessEngine,
)
from cloud_scanner.enterprise.tls_discovery import TlsDiscovery

from zelix_fixtures import all_providers


def _inventories():
    entries = [p.to_provider_entry() for p in all_providers()]
    return {
        "keys": KeyDiscovery(entries).discover(),
        "certificates": CertificateDiscovery(entries).discover(),
        "tls": TlsDiscovery(entries).discover(),
    }


# ------------------------------------------------------------------ §16 PQC


def test_pqc_readiness_assesses_all_resources():
    inv = _inventories()
    pqc = CloudPqcReadinessEngine(keys=inv["keys"], certificates=inv["certificates"],
                                  tls=inv["tls"]).assess()
    assert pqc.summary()["assessed"] == \
        inv["keys"].count() + inv["certificates"].count() + inv["tls"].summary()["endpoints"]


def test_pqc_never_ready_without_evidence():
    inv = _inventories()
    pqc = CloudPqcReadinessEngine(keys=inv["keys"], certificates=inv["certificates"],
                                  tls=inv["tls"]).assess()
    # no evidence injected → nothing may be classified PQC_READY
    assert len(pqc.by_verdict(PQC_READY)) == 0
    assert len(pqc.by_verdict(PQC_UNKNOWN)) > 0


def test_pqc_ready_with_full_evidence():
    inv = _inventories()
    key_id = inv["keys"].keys[0].key_id
    evidence = {
        key_id: {
            "provider_capability": "PQC_READY",
            "service_compatibility": "COMPATIBLE",
            "application_dependency": "NONE",
            "library_compatibility": "COMPATIBLE",
            "hsm_dependency": "NONE",
            "network_dependency": "NONE",
            "vendor_readiness": "READY",
            "pqc_algorithm": "ML-KEM-768",
        }
    }
    pqc = CloudPqcReadinessEngine(keys=inv["keys"], certificates=inv["certificates"],
                                  tls=inv["tls"],
                                  resource_evidence=evidence).assess()
    ready = pqc.by_verdict(PQC_READY)
    assert len(ready) == 1
    assert ready[0].resource_id == key_id
    assert ready[0].score >= 9.0
    assert any("pqc_algorithm=ML-KEM-768" in e for e in ready[0].evidence)


def test_pqc_blocked_when_hsm_or_network_dependency():
    inv = _inventories()
    key_id = inv["keys"].keys[0].key_id
    evidence = {
        key_id: {
            "provider_capability": "PQC_READY",
            "service_compatibility": "COMPATIBLE",
            "application_dependency": "NONE",
            "library_compatibility": "COMPATIBLE",
            "hsm_dependency": "BLOCKED",
            "network_dependency": "NONE",
            "vendor_readiness": "READY",
        }
    }
    pqc = CloudPqcReadinessEngine(keys=inv["keys"], certificates=inv["certificates"],
                                  tls=inv["tls"],
                                  resource_evidence=evidence).assess()
    blocked = pqc.by_verdict(BLOCKED)
    assert any(r.resource_id == key_id for r in blocked)
    assert any("hsm_dependency=BLOCKED" in r.blockers for r in blocked)


def test_pqc_hybrid_ready_partial_evidence():
    inv = _inventories()
    key_id = inv["keys"].keys[0].key_id
    evidence = {
        key_id: {
            "provider_capability": "HYBRID_READY",
            "service_compatibility": "COMPATIBLE",
            "application_dependency": "MEDIUM",
            "library_compatibility": "COMPATIBLE",
            "hsm_dependency": "NONE",
            "network_dependency": "NONE",
            "vendor_readiness": "READY",
        }
    }
    pqc = CloudPqcReadinessEngine(keys=inv["keys"], certificates=inv["certificates"],
                                  tls=inv["tls"],
                                  resource_evidence=evidence).assess()
    hybrid = pqc.by_verdict(HYBRID_READY)
    assert any(r.resource_id == key_id for r in hybrid)


def test_pqc_classical_algorithm_scores_migration():
    inv = _inventories()
    pqc = CloudPqcReadinessEngine(keys=inv["keys"], certificates=inv["certificates"],
                                  tls=inv["tls"]).assess()
    {r.resource_id: r for r in pqc.results}
    rsa_key = next(r for r in pqc.results if r.public_key_algorithms == ["RSA"])
    assert rsa_key.score < 6.0
    assert rsa_key.verdict in (MIGRATION_REQUIRED, PQC_UNKNOWN)


def test_pqc_summary_shape():
    pqc = CloudPqcReadinessEngine().assess()
    summary = pqc.summary()
    assert set(summary["by_verdict"]) == {PQC_READY, HYBRID_READY, MIGRATION_REQUIRED,
                                          BLOCKED, PQC_UNKNOWN}


# ------------------------------------------------------------------ §17 simulation


def test_simulation_builds_steps_and_impacts():
    graph = CloudDependencyGraph()
    graph.add_edge("payments-api", "arn:aws:kms:key-1", "USES_KEY")
    graph.add_edge("payments-api", "api.bank.example", "EXPOSED_BY")
    simulator = CloudMigrationSimulator(graph)
    result = simulator.simulate(["arn:aws:kms:key-1", "api.bank.example"])
    assert result.steps
    assert result.verdict in ("COMPATIBLE", "BLOCKED")
    assert len(result.impacts) == 2


def test_simulation_impacts_dependents():
    graph = CloudDependencyGraph()
    graph.add_edge("payments-api", "arn:aws:kms:key-1", "USES_KEY")
    simulator = CloudMigrationSimulator(graph)
    result = simulator.simulate(["arn:aws:kms:key-1"])
    impact = next(i for i in result.impacts if i.resource_id == "arn:aws:kms:key-1")
    assert "payments-api" in impact.affected_dependents


def test_simulation_non_hybrid_step_blocks_rollback():
    graph = CloudDependencyGraph()
    simulator = CloudMigrationSimulator(
        graph,
        step_builder=lambda rid: [{"current_algorithm": "RSA", "replacement_algorithm": "ML-KEM-768",
                                   "hybrid": False, "service": "kms"}],
    )
    result = simulator.simulate(["key-1"])
    impact = result.impacts[0]
    assert impact.compatible is False
    assert impact.rollback_feasible is False
    assert result.verdict == "BLOCKED"


def test_simulation_uses_network_simulator_when_available():
    graph = CloudDependencyGraph()
    graph.add_edge("vpc-core", "vpn-1", "VPN_TUNNEL")

    class FakeNetworkSimulator:
        def __init__(self):
            self.calls = []

        def simulate_steps(self, steps):
            self.calls.append(steps)
            return {"verdict": "COMPATIBLE", "paths_evaluated": 1}

    fake = FakeNetworkSimulator()
    simulator = CloudMigrationSimulator(graph, network_simulator=fake)
    result = simulator.simulate(["vpn-1"])
    assert fake.calls
    assert result.path_simulations == [{"verdict": "COMPATIBLE", "paths_evaluated": 1}]


def test_simulation_default_steps_are_hybrid():
    steps = CloudMigrationSimulator(CloudDependencyGraph())._step_builder("k1")
    assert steps
    assert all(step.get("hybrid") is True for step in steps)


# ------------------------------------------------------------------ §18 cost


def test_cost_estimate_components_and_labels():
    cost = CostIntelligenceEngine()
    estimate = cost.estimate(
        workloads=10, storage_gb=100, egress_gb=50, hsm_keys=5, kms_keys=20,
        certificates=8, log_gb=10, engineering_hours=40, vendor_delta=100,
    )
    components = {line.component for line in estimate.lines}
    assert components == {"compute", "storage", "network", "hsm", "key_management",
                          "certificate", "logging", "migration_engineering", "vendor"}
    assert estimate.total() > 0
    assert estimate.to_dict()["total"] > 0
    assert estimate.to_dict()["currency"] == "USD"


def test_cost_confidence_labels():
    cost = CostIntelligenceEngine()
    estimate = cost.estimate(workloads=2, engineering_hours=10, kms_keys=1)
    labels = {line.component: line.confidence for line in estimate.lines}
    assert labels["compute"] == ESTIMATED
    assert labels["key_management"] == ESTIMATED
    assert labels["migration_engineering"] == ASSUMED


def test_cost_custom_pricing_is_provider_reported():
    cost = CostIntelligenceEngine(pricing_model={"compute": 90.0},
                                  provider_reported=True)
    estimate = cost.estimate(workloads=2)
    line = estimate.lines[0]
    assert line.component == "compute"
    assert line.confidence == PROVIDER_REPORTED
    assert line.amount == pytest.approx(180.0)


def test_cost_custom_pricing_without_provider_flag_is_assumed():
    cost = CostIntelligenceEngine(pricing_model={"compute": 90.0})
    estimate = cost.estimate(workloads=2)
    assert estimate.lines[0].confidence == ASSUMED


def test_cost_region_multiplier():
    cost = CostIntelligenceEngine()
    us = cost.estimate(workloads=1).to_dict()["total"]
    eu = cost.estimate(workloads=1, region="eu-west-1").to_dict()["total"]
    assert eu > us


def test_cost_currency_conversion():
    cost = CostIntelligenceEngine(currency="EUR")
    estimate = cost.estimate(workloads=1)
    assert estimate.currency == "EUR"
    payload = estimate.to_dict()
    assert payload["total_usd"] == pytest.approx(payload["total"] / 0.92, rel=1e-2)


def test_cost_zero_estimate_empty_lines():
    estimate = CostIntelligenceEngine().estimate()
    assert estimate.lines == []
    assert estimate.total() == 0


# ------------------------------------------------------------------ §19 compliance


def test_compliance_mapping_baseline_rules():
    inv = _inventories()
    report = ComplianceMappingEngine(keys=inv["keys"], certificates=inv["certificates"],
                                     tls=inv["tls"]).evaluate()
    assert report.summary()["evaluations"] > 0
    statuses = report.summary()["by_status"]
    assert statuses[COMPLIANT] > 0
    assert statuses[NON_COMPLIANT] > 0


def test_compliance_tls_min_1_2_flags_legacy():
    inv = _inventories()
    report = ComplianceMappingEngine(keys=inv["keys"], certificates=inv["certificates"],
                                     tls=inv["tls"]).evaluate()
    results = {r.resource_id: r for r in report.results if r.rule_id == "TLS_MIN_1_2"}
    assert results["legacy.bank.example"].status == NON_COMPLIANT
    assert results["api.bank.example"].status == COMPLIANT


def test_compliance_key_rules():
    inv = _inventories()
    report = ComplianceMappingEngine(keys=inv["keys"], certificates=inv["certificates"],
                                     tls=inv["tls"]).evaluate()
    results = {r.resource_id: r for r in report.results if r.rule_id == "KEYS_ROTATION_REQUIRED"}
    assert results["arn:aws:kms:key-2"].status == NON_COMPLIANT
    assert results["arn:aws:kms:key-1"].status == COMPLIANT
    assert results["arn:aws:kms:key-aws"].status == COMPLIANT  # provider-managed rotation


def test_compliance_certificate_sha1_flagged():
    inv = _inventories()
    report = ComplianceMappingEngine(keys=inv["keys"], certificates=inv["certificates"],
                                     tls=inv["tls"]).evaluate()
    results = {r.resource_id: r for r in report.results
               if r.rule_id == "CERTS_SHA256_OR_STRONGER"}
    assert results["arn:aws:acm:cert-exp"].status == NON_COMPLIANT
    assert results["arn:aws:acm:cert-1"].status == COMPLIANT


def test_compliance_custom_sector_rule():
    inv = _inventories()
    engine = ComplianceMappingEngine(
        keys=inv["keys"], certificates=inv["certificates"], tls=inv["tls"],
        rules=[ComplianceRule(
            rule_id="PCI_HSM_KEYS",
            description="PCI keys must be HSM-backed",
            controls=["PCI-HSM-CUSTODY"],
            sector="PCI-DSS",
            evaluate=lambda config: (
                COMPLIANT if config.get("kind") == "key" and config.get("hsm_backed")
                else NON_COMPLIANT if config.get("kind") == "key"
                else NOT_APPLICABLE),
        )],
    )
    report = engine.evaluate(sectors=["PCI-DSS"])
    assert report.sectors == ["PCI-DSS"]
    statuses = report.summary()["by_status"]
    assert statuses[COMPLIANT] == 2  # azure hsm + gcp hsm keys
    # worst-status rollup: aws keys are non-HSM → control is NON_COMPLIANT
    assert report.summary()["controls"]["PCI-HSM-CUSTODY"] == NON_COMPLIANT


def test_compliance_not_applicable_for_non_keys():
    inv = _inventories()
    report = ComplianceMappingEngine(keys=inv["keys"], certificates=inv["certificates"],
                                     tls=inv["tls"]).evaluate()
    results = {r.resource_id: r for r in report.results if r.rule_id == "KEYS_MIN_2048"}
    # certificates are not keys → NOT_APPLICABLE for key rules
    assert results["arn:aws:acm:cert-1"].status == NOT_APPLICABLE


def test_compliance_unknown_when_no_data():
    report = ComplianceMappingEngine().evaluate()
    assert report.summary()["evaluations"] == 0
    assert report.summary()["by_status"][UNKNOWN] == 0
