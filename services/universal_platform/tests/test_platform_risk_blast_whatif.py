"""§29/§30/§31 tests — eight-factor risk engine, blast-radius analysis,
what-if migration analysis."""

from __future__ import annotations

from universal_platform.blast_radius import blast_radius
from universal_platform.risk import estate_risk, risk_score
from universal_platform.whatif import what_if


def test_risk_score_levels():
    assert risk_score()["level"] == "LOW"
    low = risk_score(crypto_risk=1, business_criticality=1, exposure=0,
                     dependency_count=0, quantum_risk=1,
                     migration_complexity=0, vendor_dependency=0,
                     hardware_dependency=0)
    assert low["level"] == "LOW"
    critical = risk_score(crypto_risk=4, business_criticality=4, exposure=4,
                          dependency_count=4, quantum_risk=4,
                          migration_complexity=4, vendor_dependency=4,
                          hardware_dependency=4)
    assert critical["level"] == "CRITICAL"
    assert critical["score"] == 100.0
    assert critical["missing_factors"] == []


def test_risk_score_from_asset_dict():
    asset = {"identity": "payments", "risk_factors": {
        "crypto_risk": 4, "business_criticality": 4, "exposure": 3,
        "dependency_count": 3, "quantum_risk": 4, "migration_complexity": 3,
        "vendor_dependency": 2, "hardware_dependency": 2}}
    result = risk_score(asset)
    assert result["level"] in ("HIGH", "CRITICAL")
    assert result["score"] > 60


def test_estate_risk_aggregation():
    assets = [
        {"identity": "a", "risk_factors": {"crypto_risk": 4,
                                           "business_criticality": 4,
                                           "exposure": 4, "dependency_count": 4,
                                           "quantum_risk": 4,
                                           "migration_complexity": 4,
                                           "vendor_dependency": 4,
                                           "hardware_dependency": 4}},
        {"identity": "b"},
    ]
    result = estate_risk(assets)
    assert result["count"] == 2
    assert result["by_level"]["CRITICAL"] == 1
    # mean of (100, 0) = 50 → MEDIUM (scale is honest, not padded)
    assert result["level"] == "MEDIUM"


def test_blast_radius_from_certificate():
    assets = {
        "payments.internal": {"asset_type": "certificate",
                              "domain": "crypto"},
        "lb-01": {"asset_type": "load_balancer", "domain": "network"},
        "app-pay": {"asset_type": "application", "domain": "application"},
        "api-pay": {"asset_type": "api", "domain": "application"},
        "hsm-1": {"asset_type": "hsm", "domain": "hardware"},
    }
    relationships = [
        {"from": "payments.internal", "to": "lb-01", "kind": "uses_cert"},
        {"from": "lb-01", "to": "app-pay", "kind": "serves"},
        {"from": "app-pay", "to": "api-pay", "kind": "hosts"},
        {"from": "app-pay", "to": "hsm-1", "kind": "has_hw"},
    ]
    result = blast_radius("payments.internal", assets, relationships)
    assert result["affected_count"] == 4
    assert result["business_impact"] is True
    assert "app-pay" in result["business_services_affected"]
    assert "api-pay" in result["business_services_affected"]
    # deterministic path from seed to a business service
    assert result["paths"]["app-pay"] == ["payments.internal", "lb-01",
                                          "app-pay"]


def test_whatif_checks_library_hardware_vendor_cloud():
    result = what_if(
        "RSA", "ML-KEM-768",
        libraries=[{"name": "OpenSSL", "version": "3.5",
                    "algorithms": "ML-KEM-768"}],
        hardware=[{"identity": "hsm-1", "crypto_capabilities": ["mlkem768"]}],
        vendors=[{"name": "Acme", "pqc_support": "ml-kem"}],
        cloud=[{"name": "aws-kms", "service": "kms"}],
        quantum={"quantum_status": "QUANTUM_SAFE"})
    assert result["feasible"] is True
    assert result["checks"]["libraries"]["supported"] is True
    assert result["checks"]["hardware"]["supported"] is True
    assert result["checks"]["vendor"]["supported"] is True
    assert result["checks"]["cloud"]["supported"] is True
    assert result["checks"]["impact"]["projected_quantum_status"] == \
        "QUANTUM_SAFE"
    assert result["migration_plan"]["steps"]
    assert result["honest_unknowns"] == []


def test_whatif_unknown_when_no_evidence():
    result = what_if("RSA", "ML-KEM-768")
    assert result["feasible"] is False
    assert result["checks"]["libraries"]["supported"] is False
    # unknown support is reported honestly, not guessed
    assert set(result["honest_unknowns"]) == {"libraries", "hardware",
                                              "vendor", "cloud"}
