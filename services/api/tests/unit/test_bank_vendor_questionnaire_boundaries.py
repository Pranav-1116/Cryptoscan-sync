"""Bank due-diligence negatives: names/declarations are not deployment proof."""
from datetime import date

import pytest
from pydantic import ValidationError

from api.routers.inventory import _pqc
from api.routers.quantum import MoscaRequest
from cbom.banking import assess_hsm_fleet, fips_validation, quantum_vulnerability
from quantum.plan import _family, mosca
from quantum.risk import hndl_risk


@pytest.mark.parametrize("algorithm", [None, "private-bank-cipher", "ML-KEM-MAGIC", "AES-MAGIC"])
def test_unrecognized_algorithm_is_not_reported_quantum_safe(algorithm):
    result = quantum_vulnerability(algorithm)
    assert result["quantum_vulnerable"] is None
    assert result["transition"] == "unknown"
    assert result["requires_review"] is True


@pytest.mark.parametrize("algorithm", ["Kyber768", "Dilithium", "SIKE", "HQC-128"])
def test_nonapproved_algorithm_name_cannot_make_inventory_ready(algorithm):
    assert _pqc(algorithm) != "ready"


@pytest.mark.parametrize("algorithm", ["X25519MLKEM768", "mlkem768x25519-sha256", "SecP256r1MLKEM768"])
def test_hybrid_is_recognized_without_claiming_deployment_readiness(algorithm):
    assert _pqc(algorithm) == "hybrid_candidate"
    assert _family(algorithm) == "PQC"


@pytest.mark.parametrize("module", ["Thales Luna unknown firmware", "OpenSSL FIPS Provider 999", "Utimaco", "TPM unknown SKU"])
def test_family_name_does_not_establish_exact_module_fips_validation(module):
    result = fips_validation(module)
    assert result["status"] == "unknown"
    assert result["validation_verified"] is False


def test_supplied_fips_assertion_is_retained_but_not_promoted_to_verified():
    result = fips_validation("ICSF", supplied={"claim": {"match": "icsf", "status": "validated", "cert": "test-only"}})
    assert result["status"] == "declared_not_verified"
    assert result["declared_status"] == "validated"
    assert result["cert"] == "test-only"
    assert result["validation_verified"] is False


@pytest.mark.parametrize("capabilities", [{"algorithms": ["ML-KEM"]}, {"supports_ml_kem": False}, {"notes": "ML-KEM not supported"}, {"roadmap": "ML-KEM next year"}])
def test_hsm_declaration_cannot_inflate_verified_readiness(capabilities):
    result = assess_hsm_fleet([{"asset_id": "synthetic-hsm", "manufacturer": "Thales", "model": "Luna", "hsm": capabilities}])
    assert result["pqc_ready"] == 0
    assert result["fips_validated_family"] == 0
    assert result["ready_share"] is None
    assert result["hsms"][0]["pqc_status"] != "ready"
    assert result["hsms"][0]["gap"]


@pytest.mark.parametrize("field,value", [("retention_years", -1), ("retention_years", True), ("migration_years", -1), ("migration_years", float("nan")), ("migration_years", float("inf")), ("migration_years", True), ("threat_year", 0), ("threat_year", True)])
def test_mosca_api_rejects_invalid_or_nonfinite_scenario_inputs(field, value):
    with pytest.raises(ValidationError):
        MoscaRequest(**{field: value})


@pytest.mark.parametrize("field,value", [("retention_years", -1), ("retention_years", True), ("migration_years", -1), ("migration_years", float("nan")), ("migration_years", float("inf")), ("migration_years", True), ("threat_year", 0)])
def test_mosca_direct_calls_cannot_bypass_scenario_validation(field, value):
    body = {"retention_years": 1, "migration_years": 1, "threat_year": 2035}
    body[field] = value
    with pytest.raises(ValueError):
        mosca(**body, today=date(2026, 1, 1))


def test_mosca_exposes_threat_year_as_assumption_not_prediction_or_regulation():
    result = mosca(retention_years=1, migration_years=1, threat_year=2035, today=date(2026, 1, 1))
    assert result["scenario_only"] is True
    assert result["threat_year_basis"] == "ASSUMPTION_NOT_FORECAST_OR_REGULATORY_DEADLINE"
    assert result["verdict"] == "SAFE_MARGIN"


@pytest.mark.parametrize("algorithm,retention", [(None, 10), ("custom-bank-cipher", 10), ("RSA", None)])
def test_missing_algorithm_or_retention_does_not_become_no_hndl_risk(algorithm, retention):
    assert hndl_risk(algorithm=algorithm, retention_years=retention)["hndl_risk"] == "UNKNOWN"


def test_banking_empty_or_unknown_inventory_cannot_prove_no_hndl_exposure():
    from cbom.banking import hndl_register
    for components in ([], [{"algorithm": "custom-bank-cipher"}]):
        result = hndl_register({"layers": {"cbom": {"components": components}}})
        assert result["at_risk"] is None
        assert result["assessment_complete"] is False
        assert result["completeness_proven"] is False


def test_signature_only_use_is_not_harvestable_ciphertext():
    from cbom.banking import hndl_register
    assert hndl_risk(algorithm="RSA", purpose="SIGNATURE", retention_years=10)["hndl_risk"] == "NONE"
    result = hndl_register({"layers": {"cbom": {"components": [{"algorithm": "ECDSA", "purpose": "signature"}]}}})
    assert result["total"] == 0


def test_general_regulatory_effective_dates_are_not_pqc_deadlines():
    from quantum.risk import migration_deadline
    result = migration_deadline(scopes=["DORA", "PCI-DSS", "CNSA"], today=date(2026, 1, 1))
    assert not any(r["reason"].startswith("regulatory:") for r in result["candidates"])
    assert result["regulatory_deadline_established"] is False
    assert result["deadline_basis"] == "ENGINEERING_PLANNING_ASSUMPTION"


def test_migration_planning_handles_leap_day_without_inventing_a_regulatory_date():
    from quantum.risk import migration_deadline
    assert migration_deadline(retention_years=30, today=date(2024, 2, 29))["deadline_date"] == "2026-02-28"


def test_banking_roadmap_marks_legacy_dates_as_planning_not_regulatory_approval():
    from cbom.banking import migration_roadmap
    result = migration_roadmap({})
    assert result["regulatory_approval"] is False
    assert result["deadline_basis"] == "HISTORICAL_DRAFT_PLANNING_REFERENCE_REVIEW_REQUIRED"


@pytest.mark.parametrize("algorithm", ["ML-KEM-MAGIC", "AES-MAGIC", "Kyber768", "SIKE"])
def test_risk_engine_does_not_promote_spoofed_or_nonapproved_pqc_names(algorithm):
    from quantum.risk import classify
    assert classify(algorithm)["threat_type"] == "UNKNOWN"


def test_plan_hybrid_candidate_is_not_verified_deployment_readiness():
    from quantum.risk import analyze_quantum_risk
    result = analyze_quantum_risk([{"algorithm": "X25519MLKEM768"}])
    assert result["pqc_candidate_count"] == 1
    assert result["pqc_ready_count"] == 0
    assert result["deployment_readiness"] == "NOT_ESTABLISHED"


def test_empty_or_unassessed_risk_portfolio_does_not_default_to_low_hndl():
    from quantum.risk import analyze_quantum_risk
    for findings in ([], [{"algorithm": "custom-bank-cipher"}], [{"algorithm": "RSA"}]):
        assert analyze_quantum_risk(findings)["overall_hndl_risk"] == "UNKNOWN"


def test_migration_plan_preserves_single_pass_findings_and_systems():
    from quantum.plan import build_migration_plan
    findings = [{"algorithm": "RSA", "purpose": "KEY_EXCHANGE", "system_id": "payments"}]
    systems = [{"id": "payments", "extra": {"data_retention_years": 10}}]
    expected = build_migration_plan(findings, systems=systems, today=date(2026, 1, 1))
    actual = build_migration_plan(iter(findings), systems=iter(systems), today=date(2026, 1, 1))
    assert actual == expected
