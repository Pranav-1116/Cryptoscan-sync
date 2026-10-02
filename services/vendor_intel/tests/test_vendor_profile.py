from __future__ import annotations

import pytest

from vendor_intel.profile import (
    VendorProfile,
    empty_profile,
    parse_profile,
    profile_approval_issues,
    profile_completeness,
    profile_hash,
)
from vendor_intel.profile_risk import assess_profile_risk


def test_empty_profile_is_explicitly_incomplete_and_unknown():
    profile = empty_profile("Example Vendor", "vendor-1")
    completeness = profile_completeness(profile)
    risk = assess_profile_risk(profile)

    assert completeness["status"] == "INCOMPLETE"
    assert completeness["score"] < 100
    assert "data_privacy.data_residency" in completeness["missing"]
    assert risk["risk_rating"] == "UNKNOWN"
    assert risk["status"] == "INCOMPLETE"


def test_profile_represents_all_due_diligence_sections():
    profile = parse_profile(
        {
            "identity": {
                "legal_name": "Example Vendor",
                "vendor_id": "ext-1",
                "vendor_type": "ISV",
                "criticality": "high",
                "vendor_tier": 1,
                "ownership_structure": "Private company",
                "headquarters_location": "India",
                "jurisdictions": ["IN"],
            },
            "contacts": {
                "business": "business@example.test", "technical_support": "support@example.test",
                "security_incident_response": "security@example.test", "escalation_contacts": ["exec@example.test"],
            },
            "components": [{
                "component_id": "svc-1", "name": "Hosted API", "component_type": "SAAS",
                "criticality": "high", "vendor_lock_in_risk": "medium",
            }],
            "contracts": [{"contract_id": "msa-1", "contract_type": "MSA"}],
            "service_level_agreements": [{"uptime_guarantee": "99.9%"}],
            "legal_liability": {"governing_law": "India"},
            "security_compliance": {
                "assessments": [{"assessment_type": "QUESTIONNAIRE", "risk_rating": "medium"}],
                "certifications": [{"certification_type": "SOC 2", "status": "UNVERIFIED"}],
                "compliance": {"dpa_signed": False},
            },
            "data_privacy": {
                "data_types_processed": ["PII"], "data_classification": "CONFIDENTIAL",
                "data_flow": "API", "data_residency": ["IN"], "data_sovereignty": ["IN"],
                "data_retention": "Contractual", "data_deletion_process": "Ticketed deletion",
                "dpo_contact": "dpo@example.test",
            },
            "financial_stability": {
                "financial_risk": "medium", "business_continuity_plan": "Reference pending",
            },
            "incident_history": {"incident_response_plan": "Reference pending"},
            "dependencies": {"critical_dependency": True, "irreplaceability": "medium"},
            "access_permissions": {"access_types": ["API"], "access_controls": ["MFA"]},
            "exit_strategy": {"transition_period": "90 days", "data_retrieval_process": "Export API"},
            "evidence": [{
                "evidence_id": "ev-1", "evidence_type": "QUESTIONNAIRE",
                "evidence_reference": "ticket://vendor/1", "status": "PENDING",
            }],
        }
    )
    assert isinstance(profile, VendorProfile)
    assert profile.identity.vendor_type == "ISV"
    assert profile.data_privacy.data_types_processed == ["PII"]
    completeness = profile_completeness(profile)
    assert completeness["status"] == "COMPLETE"
    assert completeness["sections"]["identity"]["status"] == "COMPLETE"
    assert completeness["sections"]["data_privacy"]["status"] == "COMPLETE"
    approval_issues = profile_approval_issues(profile)
    assert any("evidence" in issue for issue in approval_issues)
    assert len(profile_hash(profile)) == 64


def test_profile_rejects_secrets_and_unknown_fields():
    with pytest.raises(ValueError, match="secret-bearing"):
        parse_profile({
            "identity": {"legal_name": "Example", "api_key": "do-not-store"},
        })

    with pytest.raises(ValueError):
        parse_profile({"identity": {"legal_name": "Example", "not_a_field": "x"}})


def test_profile_validates_contract_dates_and_evidence_integrity():
    with pytest.raises(ValueError, match="end_date"):
        parse_profile({
            "identity": {"legal_name": "Example"},
            "contracts": [{
                "contract_id": "c-1", "contract_type": "MSA",
                "start_date": "2026-02-01", "end_date": "2026-01-01",
            }],
        })
    with pytest.raises(ValueError, match="sha256"):
        parse_profile({
            "identity": {"legal_name": "Example"},
            "evidence": [{
                "evidence_id": "e-1", "evidence_type": "OTHER",
                "evidence_reference": "ref", "sha256": "not-a-digest",
            }],
        })
    with pytest.raises(ValueError, match="secret value"):
        parse_profile({
            "identity": {"legal_name": "Example"},
            "evidence": [{
                "evidence_id": "e-2", "evidence_type": "OTHER",
                "evidence_reference": "https://evidence.example/item?token=not-for-storage",
            }],
        })
