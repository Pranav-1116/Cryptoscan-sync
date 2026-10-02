"""Structured vendor due-diligence profile.

The profile is intentionally metadata-only: it accepts contracts, contacts,
assessments, certifications, data handling, incidents, dependencies, access,
and exit planning, but rejects secrets and credential values. A profile may be
DRAFT while incomplete; completeness is calculated and never inferred as risk
acceptance.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

SchemaStatus = Literal["DRAFT", "IN_REVIEW", "APPROVED", "EXPIRED"]


class ProfileModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, populate_by_name=True)


class VendorIdentity(ProfileModel):
    legal_name: str = Field(min_length=1, max_length=240)
    vendor_id: str | None = Field(default=None, max_length=120)
    duns_number: str | None = Field(default=None, max_length=32)
    vendor_type: Literal["OEM", "ISV", "VAR", "MSP", "CSP", "SYSTEM_INTEGRATOR", "CONSULTING", "OTHER"] | None = None
    vendor_tier: int | None = Field(default=None, ge=1, le=99)
    parent_company: str | None = None
    ownership_structure: str | None = None
    headquarters_location: str | None = None
    jurisdictions: list[str] = Field(default_factory=list)
    operating_locations: list[str] = Field(default_factory=list)


class ContactDirectory(ProfileModel):
    business: str | None = None
    technical_support: str | None = None
    security_incident_response: str | None = None
    account_manager: str | None = None
    escalation_contacts: list[str] = Field(default_factory=list)
    emergency_24x7: str | None = None


class ComponentService(ProfileModel):
    component_id: str = Field(min_length=1, max_length=120)
    name: str = Field(min_length=1, max_length=240)
    version: str | None = None
    component_type: Literal["SOFTWARE_LIBRARY", "FRAMEWORK", "SAAS", "HARDWARE", "PROFESSIONAL_SERVICES", "CLOUD_INFRASTRUCTURE", "MANAGED_SERVICE", "OTHER"]
    license_model: str | None = None
    support_level: str | None = None
    eol_date: date | None = None
    replacement_product: str | None = None
    used_by: list[str] = Field(default_factory=list)
    criticality: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    alternatives: list[str] = Field(default_factory=list)
    vendor_lock_in_risk: Literal["high", "medium", "low", "unknown"] = "unknown"


class ContractDetails(ProfileModel):
    contract_id: str = Field(min_length=1, max_length=160)
    contract_type: Literal["MSA", "SOFTWARE_LICENSE", "PROFESSIONAL_SERVICES", "DPA", "BAA", "OTHER"]
    start_date: date | None = None
    end_date: date | None = None
    auto_renewal: bool | None = None
    termination_notice_days: int | None = Field(default=None, ge=0)
    termination_terms: str | None = None
    contract_value: float | None = Field(default=None, ge=0)
    contract_currency: str | None = Field(default=None, max_length=3)
    payment_terms: str | None = None


class ServiceLevelAgreement(ProfileModel):
    contract_id: str | None = None
    uptime_guarantee: str | None = None
    response_time: str | None = None
    resolution_time: str | None = None
    performance_metrics: dict[str, Any] = Field(default_factory=dict)
    penalties: str | None = None
    remedies: str | None = None
    service_credits: str | None = None


class LegalLiability(ProfileModel):
    limitation_of_liability: str | None = None
    indemnification: str | None = None
    insurance_requirements: str | None = None
    intellectual_property: str | None = None
    confidentiality: str | None = None
    governing_law: str | None = None
    dispute_resolution: str | None = None


class AssessmentFinding(ProfileModel):
    finding_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Literal["critical", "high", "medium", "low", "info", "unknown"] = "unknown"
    status: Literal["OPEN", "IN_PROGRESS", "REMEDIATED", "ACCEPTED", "UNKNOWN"] = "UNKNOWN"
    remediation: str | None = None
    due_date: date | None = None
    evidence_reference: str | None = None


class Subprocessor(ProfileModel):
    name: str = Field(min_length=1)
    service: str | None = None
    processing_purpose: str | None = None
    locations: list[str] = Field(default_factory=list)
    data_categories: list[str] = Field(default_factory=list)
    status: Literal["APPROVED", "PENDING", "REJECTED", "UNKNOWN"] = "UNKNOWN"
    notification_date: date | None = None
    evidence_reference: str | None = None


class SecurityAssessment(ProfileModel):
    assessment_id: str | None = None
    last_assessment_date: date | None = None
    assessment_type: Literal["QUESTIONNAIRE", "ON_SITE_AUDIT", "THIRD_PARTY_ASSESSMENT", "PEN_TEST", "CODE_REVIEW", "OTHER"] | None = None
    risk_rating: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    risk_score: float | None = Field(default=None, ge=0, le=1000)
    questionnaire_results: dict[str, Any] = Field(default_factory=dict)
    remediation_status: str | None = None
    open_findings: list[AssessmentFinding] = Field(default_factory=list)


class SecurityCertification(ProfileModel):
    certification_type: str = Field(min_length=1)
    issued_date: date | None = None
    expires_date: date | None = None
    report_date: date | None = None
    certificate_number: str | None = None
    scope: str | None = None
    evidence_reference: str | None = None
    status: Literal["CURRENT", "EXPIRED", "PENDING", "NOT_APPLICABLE", "UNVERIFIED"] = "UNVERIFIED"


class ComplianceProfile(ProfileModel):
    gdpr: bool | None = None
    ccpa_cpra: bool | None = None
    hipaa: bool | None = None
    sox: bool | None = None
    pci_dss: bool | None = None
    fedramp_level: str | None = None
    csa_star: str | None = None
    nist_csf_alignment: str | None = None
    industry_requirements: list[str] = Field(default_factory=list)
    dpa_signed: bool | None = None
    dpa_version: str | None = None
    dpa_date: date | None = None
    subprocessors: list[Subprocessor] = Field(default_factory=list)


class SecurityCompliance(ProfileModel):
    assessments: list[SecurityAssessment] = Field(default_factory=list)
    certifications: list[SecurityCertification] = Field(default_factory=list)
    compliance: ComplianceProfile = Field(default_factory=ComplianceProfile)


class DataPrivacyProfile(ProfileModel):
    data_types_processed: list[Literal["PII", "PCI", "PHI", "FINANCIAL", "PROPRIETARY", "CONFIDENTIAL", "OTHER"]] = Field(default_factory=list)
    data_classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] | None = None
    data_flow: str | None = None
    data_residency: list[str] = Field(default_factory=list)
    data_sovereignty: list[str] = Field(default_factory=list)
    data_retention: str | None = None
    data_deletion_process: str | None = None
    privacy_policy_url: str | None = None
    data_privacy_framework: str | None = None
    standard_contractual_clauses: str | None = None
    binding_corporate_rules: str | None = None
    privacy_certifications: list[str] = Field(default_factory=list)
    dpo_contact: str | None = None
    subprocessors: list[Subprocessor] = Field(default_factory=list)


class FundingEvent(ProfileModel):
    event_date: date | None = None
    event_type: str | None = None
    amount: float | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, max_length=3)
    investors: list[str] = Field(default_factory=list)
    evidence_reference: str | None = None


class FinancialStabilityProfile(ProfileModel):
    public_or_private: Literal["PUBLIC", "PRIVATE", "SUBSIDIARY", "UNKNOWN"] = "UNKNOWN"
    financial_statements_reference: str | None = None
    annual_revenue_range: str | None = None
    profitability_status: str | None = None
    credit_rating: str | None = None
    d_and_b_rating: str | None = None
    funding_status: str | None = None
    recent_funding: list[FundingEvent] = Field(default_factory=list)
    business_continuity_plan: str | None = None
    financial_risk: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    years_in_business: int | None = Field(default=None, ge=0)
    customer_base_summary: str | None = None
    market_share_summary: str | None = None
    strategic_importance: Literal["critical", "high", "medium", "low"] | None = None
    succession_plan: str | None = None


class SecurityIncident(ProfileModel):
    incident_id: str = Field(min_length=1)
    incident_type: Literal["BREACH", "OUTAGE", "PERFORMANCE", "DATA_LOSS", "COMPLIANCE", "OTHER"]
    occurred_on: date | None = None
    disclosed_on: date | None = None
    scope: str | None = None
    customer_impact: str | None = None
    root_cause: str | None = None
    remediation: str | None = None
    notification_timeliness: str | None = None
    severity: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    status: str | None = None


class IncidentHistory(ProfileModel):
    incidents: list[SecurityIncident] = Field(default_factory=list)
    incident_response_plan: str | None = None
    notification_obligations: str | None = None
    incident_response_time: str | None = None
    communication_channels: list[str] = Field(default_factory=list)


class SubVendor(ProfileModel):
    name: str = Field(min_length=1)
    service: str | None = None
    tier: int = Field(default=2, ge=2, le=99)
    locations: list[str] = Field(default_factory=list)
    criticality: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    risk_rating: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    evidence_reference: str | None = None


class IntegrationPoint(ProfileModel):
    name: str = Field(min_length=1)
    direction: Literal["INBOUND", "OUTBOUND", "BIDIRECTIONAL", "UNKNOWN"] = "UNKNOWN"
    protocol: str | None = None
    data_exchanged: list[str] = Field(default_factory=list)
    dependent_systems: list[str] = Field(default_factory=list)
    criticality: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    cascading_failure_effect: str | None = None


class VendorDependencyProfile(ProfileModel):
    critical_dependency: bool | None = None
    single_point_of_failure: bool | None = None
    concentration_risk: Literal["high", "medium", "low", "unknown"] = "unknown"
    systemic_risk: str | None = None
    irreplaceability: Literal["high", "medium", "low", "unknown"] = "unknown"
    vendor_lock_in_summary: str | None = None
    sub_vendors: list[SubVendor] = Field(default_factory=list)
    supply_chain_visibility_depth: int | None = Field(default=None, ge=1, le=99)
    subvendor_change_notification: str | None = None
    ecosystem_vendors: list[str] = Field(default_factory=list)
    integration_points: list[IntegrationPoint] = Field(default_factory=list)
    cascading_failure_analysis: str | None = None


class AccessPermissionProfile(ProfileModel):
    access_types: list[Literal["REMOTE", "API", "VPN", "PHYSICAL", "ADMINISTRATIVE"]] = Field(default_factory=list)
    access_scope: list[str] = Field(default_factory=list)
    access_controls: list[str] = Field(default_factory=list)
    mfa_required: bool | None = None
    ip_restrictions: str | None = None
    time_restrictions: str | None = None
    privileged_access: bool | None = None
    access_review_frequency: str | None = None
    background_checks: str | None = None
    nda_status: str | None = None
    training_requirements: str | None = None
    personnel_change_notification: str | None = None


class ExitStrategyProfile(ProfileModel):
    transition_period: str | None = None
    data_retrieval_process: str | None = None
    knowledge_transfer: str | None = None
    license_portability: str | None = None
    escrow_arrangements: str | None = None
    replacement_plan: str | None = None
    migration_plan: str | None = None
    rollback_plan: str | None = None
    last_tested_on: date | None = None


class ProfileEvidence(ProfileModel):
    evidence_id: str = Field(min_length=1)
    evidence_type: Literal["CONTRACT", "ASSESSMENT", "CERTIFICATION", "QUESTIONNAIRE", "OBSERVED_SCAN", "ATTESTATION", "OTHER"]
    evidence_reference: str = Field(min_length=1)
    status: Literal["PASS", "FAIL", "PENDING", "EXPIRED", "UNAVAILABLE", "UNVERIFIED"] = "UNVERIFIED"
    captured_at: datetime | None = None
    issuer: str | None = None
    reviewed_by: str | None = None
    limitations: list[str] = Field(default_factory=list)
    sha256: str | None = None


class VendorProfile(ProfileModel):
    profile_schema: str = Field(default="cryptoscan.vendor-profile/1", alias="schema")
    identity: VendorIdentity
    contacts: ContactDirectory = Field(default_factory=ContactDirectory)
    components: list[ComponentService] = Field(default_factory=list)
    contracts: list[ContractDetails] = Field(default_factory=list)
    service_level_agreements: list[ServiceLevelAgreement] = Field(default_factory=list)
    legal_liability: LegalLiability = Field(default_factory=LegalLiability)
    security_compliance: SecurityCompliance = Field(default_factory=SecurityCompliance)
    data_privacy: DataPrivacyProfile = Field(default_factory=DataPrivacyProfile)
    financial_stability: FinancialStabilityProfile = Field(default_factory=FinancialStabilityProfile)
    incident_history: IncidentHistory = Field(default_factory=IncidentHistory)
    dependencies: VendorDependencyProfile = Field(default_factory=VendorDependencyProfile)
    access_permissions: AccessPermissionProfile = Field(default_factory=AccessPermissionProfile)
    exit_strategy: ExitStrategyProfile = Field(default_factory=ExitStrategyProfile)
    evidence: list[ProfileEvidence] = Field(default_factory=list)

    @field_validator("profile_schema")
    @classmethod
    def validate_schema(cls, value: str) -> str:
        if value != "cryptoscan.vendor-profile/1":
            raise ValueError("unsupported vendor profile schema")
        return value


_SECRET_KEY = re.compile(r"(?i)(password|secret_value|private_key|api_key|access_key|client_secret|credential_value|connection_string)")
_SECRET_VALUE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|bearer\s+[a-z0-9._-]{20,}", re.IGNORECASE)


def _reject_secrets(value: Any, path: str = "profile") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_path = f"{path}.{key}"
            if _SECRET_KEY.search(str(key)):
                raise ValueError(f"secret-bearing field is not accepted: {key_path}")
            _reject_secrets(child, key_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secrets(child, f"{path}[{index}]")
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise ValueError(f"secret value is not accepted at {path}")


def parse_profile(value: dict[str, Any]) -> VendorProfile:
    _reject_secrets(value)
    return VendorProfile.model_validate(value)


def _present(value: Any) -> bool:
    if value is None or value == "" or value == [] or value == {}:
        return False
    if isinstance(value, dict):
        return any(_present(child) for child in value.values())
    return True


_REQUIRED_PATHS = (
    ("identity.legal_name", lambda p: p.identity.legal_name),
    ("identity.vendor_id", lambda p: p.identity.vendor_id),
    ("identity.vendor_type", lambda p: p.identity.vendor_type),
    ("identity.vendor_tier", lambda p: p.identity.vendor_tier),
    ("identity.ownership_structure", lambda p: p.identity.ownership_structure),
    ("identity.headquarters_location", lambda p: p.identity.headquarters_location),
    ("identity.jurisdictions", lambda p: p.identity.jurisdictions),
    ("contacts.business", lambda p: p.contacts.business),
    ("contacts.technical_support", lambda p: p.contacts.technical_support),
    ("contacts.security_incident_response", lambda p: p.contacts.security_incident_response),
    ("contacts.escalation_contacts", lambda p: p.contacts.escalation_contacts),
    ("components", lambda p: p.components),
    ("contracts", lambda p: p.contracts),
    ("service_level_agreements", lambda p: p.service_level_agreements),
    ("legal_liability.governing_law", lambda p: p.legal_liability.governing_law),
    ("security_compliance.assessments", lambda p: p.security_compliance.assessments),
    ("security_compliance.certifications", lambda p: p.security_compliance.certifications),
    ("security_compliance.compliance.dpa_signed", lambda p: p.security_compliance.compliance.dpa_signed),
    ("data_privacy.data_types_processed", lambda p: p.data_privacy.data_types_processed),
    ("data_privacy.data_classification", lambda p: p.data_privacy.data_classification),
    ("data_privacy.data_flow", lambda p: p.data_privacy.data_flow),
    ("data_privacy.data_residency", lambda p: p.data_privacy.data_residency),
    ("data_privacy.data_sovereignty", lambda p: p.data_privacy.data_sovereignty),
    ("data_privacy.data_retention", lambda p: p.data_privacy.data_retention),
    ("data_privacy.data_deletion_process", lambda p: p.data_privacy.data_deletion_process),
    ("data_privacy.dpo_contact", lambda p: p.data_privacy.dpo_contact),
    ("financial_stability.financial_risk", lambda p: p.financial_stability.financial_risk if p.financial_stability.financial_risk != "unknown" else None),
    ("financial_stability.business_continuity_plan", lambda p: p.financial_stability.business_continuity_plan),
    ("incident_history.incident_response_plan", lambda p: p.incident_history.incident_response_plan),
    ("dependencies.critical_dependency", lambda p: p.dependencies.critical_dependency),
    ("access_permissions.access_types", lambda p: p.access_permissions.access_types),
    ("exit_strategy.data_retrieval_process", lambda p: p.exit_strategy.data_retrieval_process),
    ("evidence", lambda p: p.evidence),
)


def profile_completeness(profile: VendorProfile) -> dict[str, Any]:
    missing: list[str] = []
    for path, getter in _REQUIRED_PATHS:
        try:
            if not _present(getter(profile)):
                missing.append(path)
        except (AttributeError, TypeError):
            missing.append(path)
    total = len(_REQUIRED_PATHS)
    present = total - len(missing)
    score = round((present / total) * 100, 2) if total else 0.0
    return {
        "score": score,
        "status": "COMPLETE" if not missing else "INCOMPLETE",
        "required_fields": total,
        "present_fields": present,
        "missing": missing,
        "next_actions": [f"Provide {path}" for path in missing],
    }


def profile_hash(profile: VendorProfile) -> str:
    blob = json.dumps(profile.model_dump(mode="json", by_alias=True), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def empty_profile(vendor_name: str, vendor_id: str) -> VendorProfile:
    return VendorProfile(identity=VendorIdentity(legal_name=vendor_name, vendor_id=vendor_id))


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


__all__ = [
    "VendorProfile", "VendorIdentity", "ProfileEvidence", "parse_profile",
    "profile_completeness", "profile_hash", "empty_profile", "ValidationError",
]
