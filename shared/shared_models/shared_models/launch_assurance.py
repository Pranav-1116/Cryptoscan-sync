"""Launch assurance contracts. Recorded review is never accreditation or an SLA."""

from datetime import datetime
from typing import Literal
from pydantic import Field, model_validator
from .assurance import Contract, Revision, Text, Ref, SHA

AREAS = ("TENANT_ISOLATION", "AUTHORIZATION", "UPLOAD_PARSER", "SECRETS_EVIDENCE", "SUPPLY_DEPLOYMENT")
REQUIRED_CASES = {
    "tenant.cross_read": "TENANT_ISOLATION",
    "tenant.cross_write": "TENANT_ISOLATION",
    "tenant.null_scope": "TENANT_ISOLATION",
    "auth.revoked_session": "AUTHORIZATION",
    "auth.denied_role": "AUTHORIZATION",
    "upload.traversal": "UPLOAD_PARSER",
    "upload.resource_limits": "UPLOAD_PARSER",
    "parser.no_privileged_fallback": "UPLOAD_PARSER",
    "evidence.cross_estate_download": "SECRETS_EVIDENCE",
    "secrets.redaction": "SECRETS_EVIDENCE",
    "supply.digest_tamper": "SUPPLY_DEPLOYMENT",
    "supply.untrusted_signature": "SUPPLY_DEPLOYMENT",
    "deploy.secret_ca_mounts": "SUPPLY_DEPLOYMENT",
}
DUTIES = (
    "VULNERABILITY_RESPONSE",
    "INCIDENT_RESPONSE",
    "BACKUP_RESTORE",
    "CERTIFICATE_ROTATION",
    "CREDENTIAL_ROTATION",
    "SUPPORT_ESCALATION",
    "RELEASE_APPROVAL",
    "DATA_RETENTION",
    "CUSTOMER_OFFBOARDING",
)
Area = Literal["TENANT_ISOLATION", "AUTHORIZATION", "UPLOAD_PARSER", "SECRETS_EVIDENCE", "SUPPLY_DEPLOYMENT"]
Duty = Literal[
    "VULNERABILITY_RESPONSE",
    "INCIDENT_RESPONSE",
    "BACKUP_RESTORE",
    "CERTIFICATE_ROTATION",
    "CREDENTIAL_ROTATION",
    "SUPPORT_ESCALATION",
    "RELEASE_APPROVAL",
    "DATA_RETENTION",
    "CUSTOMER_OFFBOARDING",
]


class TestCase(Contract):
    case_id: Text
    area: Area
    procedure: Text
    expected_result: Text


class Engagement(Contract):
    report_max_age_seconds: int = Field(2592000, ge=60, le=31536000)
    artifact_id: Ref
    environment_ref: Text
    provider_organization: Text
    lead_tester_ref: Text
    public_key_base64: str = Field(min_length=40, max_length=100)
    independence_declaration_blob_id: Ref
    scope_blob_id: Ref
    deployment_manifest_blob_id: Ref
    expires_at: datetime
    cases: list[TestCase] = Field(min_length=13, max_length=100)
    exclusions: list[Text] = Field(min_length=1, max_length=30)

    @model_validator(mode="after")
    def complete_scope(self):
        cases = {c.case_id: c.area for c in self.cases}
        if len(cases) != len(self.cases) or any(cases.get(k) != v for k, v in REQUIRED_CASES.items()):
            raise ValueError("All required negative cases must appear once in their correct areas")
        return self


class CaseResult(Contract):
    case_id: Text
    outcome: Literal["PASSED", "FAILED", "NOT_TESTED", "INCONCLUSIVE"]
    evidence_ref: Text


class SecurityFinding(Contract):
    finding_ref: Text
    case_ids: list[Text] = Field(min_length=1, max_length=100)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    description: Text
    evidence_ref: Text


class RetestResult(Contract):
    finding_id: Ref
    expected_finding_sha256: SHA
    outcome: Literal["RESOLVED", "PRESENT", "NOT_TESTED", "INCONCLUSIVE"]
    evidence_ref: Text


class AssessmentReport(Contract):
    schema_version: Literal["cryptoscan.independent-test/1"]
    estate_scope: Text
    engagement_id: Ref
    engagement_revision: int = Field(ge=1)
    sequence: int = Field(ge=1)
    scope_sha256: SHA
    artifact_id: Ref
    artifact_digest: Text
    deployment_manifest_sha256: SHA
    environment_ref: Text
    started_at: datetime
    ended_at: datetime
    report_blob_id: Ref
    report_sha256: SHA
    cases: list[CaseResult] = Field(min_length=13, max_length=100)
    findings: list[SecurityFinding] = Field(max_length=100)
    retests: list[RetestResult] = Field(max_length=200)


class SignedReport(Revision):
    payload: AssessmentReport
    signature_base64: str = Field(min_length=80, max_length=100)


class FindingPlan(Revision):
    owner_user_id: Ref
    replacement_artifact_id: Ref
    deployment_manifest_blob_id: Ref
    change_ref: Text
    verification_criteria: Text


class FindingCompletion(Revision):
    completed_at: datetime
    evidence_blob_id: Ref


class OperatingAssignment(Revision):
    duty: Duty
    owner_user_id: Ref
    backup_user_id: Ref
    procedure_blob_id: Ref
    escalation_ref: Text
    service_window: Text
    review_due_at: datetime
    exercise_max_age_seconds: int = Field(ge=60, le=31536000)


class OperatingExercise(Revision):
    assignment_revision: int = Field(ge=1)
    started_at: datetime
    ended_at: datetime
    evidence_blob_id: Ref
    outcome: Literal["PASSED", "FAILED", "INCONCLUSIVE"]
    measured_recovery_seconds: float | None = Field(None, ge=0)
    checks: list[Text] = Field(min_length=1, max_length=30)
    limitations: list[Text] = Field(min_length=1, max_length=30)


class Pilot(Revision):
    evidence_max_age_seconds: int = Field(3600, ge=60, le=604800)
    workflow: Literal["PAYMENTS_RELEASE_REMEDIATION_V1"]
    title: Text
    business_value: Text
    customer_owner_user_id: Ref
    technical_owner_user_id: Ref
    system_id: Ref
    register_id: Ref
    source_scan_id: Ref
    artifact_id: Ref
    sbom_binding_id: Ref
    deployment_id: Ref
    source_build_binding_blob_id: Ref
    tls_run_id: Ref
    tls_endpoint: Text
    tls_permission_ref: Text
    ssh_receipt_id: Ref
    ssh_permission_ref: Text
    hardware_id: Ref
    vendor_id: Ref
    supplier_evidence_id: Ref
    remediation_change_id: Ref
    engagement_id: Ref
    success_criteria: list[Text] = Field(min_length=1, max_length=20)
    exclusions: list[Text] = Field(min_length=1, max_length=30)
    expires_at: datetime
