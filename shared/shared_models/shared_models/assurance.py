"""Bounded assurance contracts; declarations never become observations by name."""
from datetime import datetime
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator, field_validator

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]
ID = Annotated[str, StringConstraints(pattern=r"^[0-9a-f-]{36}$")]
Ref = Annotated[str, StringConstraints(min_length=1, max_length=36)]
SHA = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
SourceClass = Literal["source", "wrappers_config", "native_provider", "legacy_mainframe", "mobile_obfuscated", "proprietary_export", "runtime_log", "network", "hardware", "supplier"]
SOURCE_CLASSES = ["source", "wrappers_config", "native_provider", "legacy_mainframe", "mobile_obfuscated", "proprietary_export", "runtime_log", "network", "hardware", "supplier"]
Purpose = Literal["CHECKSUM", "SECURITY_HASH", "CERT_SIGNATURE", "KEY_EXCHANGE", "SYMMETRIC", "UNKNOWN"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    @model_validator(mode="after")
    def explicit_timezones(self):
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, datetime) and value.tzinfo is None:
                raise ValueError(f"{name} requires an explicit timezone")
        return self


class Revision(Contract):
    expected_revision: int = Field(ge=0)


class Target(Contract):
    target_id: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._-]{1,80}$")]
    system_id: Ref | None = None
    owner_ref: Text
    kind: Literal["SOURCE", "DEPLOYMENT", "ENDPOINT", "HARDWARE", "SUPPLIER"]
    source_class: SourceClass
    target_ref: Text
    method: Literal["LOCAL_SOURCE", "SSH_HOST_KEYS", "SSH_HOST_KEYS_KEX", "EXTERNAL_EXPORT"]
    permission_ref: Text
    freshness_seconds: int = Field(ge=60, le=31536000)


class Register(Revision):
    scope_description: Text
    register_owner: Text
    completeness: Literal["UNKNOWN", "PARTIAL", "OWNER_ATTESTED_COMPLETE"]
    completeness_evidence_ref: Text
    targets: list[Target] = Field(max_length=1000)

    @model_validator(mode="after")
    def unique_targets(self):
        if len({t.target_id for t in self.targets}) != len(self.targets):
            raise ValueError("Duplicate target_id")
        if len({(t.kind, t.target_ref, t.method) for t in self.targets}) != len(self.targets):
            raise ValueError("Duplicate collection target would inflate the denominator")
        for target in self.targets:
            if target.method == "LOCAL_SOURCE" and target.kind != "SOURCE":
                raise ValueError("Local source cannot establish deployment/endpoint/hardware coverage")
            if target.method.startswith("SSH_") and target.kind != "ENDPOINT":
                raise ValueError("SSH endpoint facts cannot establish source/deployment coverage")
        return self


class CoverageObservation(Revision):
    outcome: Literal["RECEIPT", "BLOCKED", "UNSUPPORTED"]
    job_id: ID | None = None
    evidence_ref: Text
    reason: Text


class SampleUnit(Contract):
    file: Text
    algorithm: Text
    source_class: SourceClass
    split: Literal["FIRST_PASS", "HOLDOUT"]
    fixture_blob_id: ID


class Sample(Contract):
    scope_description: Text
    selection_method: Text
    domain_owner: Text
    domain_owner_user_id: Ref
    positive_definition: Literal["FILE_ALGORITHM_OBSERVATION"] = "FILE_ALGORITHM_OBSERVATION"
    approval_ref: Text
    blind_spots: list[Text] = Field(min_length=1, max_length=30)
    scan_ids: list[ID] = Field(min_length=1, max_length=20)
    units: list[SampleUnit] = Field(min_length=2, max_length=1000)

    @model_validator(mode="after")
    def partitions(self):
        if {u.split for u in self.units} != {"FIRST_PASS", "HOLDOUT"}:
            raise ValueError("A first-pass and a held-out partition are required")
        if len({(u.file, u.algorithm.upper()) for u in self.units}) != len(self.units):
            raise ValueError("Unit is file × algorithm family; duplicates are not independent samples")
        return self


class Approval(Revision):
    evidence_ref: Text
    reason: Text


class UnitReview(Contract):
    unit_id: ID
    truth: Literal["PRESENT", "ABSENT", "UNREVIEWED"]
    explanation: Text


class Review(Contract):
    phase: Literal["FIRST_PASS", "HOLDOUT"]
    domain_owner: Text
    evidence_ref: Text
    units: list[UnitReview] = Field(min_length=1, max_length=1000)


class Repeat(Contract):
    scan_ids: list[ID] = Field(min_length=1, max_length=20)
    evidence_ref: Text


class Context(Revision):
    purpose: Purpose
    security_use: bool | None = None
    environment: Literal["PRODUCTION", "TEST", "UNKNOWN"] = "UNKNOWN"
    execution: Literal["PACKAGED", "INVOKED", "UNKNOWN"] = "UNKNOWN"
    evidence_ref: Text
    rationale: Text
    advisory_id: Text | None = None
    pypi_affected_versions: Text | None = None
    sbom_binding_id: ID | None = None
    package_identity: Text | None = None
    certification_label: Text | None = None
    module_name: Text | None = None
    module_version: Text | None = None
    module_mode: Text | None = None
    certified_module: Text | None = None
    certified_version: Text | None = None
    certified_modes: list[Text] = Field(default_factory=list, max_length=20)


class Relationship(Revision):
    relation: Literal["PACKAGE_CRYPTO", "ENDPOINT_SERVICE", "SERVICE_DEPLOYMENT", "HARDWARE_FIRMWARE", "SUPPLIER_PRODUCT"]
    subject_type: Literal["sbom_binding", "phase_receipt", "deployment", "hardware", "vendor", "system"]
    subject_id: Ref
    object_type: Literal["evidence", "system", "deployment", "hardware", "vendor"]
    object_id: Ref
    package_identity: Text | None = None
    observed_at: datetime
    expires_at: datetime
    evidence_ids: list[Ref] = Field(min_length=1, max_length=20)
    evidence_ref: Text
    basis: Literal["OPERATOR_REVIEWED", "SUPPLIER_DECLARED"]
    rationale: Text


class Signer(Revision):
    label: Text
    public_key_base64: Annotated[str, StringConstraints(min_length=44, max_length=44)]
    expires_at: datetime
    revoked: bool = False
    evidence_ref: Text

    @field_validator("public_key_base64")
    @classmethod
    def ed25519_key(cls, value):
        import base64
        try:
            if len(base64.b64decode(value, validate=True)) != 32:
                raise ValueError()
        except ValueError:
            raise ValueError("Expected a base64 32-byte Ed25519 PUBLIC key") from None
        return value


class SupplierManifest(Contract):
    estate_scope: Text
    customer_id: Text
    build_digest: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    payload_sha256: SHA
    vendor: Text
    product: Text
    version: Text
    profile: Text
    format: Literal["vendor-export/v1-json"]
    collected_at: datetime
    expires_at: datetime


class SupplierUpload(Contract):
    artifact_id: ID
    signer_id: ID
    manifest: SupplierManifest
    signature_base64: Annotated[str, StringConstraints(max_length=128)]
    payload_base64: Annotated[str, StringConstraints(min_length=1, max_length=1400000)]


class Adapter(Revision):
    vendor: Text
    product: Text
    version: Text
    profile: Text
    format: Literal["vendor-export/v1-json"]
    required_permissions: list[Text] = Field(min_length=1, max_length=30)
    collected_fields: list[Literal["packages", "endpoints", "crypto", "deployments", "hardware", "suppliers"]] = Field(min_length=1, max_length=6)
    pagination: Literal["COMPLETE_OR_EXPLICIT_PARTIAL"]
    requests_per_second: int = Field(ge=1, le=100)
    retries: int = Field(ge=0, le=5)
    retry_backoff_seconds: int = Field(ge=1, le=60)
    exclusions: list[Text] = Field(min_length=1, max_length=30)
    evidence_ref: Text


class QualificationCase(Contract):
    supplier_evidence_id: ID
    expected_outcome: Literal["COMPLETE", "PARTIAL", "WRONG_CUSTOMER", "WRONG_BUILD", "STALE", "UNTRUSTED_SIGNER", "MALFORMED"]
    expected_output_sha256: SHA | None = None


class AdapterQualification(Contract):
    cases: list[QualificationCase] = Field(min_length=7, max_length=20)
    evidence_ref: Text


REDIS_SCENARIOS = ["certificate_rotation", "credential_rotation", "partition_split_brain", "replica_lag", "disk_full", "memory_pressure", "process_kill", "power_loss", "backup_restore", "failback", "representative_recovery_load"]
REDIS_ROLES = ["realtime", "current_run", "queue", "rate_limit", "health", "platform_state", "sso_state", "telecom"]


class RedisObjectives(Revision):
    deployment_id: Text
    topology_sha256: SHA
    roles: list[Literal["realtime", "current_run", "queue", "rate_limit", "health", "platform_state", "sso_state", "telecom"]] = Field(min_length=1, max_length=8)
    max_recovery_seconds: float = Field(ge=0, le=86400)
    max_measurement_age_seconds: int = Field(default=2592000, ge=60, le=31536000)
    max_acknowledged_event_loss: int = Field(ge=0, le=100000)
    minimum_recovery_operations_per_second: float = Field(gt=0, le=1000000)
    minimum_measurement_seconds: float = Field(ge=1, le=86400)
    evidence_ref: Text


class Acknowledgement(Contract):
    event_id: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._:-]{1,100}$")]
    acknowledged_at: datetime


class RedisMeasurement(Contract):
    deployment_id: Text
    topology_sha256: SHA
    scenario: Literal["certificate_rotation", "credential_rotation", "partition_split_brain", "replica_lag", "disk_full", "memory_pressure", "process_kill", "power_loss", "backup_restore", "failback", "representative_recovery_load"]
    role: Literal["realtime", "current_run", "queue", "rate_limit", "health", "platform_state", "sso_state", "telecom"]
    fault_at: datetime
    recovered_at: datetime
    measured_until: datetime
    acknowledged: list[Acknowledgement] = Field(max_length=5000)
    recovered_event_ids: list[Text] = Field(max_length=5000)
    recovery_operations: int = Field(ge=1, le=100000000)
    evidence_blob_id: ID
    evidence_ref: Text
    fault_witness: Text

    @model_validator(mode="after")
    def clocks_and_journal(self):
        if not self.fault_at <= self.recovered_at < self.measured_until:
            raise ValueError("Recovery and load measurement require ordered UTC timestamps")
        ids = [a.event_id for a in self.acknowledged]
        if len(ids) != len(set(ids)) or len(self.recovered_event_ids) != len(set(self.recovered_event_ids)):
            raise ValueError("Duplicate journal IDs invalidate event-loss measurement")
        if self.role == "health" and self.acknowledged:
            raise ValueError("Health PINGs have no durable-event RPO; do not invent acknowledged durable events")
        if self.role != "health" and not any(a.acknowledged_at < self.fault_at for a in self.acknowledged):
            raise ValueError("Must measure events acknowledged BEFORE the fault, not only a new snapshot")
        if any(a.acknowledged_at > self.measured_until for a in self.acknowledged):
            raise ValueError("Acknowledgements cannot postdate the measurement")
        return self


class RegressionExecution(Contract):
    scan_id: ID
    evidence_ref: Text


class RemediationChange(Contract):
    freshness_seconds: int = Field(3600, ge=60, le=604800)
    kind: Literal["SOURCE_SITE", "TLS_CERTIFICATE"]
    owner_ref: Text
    change_ref: Text
    verification_criteria: Text
    expires_at: datetime
    task_id: Ref | None = None
    before_run_id: Ref | None = None
    endpoint: Text | None = None
    expected_fingerprint_sha256: SHA | None = None
    expected_algorithm: Annotated[str, StringConstraints(min_length=1, max_length=100)] | None = None

    @model_validator(mode="after")
    def complete_condition(self):
        if self.kind == "SOURCE_SITE":
            if not self.task_id or not self.expected_algorithm or any((self.before_run_id, self.endpoint, self.expected_fingerprint_sha256)):
                raise ValueError("Source condition requires task and expected algorithm only")
        elif not all((self.before_run_id, self.endpoint, self.expected_fingerprint_sha256)) or self.task_id or self.expected_algorithm:
            raise ValueError("TLS condition requires before run, exact endpoint and replacement SHA256 only")
        return self


class ReportChange(Revision):
    completed_at: datetime
    evidence_ref: Text


class VerifyChange(Revision):
    rescan_id: Ref
    expected_proof_revision: int = Field(0, ge=0)


class AssignedRemediationTask(Contract):
    evidence_id: Ref
    owner_ref: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
    notes: Text | None = None
