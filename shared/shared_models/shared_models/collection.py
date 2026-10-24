"""Universal boundary: observations are evidence, never inferred BOM/use claims."""

from datetime import datetime
from typing import Literal, Protocol
from pydantic import Field, model_validator, field_validator
from shared_models.host_collection import Strict, Token, Digest, HostManifest, HostSnapshot, HostFact, Kind
from shared_models.host_runtime import RuntimeFact

Method = Literal[
    "offline_host", "windows", "container", "source", "cloud", "network", "hsm", "hardware", "vendor", "ot"
]


def offset_time(value):
    if not isinstance(value, (str, datetime)) or isinstance(value, str) and len(value) > 64:
        raise ValueError("Offset-aware timestamp required")
    return HostManifest.aware(value)


class TargetSpec(Strict):
    target_key: Token
    system_id: Token
    owner: Token  # customer contact label; never the authorization principal
    environment: Token
    collection_method: Method
    address: str = Field(min_length=1, max_length=1024, pattern=r"^[^\x00-\x1f\x7f]+$")
    credential_ref: str | None = Field(default=None, max_length=200, pattern=r"^vault://[A-Za-z0-9_./-]+$")
    allowed_operations: list[Literal["READ_APPROVED_METADATA"]] = Field(min_length=1, max_length=1)
    read_only: Literal[True] = True
    not_before: datetime
    manifest: HostManifest | None = None
    exclusions: list[Token] = Field(default_factory=list, max_length=100)

    @field_validator("not_before", mode="before")
    @classmethod
    def aware(cls, value):
        return offset_time(value)

    @model_validator(mode="after")
    def scope(self):
        if self.collection_method == "offline_host":
            if self.manifest is None or self.credential_ref is not None:
                raise ValueError("Offline host requires an explicit manifest, never credentials")
            if self.manifest.environment != self.environment or self.not_before >= self.manifest.expires_at:
                raise ValueError("Manifest environment/time window mismatch")
            if set(self.exclusions) & {i.input_id for i in self.manifest.inputs}:
                raise ValueError("Excluded inputs must be removed from the approved allowlist")
        if len(set(self.exclusions)) != len(self.exclusions):
            raise ValueError("Duplicate exclusion")
        return self


class TargetUpdate(Strict):
    expected_revision: int = Field(ge=1, le=100)
    target: TargetSpec


class RevisionRequest(Strict):
    expected_revision: int = Field(ge=1, le=100)
    evidence_ref: Token
    reason: str = Field(min_length=20, max_length=500, pattern=r"^[^\x00-\x1f\x7f]+$")


from shared_models.collector_identity import CollectorIdentityPolicy


class AuthorizeRequest(RevisionRequest):
    collector_identity: CollectorIdentityPolicy | None = None


class JobRequest(Strict):
    target_id: str = Field(min_length=1, max_length=36)
    expected_target_revision: int = Field(ge=1, le=100)


class JobDecision(Strict):
    expected_revision: int = Field(ge=1, le=10)


class ObservationSource(Strict):
    kind: Kind
    path: str = Field(min_length=1, max_length=1024)
    input_content_sha256: Digest
    host_id: Token


class Observation(Strict):
    observation_id: str
    identity_slot: str
    identity_basis: Literal["SCOPED_METADATA_SLOT_NOT_ATTESTED_ASSET"] = "SCOPED_METADATA_SLOT_NOT_ATTESTED_ASSET"
    input_id: Token
    fact_ordinal: int = Field(ge=0, le=999)
    fact: HostFact | RuntimeFact
    source: ObservationSource
    collected_at: str = Field(min_length=1, max_length=40)
    evidence_id: str
    content_hash: Digest
    fact_sha256: Digest
    provenance: Literal["IMPORTED"] = "IMPORTED"
    contributes_to: list[Literal["SBOM", "CBOM", "NBOM", "HBOM", "TechBOM"]] = Field(min_length=1, max_length=3)


class UniversalCollector(Protocol):
    """Runtime adapters collect typed facts only; platform normalization is separate.

    No generic command executor, automatic target discovery or BOM writer.
    """

    def validate_scope(self, target: TargetSpec) -> None: ...
    def collect(self, target: TargetSpec) -> HostSnapshot: ...
    def health(self) -> dict: ...


class EvidenceManifest(Strict):
    approval_id: str
    scan_id: str
    snapshot_sha256: Digest
    scan_manifest_sha256: Digest


class CollectionError(Strict):
    input_id: Token
    status: Literal["DENIED", "UNSUPPORTED", "INVALID", "BUDGET_EXCEEDED", "UNAVAILABLE"]
    reason: Token
    asset_absence_proven: Literal[False] = False


class Coverage(Strict):
    parsed_inputs: int = Field(ge=0, le=100)
    approved_inputs: int = Field(ge=1, le=100)
    basis: Literal["APPROVED_INPUT_RECEIPTS_ONLY"] = "APPROVED_INPUT_RECEIPTS_ONLY"
    whole_host_percent: None = None
    whole_host_coverage_verified: Literal[False] = False


class CollectorIdentity(Strict):
    name: Literal["offline-linux/v1"]
    version: Token


class CollectionResult(Strict):
    schema_version: Literal["cryptoscan.collection-evidence/v1"]
    job_id: str
    target_id: str
    target_revision: int = Field(ge=1, le=100)
    target_sha256: Digest
    system_id: Token
    environment: Token
    collector: CollectorIdentity
    status: Literal["COMPLETED", "PARTIAL", "FAILED"]
    provenance: Literal["IMPORTED"] = "IMPORTED"
    started_at: str
    finished_at: str
    source_revision: None = None
    evidence_manifest: EvidenceManifest
    observations: list[Observation] = Field(max_length=1000)
    errors: list[CollectionError] = Field(max_length=100)
    coverage: Coverage
    host_identity_attested: Literal[False] = False
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    pqc_use: Literal["UNKNOWN"] = "UNKNOWN"

    @model_validator(mode="after")
    def consistent(self):
        parsed, total = self.coverage.parsed_inputs, self.coverage.approved_inputs
        expected = "COMPLETED" if parsed == total else "PARTIAL" if parsed else "FAILED"
        if parsed > total or len(self.errors) != total - parsed or self.status != expected:
            raise ValueError("Coverage/collection outcome inconsistent")
        if offset_time(self.finished_at) < offset_time(self.started_at):
            raise ValueError("Evidence timestamp order inconsistent")
        return self
