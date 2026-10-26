"""Job-bound OCI metadata returns. Public challenges are not attestations."""

from datetime import datetime
from typing import Annotated, Literal
from pydantic import Field, StringConstraints, field_validator, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Digest, HostManifest, Token, digest
from shared_models.oci_collection import OciEvidence, OciTarget

Identifier = Annotated[
    str, StringConstraints(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
]


class OciCaptureBinding(Strict):
    schema_version: Literal["cryptoscan.oci-capture-binding/v1"] = "cryptoscan.oci-capture-binding/v1"
    job_id: Identifier
    target_id: Identifier
    target_revision: int = Field(ge=2, le=100)
    target_record_sha256: Digest
    target_sha256: Digest
    nonce: Digest
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)

    @model_validator(mode="after")
    def window(self):
        if not 0 < (self.expires_at - self.issued_at).total_seconds() <= 86400:
            raise ValueError("Positive bounded handoff window required")
        return self


class OciJobReturn(Strict):
    schema_version: Literal["cryptoscan.oci-job-return/v1"] = "cryptoscan.oci-job-return/v1"
    binding: OciCaptureBinding
    evidence: OciEvidence
    producer_authenticity_verified: Literal[False] = False
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"

    @model_validator(mode="after")
    def scoped(self):
        b, e = self.binding, self.evidence
        if b.target_sha256 != e.target_sha256 or b.target_sha256 != digest(e.target):
            raise ValueError("Job return target commitment mismatch")
        if not b.issued_at <= e.started_at <= e.finished_at < b.expires_at <= e.target.expires_at:
            raise ValueError("Evidence must be captured in the handoff window")
        return self


class OciTargetUpdate(Strict):
    expected_revision: int = Field(ge=1, le=99)
    target: OciTarget


class OciDecision(Strict):
    expected_revision: int = Field(ge=1, le=99)
    evidence_ref: Token
    reason: str = Field(min_length=20, max_length=500, pattern=r"^[^\x00-\x1f\x7f]+$")


class OciJobRequest(Strict):
    target_id: Identifier
    expected_target_revision: int = Field(ge=2, le=100)


class OciJobAction(Strict):
    expected_revision: int = Field(ge=1, le=3)


class OciIntakeRequest(OciJobAction):
    capture: OciJobReturn
    expected_evidence_sha256: Digest
