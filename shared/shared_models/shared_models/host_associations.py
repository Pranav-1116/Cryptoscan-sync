"""Host-to-existing-estate associations: declarations, never runtime dependencies."""

from datetime import datetime
from typing import Literal
from pydantic import Field, field_validator
from shared_models.host_collection import Strict, Token, Digest, HostManifest

SCHEMA = "cryptoscan.host-association/v1"
GRAPH_SCHEMA = "cryptoscan.host-estate-graph/v1"
TargetType = Literal["sbom_binding", "phase_receipt", "hardware", "vendor", "deployment"]
DOMAINS = {
    "sbom_binding": "SBOM",
    "phase_receipt": "NBOM",
    "hardware": "HBOM",
    "vendor": "VBOM",
    "deployment": "TechBOM",
}


class AssociationProposal(Strict):
    input_id: Token
    fact_ordinal: int = Field(ge=0, le=999)
    target_type: TargetType
    target_id: str = Field(min_length=1, max_length=36)
    package_identity: str | None = Field(default=None, min_length=1, max_length=500)
    expected_target_sha256: Digest
    expires_at: datetime
    evidence_ref: Token
    reason: str = Field(min_length=20, max_length=500, pattern=r"^[^\x00-\x1f\x7f]+$")

    @field_validator("expires_at", mode="before")
    @classmethod
    def aware(cls, value):
        if not isinstance(value, (str, datetime)) or (isinstance(value, str) and len(value) > 64):
            raise ValueError("Offset-aware expiry required")
        return HostManifest.aware(value)


class AssociationDecision(Strict):
    expected_revision: int = Field(ge=1, le=3)
    evidence_ref: Token
    reason: str = Field(min_length=20, max_length=500, pattern=r"^[^\x00-\x1f\x7f]+$")
