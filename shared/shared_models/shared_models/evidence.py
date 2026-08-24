"""Evidence record models - tamper-proof finding storage."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional, Any

from pydantic import BaseModel, Field

from shared_models.finding import RawFinding


class ChainInfo(BaseModel):
    """Blockchain-style chain linking information."""
    position: int = Field(..., ge=0, description="Position in chain (0-indexed)")
    chain_hash: str = Field(..., description="SHA-256 chain hash for this position")
    previous_hash: Optional[str] = Field(
        None, description="Previous chain hash (None for position 0)"
    )


class IntegrityInfo(BaseModel):
    """Integrity proof metadata."""
    hash_algorithm: str = Field("SHA-256", description="Hash algorithm used")
    canonical_form: str = Field("sorted-json-utf8", description="Serialization method")
    hash_includes: list[str] = Field(
        default=["finding"],
        description="Fields included in hash computation"
    )
    hash_excludes: list[str] = Field(
        default=["evidence_id", "created_at"],
        description="Fields excluded from hash computation"
    )


class ProvenanceInfo(BaseModel):
    """Scanner provenance information."""
    scanner_id: str = Field(..., description="Scanner that produced the finding")
    scanner_version: str = Field(..., description="Scanner version")
    scan_session_id: str = Field(..., description="UUID of the scan session")
    operator: str = Field(..., description="Who/what triggered the scan")


class EvidenceRecord(BaseModel):
    """
    Tamper-proof evidence record wrapping a RawFinding.
    
    The content_hash enables detection of tampering.
    The chain_hash enables detection of deletion/reordering.
    """
    evidence_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique evidence identifier"
    )
    content_hash: str = Field(
        ...,
        description="SHA-256 hash of canonical finding JSON",
        pattern=r"^[a-f0-9]{64}$"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this evidence record was created"
    )
    finding: RawFinding = Field(..., description="The original raw finding")
    integrity: IntegrityInfo = Field(
        default_factory=IntegrityInfo,
        description="Integrity proof metadata"
    )
    provenance: ProvenanceInfo = Field(..., description="Scanner provenance")
    chain: Optional[ChainInfo] = Field(None, description="Chain hash info (set after sequencing)")

    model_config = {
        "json_encoders": {datetime: lambda v: v.isoformat()},
    }


class ManifestSummary(BaseModel):
    """Summary section of a scan manifest."""
    total_findings: int = Field(..., ge=0)
    first_chain_hash: Optional[str] = Field(None, description="chain_hash[0]")
    last_chain_hash: Optional[str] = Field(None, description="chain_hash[N]")
    manifest_hash: Optional[str] = Field(None, description="SHA-256 of all evidence IDs")
    self_hash: Optional[str] = Field(None, description="SHA-256 of entire manifest")


class ManifestEvidenceRef(BaseModel):
    """Lightweight reference to an evidence record in the manifest."""
    evidence_id: str
    content_hash: str
    chain_hash: str
    chain_position: int


class ScanManifest(BaseModel):
    """
    Manifest for an entire scan session.
    
    Provides overall integrity proof for the complete set of findings.
    """
    manifest_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_session_id: str = Field(..., description="UUID of the scan session")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    summary: ManifestSummary = Field(..., description="Aggregated summary")
    evidence_records: list[ManifestEvidenceRef] = Field(
        default_factory=list,
        description="All evidence records in chain order"
    )
    integrity_proof: dict[str, Any] = Field(
        default_factory=lambda: {
            "algorithm": "SHA-256-chain",
            "verification_instructions": (
                "1. Recompute content_hash for each finding. "
                "2. Recompute chain_hash[N] = SHA-256(content_hash[N] + chain_hash[N-1]). "
                "3. Verify manifest_hash = SHA-256(sorted evidence_ids). "
                "4. Compare all computed values to stored values. "
                "5. Any mismatch indicates tampering."
            )
        }
    )

    model_config = {
        "json_encoders": {datetime: lambda v: v.isoformat()},
    }