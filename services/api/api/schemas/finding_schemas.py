from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class FindingResponse(BaseModel):
    evidence_id: str
    scan_id: str
    algorithm: str
    key_size: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    purpose: Optional[str] = None
    confidence: str
    is_hardcoded_key: bool
    file_path: str
    line_number: int
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    compliance_status: Optional[str] = None
    content_hash: str
    chain_hash: str
    normalized_crypto: Optional[dict] = None
    policy_evaluation: Optional[dict] = None
    finding_data: Optional[dict] = None
    redacted_projection: bool = False
    # Evidence-chain timestamps (BaseModel.created_at / updated_at). Exposed so
    # the findings console can show first-seen / last-seen. Optional: rows from
    # old stores or test fixtures may not carry them, so the mapper never fails.
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # Soft-delete tombstone (migration 0075): present only on retracted
    # findings. Consumption surfaces exclude tombstones by default; the raw
    # projection (GET /findings/{id}) shows them so an auditor can inspect
    # what was retracted, when, by whom, and why.
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[str] = None
    delete_reason: Optional[str] = None


class FindingListResponse(BaseModel):
    findings: list[FindingResponse]
    total_count: int
    page: int
    page_size: int


class ProvenanceCollector(BaseModel):
    scanner_id: str
    scanner_version: str
    operator: str
    scan_status: str


class ProvenanceAsset(BaseModel):
    file_path: str
    line_number: int
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    target_type: str
    target_location: str
    target_commit: Optional[str] = None


class ProvenanceObserved(BaseModel):
    scan_start: datetime
    scan_end: Optional[datetime] = None
    recorded_at: Optional[datetime] = None


class ProvenanceSourceAndMethod(BaseModel):
    collection_method: str
    target_type: str
    target_location: str
    collection_authorization: dict


class ProvenanceEvidenceReference(BaseModel):
    content_hash: str
    storage_key: str
    storage_backend: str = "content_addressed_store"
    chain_position: int
    chain_hash: str
    previous_hash: Optional[str] = None
    manifest_hash: Optional[str] = None


class ProvenanceDetection(BaseModel):
    detection_rule_version: str
    scanner_ids: list[str] = []


class ProvenanceIntegrity(BaseModel):
    # The claim is capped at hash integrity. This is not caution — it is
    # the contract: a verified hash proves the record is unmodified since
    # it was recorded, nothing about whether the collector observed truth.
    claim: str = "HASH_INTEGRITY_ONLY"
    hash_algorithm: str = "SHA-256"
    chain_link_verified: Optional[bool] = None
    verification_result: str
    statement: str = (
        "Hash integrity detects later modification of the record. It does "
        "not independently prove that the collector observed the truth: the "
        "evidence source, collection authorization and detection method are "
        "preserved above and remain the basis on which truth is assessed."
    )


class ProvenanceTruth(BaseModel):
    status: str = "NOT_INDEPENDENTLY_VERIFIED"
    independently_verified: bool = False
    note: str = (
        "Independent truth review (the assurance layer's reviewed-verdict "
        "process) is separate from integrity verification and is never "
        "implied by a verified hash."
    )


class FindingProvenanceBundle(BaseModel):
    evidence_id: str
    collector: ProvenanceCollector
    asset: ProvenanceAsset
    observed: ProvenanceObserved
    source_and_method: ProvenanceSourceAndMethod
    evidence_reference: ProvenanceEvidenceReference
    detection: ProvenanceDetection
    finding: dict
    integrity: ProvenanceIntegrity
    truth: ProvenanceTruth
