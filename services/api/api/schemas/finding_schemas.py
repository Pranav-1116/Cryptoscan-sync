from __future__ import annotations

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


class FindingListResponse(BaseModel):
    findings: list[FindingResponse]
    total_count: int
    page: int
    page_size: int
