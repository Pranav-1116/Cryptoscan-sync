"""
Finding Schemas - Pydantic models for finding API requests/responses.

Request/response validation for finding endpoints.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class ComplianceStatus(str, Enum):
    """Compliance status enumeration."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


class FindingResponse(BaseModel):
    """Finding response object."""
    
    evidence_id: str = Field(
        ...,
        description="Unique evidence identifier"
    )
    
    scan_id: str = Field(
        ...,
        description="Associated scan ID"
    )
    
    algorithm: str = Field(
        ...,
        description="Cryptographic algorithm"
    )
    
    key_size: Optional[int] = Field(
        None,
        description="Key size in bits"
    )
    
    mode: Optional[str] = Field(
        None,
        description="Algorithm mode (e.g., GCM)"
    )
    
    purpose: str = Field(
        ...,
        description="Crypto usage purpose"
    )
    
    file_path: str = Field(
        ...,
        description="Source file location"
    )
    
    line_number: int = Field(
        ...,
        ge=1,
        description="Line number in file"
    )
    
    method_name: str = Field(
        ...,
        description="Containing method name"
    )
    
    is_hardcoded_key: bool = Field(
        default=False,
        description="Whether key is hardcoded"
    )
    
    compliance_status: ComplianceStatus = Field(
        ...,
        description="Compliance evaluation result"
    )
    
    created_at: datetime = Field(
        ...,
        description="When finding was discovered"
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class FindingListResponse(BaseModel):
    """List of findings with pagination."""
    
    findings: List[FindingResponse] = Field(
        ...,
        description="List of findings"
    )
    
    total_count: int = Field(
        ...,
        description="Total number of findings"
    )
    
    page: int = Field(
        ...,
        ge=1,
        description="Current page number"
    )
    
    page_size: int = Field(
        ...,
        ge=1,
        description="Page size"
    )
    
    compliant_count: int = Field(
        default=0,
        description="Count of compliant findings"
    )
    
    non_compliant_count: int = Field(
        default=0,
        description="Count of non-compliant findings"
    )