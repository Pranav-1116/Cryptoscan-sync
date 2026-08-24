"""
Scan Schemas - Pydantic models for scan API requests/responses.

Request/response validation for scan endpoints.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    """Scan status enumeration."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanCreateRequest(BaseModel):
    """Request to create new scan."""
    
    scan_type: str = Field(
        ...,
        regex="^(GIT_REPOSITORY|LOCAL_DIR|CONTAINER_IMAGE)$",
        description="Type of scan target"
    )
    
    target_url: str = Field(
        ...,
        min_length=1,
        description="Git repo URL, local path, or container image URI"
    )
    
    branch: Optional[str] = Field(
        default="main",
        description="Git branch to scan (for Git repos)"
    )
    
    commit: Optional[str] = Field(
        default=None,
        description="Specific commit to scan"
    )
    
    labels: Optional[Dict[str, str]] = Field(
        default=None,
        description="Custom labels for scan"
    )


class ScanResponse(BaseModel):
    """Scan response object."""
    
    scan_id: str = Field(
        ...,
        description="Unique scan identifier"
    )
    
    status: ScanStatus = Field(
        ...,
        description="Current scan status"
    )
    
    target_url: str = Field(
        ...,
        description="Scan target"
    )
    
    scan_start: datetime = Field(
        ...,
        description="When scan started"
    )
    
    scan_end: Optional[datetime] = Field(
        None,
        description="When scan completed"
    )
    
    findings_count: int = Field(
        default=0,
        description="Total findings in this scan"
    )
    
    findings_compliant: int = Field(
        default=0,
        description="Compliant findings"
    )
    
    findings_non_compliant: int = Field(
        default=0,
        description="Non-compliant findings"
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class ScanListResponse(BaseModel):
    """List of scans with pagination."""
    
    scans: List[ScanResponse] = Field(
        ...,
        description="List of scans"
    )
    
    total_count: int = Field(
        ...,
        description="Total number of scans"
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