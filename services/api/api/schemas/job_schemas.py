"""
Pydantic schemas for scan job request/response models.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class TriggerScanRequest(BaseModel):
    """Request body for POST /api/scans/trigger."""

    repo_url: HttpUrl = Field(
        description="Git repository URL to scan",
        examples=["https://github.com/org/payment-api"],
    )
    branch: Optional[str] = Field(
        default="main",
        description="Branch to scan (defaults to 'main')",
        max_length=200,
    )
    commit: Optional[str] = Field(
        default=None,
        description="Specific commit hash (defaults to HEAD of branch)",
        max_length=40,
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "repo_url": "https://github.com/org/payment-api",
                "branch": "main",
                "commit": None,
            }
        }
    }


class TriggerScanResponse(BaseModel):
    """Response for POST /api/scans/trigger."""

    job_id: str
    status: str
    created_at: str
    message: str


class JobProgressDetail(BaseModel):
    """Progress detail for a running job."""

    current_stage: str
    stages_complete: int
    total_stages: int = 8
    findings_count: Optional[int] = None


class JobStatusResponse(BaseModel):
    """Response for GET /api/jobs/{job_id}."""

    job_id: str
    status: str
    job_type: str
    target_repo: str
    target_branch: Optional[str]
    target_commit: Optional[str]
    triggered_by: str
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    scan_id: Optional[str]
    error_message: Optional[str]
    progress: Optional[JobProgressDetail]


class JobLogsResponse(BaseModel):
    """Response for GET /api/jobs/{job_id}/logs."""

    job_id: str
    logs: List[str]


class JobListResponse(BaseModel):
    """Paginated list of jobs."""

    items: List[JobStatusResponse]
    total: int
    page: int
    page_size: int