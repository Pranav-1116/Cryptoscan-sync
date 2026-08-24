from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanCreateRequest(BaseModel):
    target_url: str
    scan_type: str = "GIT_REPOSITORY"
    branch: Optional[str] = "main"


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target_location: str
    target_type: str
    target_branch: Optional[str] = None
    target_commit: Optional[str] = None
    scanner_id: str
    scanner_version: str
    operator: str
    scan_start: Optional[str] = None
    scan_end: Optional[str] = None
    duration_seconds: Optional[float] = None
    statistics: Optional[dict] = None
    manifest_hash: Optional[str] = None
    error_message: Optional[str] = None


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]
    total_count: int
    page: int
    page_size: int
