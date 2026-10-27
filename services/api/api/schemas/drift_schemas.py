from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class DriftEventResponse(BaseModel):
    drift_id: str
    current_scan_id: str
    baseline_id: Optional[str] = None
    drift_type: str
    severity: str
    detected_at: Optional[str] = None
    resolution_status: str
    drift_details: Optional[dict] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None


class DriftListResponse(BaseModel):
    events: list[DriftEventResponse]
    total_count: int
    page: int
    page_size: int
