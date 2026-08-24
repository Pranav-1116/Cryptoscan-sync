"""
Drift Schemas - Pydantic models for drift detection API.

Request/response validation for drift endpoints.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class DriftType(str, Enum):
    """Types of detected drift."""
    NEW_CRYPTO = "NEW_CRYPTO"
    REMOVED_CRYPTO = "REMOVED_CRYPTO"
    CHANGED_CRYPTO = "CHANGED_CRYPTO"
    DEGRADED_CRYPTO = "DEGRADED_CRYPTO"


class DriftSeverity(str, Enum):
    """Drift severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DriftResolutionStatus(str, Enum):
    """Drift resolution status."""
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class DriftEventResponse(BaseModel):
    """Single drift event."""
    
    drift_id: str = Field(
        ...,
        description="Unique drift event identifier"
    )
    
    baseline_id: str = Field(
        ...,
        description="Associated baseline scan ID"
    )
    
    current_scan_id: str = Field(
        ...,
        description="Current scan ID that detected drift"
    )
    
    drift_type: DriftType = Field(
        ...,
        description="Type of drift detected"
    )
    
    severity: DriftSeverity = Field(
        ...,
        description="Drift severity"
    )
    
    algorithm: str = Field(
        ...,
        description="Algorithm with drift"
    )
    
    location: str = Field(
        ...,
        description="Location of drift (file:line)"
    )
    
    baseline_state: Optional[Dict[str, Any]] = Field(
        None,
        description="Baseline cryptographic state"
    )
    
    current_state: Optional[Dict[str, Any]] = Field(
        None,
        description="Current cryptographic state"
    )
    
    message: str = Field(
        ...,
        description="Human-readable drift description"
    )
    
    resolution_status: DriftResolutionStatus = Field(
        default=DriftResolutionStatus.OPEN,
        description="Resolution status"
    )
    
    detected_at: datetime = Field(
        ...,
        description="When drift was detected"
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class DriftListResponse(BaseModel):
    """List of drift events."""
    
    drift_events: List[DriftEventResponse] = Field(
        ...,
        description="List of drift events"
    )
    
    total_count: int = Field(
        ...,
        description="Total number of drift events"
    )
    
    page: int = Field(
        ...,
        ge=1,
        description="Current page"
    )
    
    page_size: int = Field(
        ...,
        ge=1,
        description="Page size"
    )
    
    critical_count: int = Field(
        default=0,
        description="Count of CRITICAL drifts"
    )


class DriftAcknowledgeRequest(BaseModel):
    """Request to acknowledge drift event."""
    
    resolution_status: DriftResolutionStatus = Field(
        ...,
        description="New resolution status"
    )
    
    notes: Optional[str] = Field(
        None,
        description="Optional notes about resolution"
    )