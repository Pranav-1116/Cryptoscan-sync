"""
DriftEvent Pydantic model — represents a single detected drift.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class DriftType(str, Enum):
    NEW_CRYPTO = "NEW_CRYPTO"
    REMOVED_CRYPTO = "REMOVED_CRYPTO"
    CHANGED_CRYPTO = "CHANGED_CRYPTO"
    DEGRADED_CRYPTO = "DEGRADED_CRYPTO"


class DriftSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


class ResolutionStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class DriftEvent(BaseModel):
    """
    A single drift event detected by comparing baseline to current scan.

    Immutable after creation — resolution is tracked in the DB separately.
    """

    drift_id: UUID = Field(default_factory=uuid4)
    baseline_id: UUID
    current_scan_id: UUID
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    drift_type: DriftType
    severity: DriftSeverity
    resolution_status: ResolutionStatus = ResolutionStatus.OPEN

    drift_details: dict[str, Any] = Field(
        description="Algorithm, location, baseline/current state, message"
    )

    # Optional resolution fields
    resolved_by: str | None = None
    resolved_at: datetime | None = None
    resolution_notes: str | None = None

    model_config = {"frozen": True}

    @property
    def is_open(self) -> bool:
        return self.resolution_status == ResolutionStatus.OPEN

    @property
    def algorithm(self) -> str:
        return self.drift_details.get("algorithm", "UNKNOWN")

    @property
    def location(self) -> str:
        return self.drift_details.get("location", "UNKNOWN")

    @property
    def message(self) -> str:
        return self.drift_details.get("message", "")

    def to_db_dict(self) -> dict[str, Any]:
        """Convert to dict for database insertion."""
        return {
            "drift_id": self.drift_id,
            "baseline_id": self.baseline_id,
            "current_scan_id": self.current_scan_id,
            "detected_at": self.detected_at,
            "drift_type": self.drift_type.value,
            "severity": self.severity.value,
            "drift_details": self.drift_details,
            "resolution_status": self.resolution_status.value,
        }

    @classmethod
    def new_crypto(
        cls,
        *,
        baseline_id: UUID,
        current_scan_id: UUID,
        algorithm: str,
        location: str,
        severity: DriftSeverity,
        baseline_state: str = "NOT_PRESENT",
        current_state: dict[str, Any] | None = None,
        compliance_status: str | None = None,
    ) -> "DriftEvent":
        """Factory: create a NEW_CRYPTO drift event."""
        return cls(
            baseline_id=baseline_id,
            current_scan_id=current_scan_id,
            drift_type=DriftType.NEW_CRYPTO,
            severity=severity,
            drift_details={
                "algorithm": algorithm,
                "location": location,
                "baseline_state": baseline_state,
                "current_state": current_state or {},
                "compliance_status": compliance_status,
                "message": f"New cryptographic call detected: {algorithm} at {location}",
            },
        )

    @classmethod
    def removed_crypto(
        cls,
        *,
        baseline_id: UUID,
        current_scan_id: UUID,
        algorithm: str,
        location: str,
        baseline_state: dict[str, Any] | None = None,
        severity: DriftSeverity = DriftSeverity.INFO,
    ) -> "DriftEvent":
        """Factory: create a REMOVED_CRYPTO drift event."""
        if not isinstance(severity, DriftSeverity):
            severity = DriftSeverity(getattr(severity, "value", severity))
        return cls(
            baseline_id=baseline_id,
            current_scan_id=current_scan_id,
            drift_type=DriftType.REMOVED_CRYPTO,
            severity=severity,
            drift_details={
                "algorithm": algorithm,
                "location": location,
                "baseline_state": baseline_state or {},
                "current_state": "NOT_PRESENT",
                "message": f"Cryptographic call removed: {algorithm} at {location}",
            },
        )