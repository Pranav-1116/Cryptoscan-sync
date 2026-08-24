"""
DriftSummary model — aggregated counts from a drift detection run.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, computed_field


class DriftSummary(BaseModel):
    """
    Aggregated summary of drift events from one scan comparison.

    Immutable after creation — computed fields are derived from raw counts.
    """

    baseline_id: UUID
    current_scan_id: UUID
    system_identifier: str
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # Severity counts
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)

    # Type counts
    new_crypto_count: int = Field(default=0, ge=0)
    removed_crypto_count: int = Field(default=0, ge=0)
    changed_crypto_count: int = Field(default=0, ge=0)

    # Baseline metadata
    baseline_approved_by: str | None = None
    baseline_approved_at: datetime | None = None
    baseline_scan_date: datetime | None = None

    model_config = {"frozen": True}

    @computed_field  # type: ignore[misc]
    @property
    def total_drift_events(self) -> int:
        return self.critical + self.high + self.medium + self.info

    @computed_field  # type: ignore[misc]
    @property
    def has_critical(self) -> bool:
        return self.critical > 0

    @computed_field  # type: ignore[misc]
    @property
    def has_actionable_drift(self) -> bool:
        """True if any drift requires immediate action (CRITICAL or HIGH)."""
        return self.critical > 0 or self.high > 0

    @computed_field  # type: ignore[misc]
    @property
    def highest_severity(self) -> str:
        """Return highest severity level present."""
        if self.critical > 0:
            return "CRITICAL"
        if self.high > 0:
            return "HIGH"
        if self.medium > 0:
            return "MEDIUM"
        if self.info > 0:
            return "INFO"
        return "NONE"

    def to_log_dict(self) -> dict[str, Any]:
        """Structured representation for logging."""
        return {
            "baseline_id": str(self.baseline_id),
            "current_scan_id": str(self.current_scan_id),
            "system_identifier": self.system_identifier,
            "total_events": self.total_drift_events,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "info": self.info,
            "new_crypto": self.new_crypto_count,
            "removed_crypto": self.removed_crypto_count,
            "highest_severity": self.highest_severity,
        }

    @classmethod
    def empty(
        cls,
        baseline_id: UUID,
        current_scan_id: UUID,
        system_identifier: str,
    ) -> "DriftSummary":
        """Create a no-drift summary (no events detected)."""
        return cls(
            baseline_id=baseline_id,
            current_scan_id=current_scan_id,
            system_identifier=system_identifier,
        )