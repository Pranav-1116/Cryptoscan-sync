"""
Pydantic schemas for webhook request/response models.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class WebhookAcknowledgement(BaseModel):
    """Response returned to GitHub after webhook receipt."""

    acknowledged: bool = Field(
        description="Whether the webhook was successfully received and validated"
    )
    queued: bool = Field(
        description="Whether a scan job was queued as a result"
    )
    message: str = Field(
        description="Human-readable status message"
    )

    model_config = {"json_schema_extra": {
        "example": {
            "acknowledged": True,
            "queued": True,
            "message": "Scan queued for https://github.com/org/repo@main",
        }
    }}