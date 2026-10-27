"""§34 Live cryptography scanner — events."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from universal_crypto.models import CryptoEventType


class CryptoEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_type: CryptoEventType
    asset_id: str = "default"
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "live"
    payload: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
