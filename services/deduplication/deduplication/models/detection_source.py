"""Scanner that contributed a finding to an asset."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class DetectionSource:
    scanner_id: str | None
    scan_id: str | None = None
    confidence: str = "LOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner_id": self.scanner_id,
            "scan_id": self.scan_id,
            "confidence": self.confidence,
        }
