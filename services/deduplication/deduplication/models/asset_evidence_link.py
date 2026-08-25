"""Many-to-many link between a crypto asset and an evidence record."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class AssetEvidenceLink:
    asset_id: str
    evidence_id: str
    link_type: str = "PRIMARY"

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "evidence_id": self.evidence_id,
            "link_type": self.link_type,
        }
