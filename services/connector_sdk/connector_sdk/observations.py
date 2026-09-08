"""Normalized connector observation envelope.

Every ZELNX connector emits observations in this single shape. It is source-,
timestamped- and evidence-linked (identity-resolution + evidence-chain),
so the platform can correlate ``10.10.1.20`` / ``server-20`` / ``payment-server``
into one asset without a connector knowing anything about the rest of the
estate.

No field is invented: ``confidence`` is a string the connector substantiates,
``evidence`` is the raw observed artifact, ``first_seen``/``last_seen`` are
timestamps the connector recorded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

_CONFIDENCE = ("HIGH", "MEDIUM", "LOW", "TENTATIVE")


@dataclass
class Observation:
    asset: str                      # canonical-looking id the connector saw
    source: str                     # connector kind (e.g. "network", "aws", "hsm")
    observation_type: str           # e.g. "asset", "crypto", "certificate", "config"
    method: str = "observation"     # how it was observed (agent/api/terraform/snmp)
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: str = "MEDIUM"
    asset_type: str | None = None   # optional normalized type hint
    scanner: str | None = None      # which scanner produced this observation
    first_seen: str | None = None
    last_seen: str | None = None
    relationship: dict[str, Any] | None = None  # optional observed link (e.g. used_by)
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.confidence not in _CONFIDENCE:
            self.confidence = "TENTATIVE"
        now = datetime.now(timezone.utc).isoformat()
        self.first_seen = self.first_seen or now
        self.last_seen = self.last_seen or now

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "source": self.source,
            "observation_type": self.observation_type,
            "method": self.method,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "asset_type": self.asset_type,
            "scanner": self.scanner,
            "relationship": self.relationship,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "extra": self.extra,
        }


def observations_to_json(items: list[Observation]) -> str:
    import json
    return json.dumps([o.to_dict() for o in items], default=str)


__all__ = ["Observation", "observations_to_json", "_CONFIDENCE"]
