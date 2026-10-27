"""§23 Platform evidence engine — every important observation carries the
full evidence record and links into the product's hash-chain architecture
(SHA-256 content hash + chain hash over the previous record).

    Asset | Source | Timestamp | Observation | Evidence | Detection Method |
    Confidence | Previous State | Current State

No AI: confidence comes from the deterministic evidence-class weights
(catalog-driven), and ``verify()`` recomputes the chain to prove integrity.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

#: deterministic confidence per evidence class (§28-style weights)
_CLASS_CONFIDENCE = {
    "observation": 0.9, "fingerprint": 0.85, "import": 0.8,
    "symbol": 0.8, "string": 0.5, "config": 0.7, "runtime": 0.7,
    "certificate": 0.9, "api": 0.8, "manual": 0.95,
}


def confidence_for(method: str) -> float:
    return _CLASS_CONFIDENCE.get(method, 0.5)


class EvidenceChain:
    """Append-only SHA-256 chain of platform evidence records."""

    def __init__(self, records: Optional[list[dict[str, Any]]] = None) -> None:
        self.records: list[dict[str, Any]] = list(records or [])

    def _hash(self, payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def append(self, *, asset: str, source: str, observation: str,
               evidence: Any, method: str, previous_state: Any = None,
               current_state: Any = None) -> dict[str, Any]:
        """Create and chain one evidence record."""
        record = {
            "asset": asset,
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "observation": observation,
            "evidence": evidence,
            "detection_method": method,
            "confidence": confidence_for(method),
            "previous_state": previous_state,
            "current_state": current_state,
        }
        record["content_hash"] = self._hash(record)
        chain_hash = self.records[-1]["chain_hash"] if self.records \
            else ("0" * 64)
        record["chain_hash"] = self._hash(
            {"previous": chain_hash, "content": record["content_hash"]})
        record["sequence"] = len(self.records)
        self.records.append(record)
        return record

    def verify(self) -> dict[str, Any]:
        """Recompute the chain; every link must match."""
        previous = "0" * 64
        for record in self.records:
            content_hash = self._hash({k: v for k, v in record.items()
                                       if k not in ("content_hash",
                                                    "chain_hash",
                                                    "sequence")})
            expected_chain = self._hash(
                {"previous": previous, "content": content_hash})
            if content_hash != record["content_hash"] or \
                    expected_chain != record["chain_hash"]:
                return {"valid": False,
                        "broken_at": record.get("sequence"),
                        "record": record}
            previous = record["chain_hash"]
        return {"valid": True, "records": len(self.records),
                "head": self.records[-1]["chain_hash"] if self.records else None}
