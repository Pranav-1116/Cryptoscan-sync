"""ZELNX Cloud Discovery Engine — evidence collection (spec §22).

Every discovery observation carries provenance (source provider, account,
API source, timestamp, normalization version, confidence) and is chained:

    Raw Evidence → Canonical Serialization → Content Hash → Chain Hash
    → Evidence Record

``content_hash`` covers the canonical serialization of the observation;
``chain_hash`` covers (previous_chain_hash + content_hash), so re-ordered
or tampered evidence breaks the chain.  ``verify()`` re-computes the whole
chain.  No key material or secret values ever enter evidence payloads.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cloud_scanner.enterprise.models import EvidenceSource, NORMALIZATION_VERSION

GENESIS_HASH = "genesis"


def canonical_json(value: dict[str, Any]) -> str:
    """Stable canonical serialization: sorted keys, compact separators."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def evidence_block(
    *,
    source_provider: str,
    api_source: str,
    account: str | None = None,
    timestamp: str | None = None,
    normalization_version: str = NORMALIZATION_VERSION,
    confidence: str = "MEDIUM",
) -> EvidenceSource:
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    return EvidenceSource(
        source_provider=source_provider,
        account=account,
        api_source=api_source,
        timestamp=ts,
        normalization_version=normalization_version,
        confidence=confidence,
    )


@dataclass
class EvidenceRecord:
    """One linked evidence record in the chain."""

    sequence: int
    observation: dict[str, Any]
    canonical: str
    content_hash: str
    previous_chain_hash: str
    chain_hash: str
    recorded_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "observation": self.observation,
            "canonical": self.canonical,
            "content_hash": self.content_hash,
            "previous_chain_hash": self.previous_chain_hash,
            "chain_hash": self.chain_hash,
            "recorded_at": self.recorded_at,
        }


class EvidenceChain:
    """Linked evidence records; append-only and verifiable."""

    def __init__(self) -> None:
        self._records: list[EvidenceRecord] = []
        self._sequence = 0

    @property
    def head(self) -> str:
        if not self._records:
            return GENESIS_HASH
        return self._records[-1].chain_hash

    def append(self, observation: dict[str, Any]) -> EvidenceRecord:
        """Hash and chain one observation (already normalized + scrubbed)."""
        self._sequence += 1
        canonical = canonical_json(observation)
        content_hash = sha256(canonical)
        previous = self.head
        chain_hash = sha256(f"{previous}|{content_hash}")
        record = EvidenceRecord(
            sequence=self._sequence,
            observation=dict(observation),
            canonical=canonical,
            content_hash=content_hash,
            previous_chain_hash=previous,
            chain_hash=chain_hash,
        )
        self._records.append(record)
        return record

    def __len__(self) -> int:
        return len(self._records)

    def records(self) -> list[EvidenceRecord]:
        return list(self._records)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [record.to_dict() for record in self._records]

    def verify(self) -> bool:
        """Re-run the hash chain; any tamper or reorder fails verification."""
        previous = GENESIS_HASH
        for record in self._records:
            canonical = canonical_json(record.observation)
            if canonical != record.canonical:
                return False
            if sha256(canonical) != record.content_hash:
                return False
            if record.previous_chain_hash != previous:
                return False
            if sha256(f"{previous}|{record.content_hash}") != record.chain_hash:
                return False
            previous = record.chain_hash
        return True

    def verify_from(self, sequence: int) -> bool:
        if sequence < 1:
            return False
        start = next((i for i, r in enumerate(self._records) if r.sequence >= sequence), None)
        if start is None:
            return False
        # anchor = chain hash of the record just before the verified window
        previous = self._records[start - 1].chain_hash if start > 0 else GENESIS_HASH
        for record in self._records[start:]:
            if sha256(canonical_json(record.observation)) != record.content_hash:
                return False
            if record.previous_chain_hash != previous:
                return False
            if sha256(f"{previous}|{record.content_hash}") != record.chain_hash:
                return False
            previous = record.chain_hash
        return True

    def tail(self, n: int = 5) -> list[dict[str, Any]]:
        return [record.to_dict() for record in self._records[-max(1, n):]]
