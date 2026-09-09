"""Evidence Chain — tamper-evident history for every change.

    Observation → Canonical Serialization → Content Hash → Previous Chain
    Hash → New Evidence Record

Each record links to the previous record's hash, producing a chain that can
be verified end-to-end.  Any modification of an earlier record breaks every
subsequent record's linkage.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

GENESIS_HASH = "GENESIS"

HashFn = Callable[[bytes], str]


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic canonical serialization (sorted keys, compact JSON)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class EvidenceRecord:
    sequence: int
    observation: dict[str, Any]
    canonical: str
    content_hash: str
    previous_hash: str
    observed_at: Any = None
    record_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        observed = self.observed_at
        if hasattr(observed, "isoformat"):
            observed = observed.isoformat()
        return {"sequence": self.sequence,
                "observation": dict(self.observation),
                "canonical": self.canonical,
                "content_hash": self.content_hash,
                "previous_hash": self.previous_hash,
                "observed_at": observed,
                "record_id": self.record_id}


class EvidenceChain:
    """Append-only, hash-linked evidence chain."""

    def __init__(self, *, hash_fn: HashFn = sha256_hex,
                 clock: Callable[[], Any] | None = None) -> None:
        self._hash = hash_fn
        self._records: list[EvidenceRecord] = []
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------- append

    def append(self, observation: dict[str, Any], *,
               now: Any | None = None) -> EvidenceRecord:
        canonical = canonical_bytes(observation).decode("utf-8")
        previous_hash = self._records[-1].content_hash if self._records else GENESIS_HASH
        content_hash = self._hash(canonical_bytes(
            {"canonical": canonical, "previous_hash": previous_hash}))
        record_id = self._hash(canonical_bytes(
            {"sequence": len(self._records), "content_hash": content_hash}))
        record = EvidenceRecord(
            sequence=len(self._records),
            observation=dict(observation),
            canonical=canonical,
            content_hash=content_hash,
            previous_hash=previous_hash,
            observed_at=now if now is not None else self._clock(),
            record_id=record_id,
        )
        self._records.append(record)
        return record

    def extend(self, observations: Iterable[dict[str, Any]],
               *, now: Any | None = None) -> list[EvidenceRecord]:
        return [self.append(obs, now=now) for obs in observations]

    # ------------------------------------------------------------- verify

    def verify(self) -> bool:
        """Recompute every link; False on any tamper or breakage."""
        previous = GENESIS_HASH
        for record in self._records:
            expected_content = self._hash(canonical_bytes(
                {"canonical": record.canonical, "previous_hash": previous}))
            if record.content_hash != expected_content:
                return False
            if record.previous_hash != previous:
                return False
            expected_id = self._hash(canonical_bytes(
                {"sequence": record.sequence, "content_hash": record.content_hash}))
            if record.record_id != expected_id:
                return False
            previous = record.content_hash
        return True

    def verify_from(self, sequence: int) -> bool:
        """Verify the tail of the chain starting at ``sequence`` (for sync)."""
        previous = self._records[sequence - 1].content_hash if sequence > 0 else GENESIS_HASH
        for record in self._records[sequence:]:
            expected = self._hash(canonical_bytes(
                {"canonical": record.canonical, "previous_hash": previous}))
            if record.content_hash != expected or record.previous_hash != previous:
                return False
            previous = record.content_hash
        return True

    # ------------------------------------------------------------- access

    def records(self) -> list[EvidenceRecord]:
        return list(self._records)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [record.to_dict() for record in self._records]

    def tail(self, n: int = 10) -> list[EvidenceRecord]:
        return list(self._records[-n:])

    def __len__(self) -> int:
        return len(self._records)
