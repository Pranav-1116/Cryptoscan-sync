"""ZELNX Live Cloud Intelligence Engine — evidence chain (§19).

Tamper-evident historical evidence:

    PROVIDER EVENT + API VERIFICATION → CANONICAL OBSERVATION →
    CONTENT HASH → PREVIOUS EVIDENCE HASH → NEW EVIDENCE RECORD

Every evidence record chains to its predecessor; any modification to a
past record breaks the chain.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

GENESIS_HASH = "genesis"


def sha256(content: str) -> str:
    return hashlib.sha256(str(content).encode("utf-8")).hexdigest()


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str)


@dataclass
class EvidenceRecord:
    """One chained evidence record."""

    record_id: str
    provider: str = ""
    event_id: str = ""
    resource_id: str = ""
    event_type: str = ""
    source: str = ""            # events | audit | api_state | reconciliation
    observation: dict[str, Any] = field(default_factory=dict)
    api_verification: dict[str, Any] = field(default_factory=dict)
    content_hash: str = ""
    previous_hash: str = ""
    record_hash: str = ""
    recorded_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "provider": self.provider,
            "event_id": self.event_id,
            "resource_id": self.resource_id,
            "event_type": self.event_type,
            "source": self.source,
            "observation": dict(self.observation),
            "api_verification": dict(self.api_verification),
            "content_hash": self.content_hash,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
            "recorded_at": self.recorded_at,
        }


class LiveEvidenceChain:
    """Append-only chained evidence store with verification."""

    def __init__(self, *, clock=None) -> None:
        self._records: list[EvidenceRecord] = []
        self._clock = clock or (lambda: "")
        self._seq = 0

    def record(self, *, provider: str = "", event_id: str = "", resource_id: str = "",
               event_type: str = "", source: str = "",
               observation: dict[str, Any] | None = None,
               api_verification: dict[str, Any] | None = None,
               recorded_at: str = "") -> EvidenceRecord:
        observation = dict(observation or {})
        api_verification = dict(api_verification or {})
        content = canonical_json({
            "provider": provider,
            "event_id": event_id,
            "resource_id": resource_id,
            "event_type": event_type,
            "source": source,
            "observation": observation,
            "api_verification": api_verification,
        })
        self._seq += 1
        record = EvidenceRecord(
            record_id=f"ev-{self._seq:06d}",
            provider=provider,
            event_id=event_id,
            resource_id=resource_id,
            event_type=event_type,
            source=source,
            observation=observation,
            api_verification=api_verification,
            content_hash=sha256(content),
            previous_hash=self.last_hash(),
            recorded_at=recorded_at or self._clock(),
        )
        record.record_hash = sha256(
            f"{record.previous_hash}|{record.content_hash}|{record.record_id}|{record.recorded_at}"
        )
        self._records.append(record)
        return record

    def last_hash(self) -> str:
        return self._records[-1].record_hash if self._records else GENESIS_HASH

    def records(self) -> list[EvidenceRecord]:
        return list(self._records)

    def count(self) -> int:
        return len(self._records)

    def verify_chain(self) -> tuple[bool, str]:
        """Return (valid, failure_reason).

        Recomputes the content hash from the CURRENT observation, so any
        post-hoc tampering with a record's content is detected even if
        the record hash field itself was left untouched.
        """
        previous = GENESIS_HASH
        for record in self._records:
            content = canonical_json({
                "provider": record.provider,
                "event_id": record.event_id,
                "resource_id": record.resource_id,
                "event_type": record.event_type,
                "source": record.source,
                "observation": record.observation,
                "api_verification": record.api_verification,
            })
            if sha256(content) != record.content_hash:
                return False, f"record {record.record_id}: content hash mismatch"
            expected = sha256(
                f"{record.previous_hash}|{record.content_hash}|{record.record_id}|{record.recorded_at}"
            )
            if record.record_hash != expected:
                return False, f"record {record.record_id}: record hash mismatch"
            if record.previous_hash != previous:
                return False, f"record {record.record_id}: breaks chain at {record.recorded_at}"
            previous = record.record_hash
        return True, "chain-valid"

    def tamper(self, record_id: str) -> None:
        """Corrupt a record (test hook) — must break chain verification."""
        for record in self._records:
            if record.record_id == record_id:
                record.observation["tampered"] = True
                return

    def to_dicts(self) -> list[dict[str, Any]]:
        return [record.to_dict() for record in self._records]

    def summary(self) -> dict[str, Any]:
        valid, reason = self.verify_chain()
        return {
            "records": len(self._records),
            "chain_valid": valid,
            "chain_reason": reason,
            "head_hash": self.last_hash(),
        }
