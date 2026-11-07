"""Integration qualification status — the registry never upgrades itself.

A fixture, a connector definition or a passing adapter test is NOT support:
the status starts at REGISTERED and only a named qualification with its
evidence reference moves it. External qualifications are recorded here
(register-only) — this module never asserts that one happened.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


REGISTERED = "REGISTERED"
QUALIFIED = "QUALIFIED"
SUSPENDED = "SUSPENDED"
_STATUSES = (REGISTERED, QUALIFIED, SUSPENDED)


@dataclass
class QualificationRecord:
    adapter_id: str
    status: str = REGISTERED
    evidence_ref: str | None = None
    qualified_by: str | None = None
    at: str | None = None
    history: list[dict[str, Any]] = field(default_factory=list)


class QualificationRegistry:
    def __init__(self) -> None:
        self._records: dict[str, QualificationRecord] = {}

    def register(self, adapter_id: str) -> QualificationRecord:
        """Presence in the registry means REGISTERED — never qualified."""
        record = self._records.get(adapter_id)
        if record is None:
            record = QualificationRecord(adapter_id=adapter_id)
            self._records[adapter_id] = record
        return record

    def qualify(self, adapter_id: str, *, evidence_ref: str,
                qualified_by: str, at: str) -> QualificationRecord:
        record = self.register(adapter_id)
        if not str(evidence_ref).strip():
            raise ValueError("qualification names its evidence reference: "
                             "status without evidence is a claim, not a "
                             "qualification")
        if not str(qualified_by).strip():
            raise ValueError("qualification names who qualified the integration")
        record.status = QUALIFIED
        record.evidence_ref = str(evidence_ref)
        record.qualified_by = str(qualified_by)
        record.at = str(at)
        record.history.append({"status": QUALIFIED, "evidence_ref": str(evidence_ref),
                               "qualified_by": str(qualified_by), "at": str(at)})
        return record

    def suspend(self, adapter_id: str, *, reason: str) -> QualificationRecord:
        record = self.register(adapter_id)
        record.status = SUSPENDED
        record.history.append({"status": SUSPENDED, "reason": str(reason)})
        return record

    def status_of(self, adapter_id: str) -> str:
        return self.register(adapter_id).status

    def snapshot(self) -> list[dict[str, Any]]:
        return [
            {"adapter_id": r.adapter_id, "status": r.status,
             "evidence_ref": r.evidence_ref, "qualified_by": r.qualified_by,
             "at": r.at}
            for r in sorted(self._records.values(), key=lambda r: r.adapter_id)
        ]
