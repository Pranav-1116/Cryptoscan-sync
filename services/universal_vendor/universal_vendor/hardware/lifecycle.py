"""Hardware lifecycle intelligence (§14).

Track manufacture/model/hardware-revision/firmware, support status, end of
support, end of life, replacement availability, crypto capability and PQC
capability. Example: legacy HSM + no required PQC capability + EOS
approaching → CRITICAL MIGRATION CANDIDATE.

Like the vendor lifecycle DB, entries are versioned and evidence-backed;
everything unverified is UNKNOWN.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from universal_vendor.models import LifecycleStatus

DB_VERSION = "2026-08"


@dataclass(frozen=True)
class HardwareLifecycleEntry:
    manufacturer: str
    model: str
    support_status: str
    end_of_support: Optional[str] = None
    end_of_life: Optional[str] = None
    replacement_available: bool = False
    crypto_capability: str = "unknown"
    pqc_capability: str = "UNKNOWN"
    evidence_source: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"manufacturer": self.manufacturer, "model": self.model,
                "support_status": self.support_status,
                "end_of_support": self.end_of_support,
                "end_of_life": self.end_of_life,
                "replacement_available": self.replacement_available,
                "crypto_capability": self.crypto_capability,
                "pqc_capability": self.pqc_capability,
                "evidence_source": self.evidence_source,
                "confidence": self.confidence}


# Evidence-backed seed — widely documented hardware EOL milestones.
_SEED: list[HardwareLifecycleEntry] = [
    HardwareLifecycleEntry(
        manufacturer="HPE", model="ProLiant Gen9",
        support_status=LifecycleStatus.END_OF_SUPPORT.value,
        end_of_support="2024-12-31", end_of_life="2025-12-31",
        replacement_available=True, crypto_capability="standard",
        pqc_capability="UNKNOWN",
        evidence_source="HPE server lifecycle documentation",
        confidence=0.9,
    ),
    HardwareLifecycleEntry(
        manufacturer="Dell", model="PowerEdge 13G",
        support_status=LifecycleStatus.END_OF_SUPPORT.value,
        end_of_support="2023-12-31", end_of_life="2024-12-31",
        replacement_available=True, crypto_capability="standard",
        pqc_capability="UNKNOWN",
        evidence_source="Dell PowerEdge lifecycle documentation",
        confidence=0.9,
    ),
    HardwareLifecycleEntry(
        manufacturer="Thales", model="payShield 9000",
        support_status=LifecycleStatus.SUPPORTED.value,
        replacement_available=True, crypto_capability="payment-hsm",
        pqc_capability="ROADMAP_DECLARED",
        evidence_source="Thales payShield product lifecycle (10K is current)",
        confidence=0.8,
    ),
]


class HardwareLifecycleDatabase:
    def __init__(self, version: str = DB_VERSION) -> None:
        self.version = version
        self._entries: list[HardwareLifecycleEntry] = list(_SEED)

    def add(self, entry: HardwareLifecycleEntry) -> None:
        self._entries.append(entry)

    def lookup(self, manufacturer: str, model: str) -> Optional[HardwareLifecycleEntry]:
        for entry in self._entries:
            if (entry.manufacturer.lower() in manufacturer.lower()
                    and entry.model.lower() in model.lower()):
                return entry
        return None

    def status(self, manufacturer: str, model: str) -> dict[str, Any]:
        entry = self.lookup(manufacturer, model)
        if entry is None:
            return {"manufacturer": manufacturer, "model": model,
                    "support_status": LifecycleStatus.UNKNOWN.value,
                    "reason": "no verified lifecycle entry; NOT inferred",
                    "db_version": self.version}
        return entry.to_dict() | {"db_version": self.version}

    def migration_candidate(self, manufacturer: str, model: str, *,
                            pqc_required: bool = True) -> dict[str, Any]:
        """§14 example: legacy HSM + no PQC + EOS → CRITICAL MIGRATION CANDIDATE.

        Evidence-backed only: verdicts come from the lifecycle DB; anything
        unverified stays STANDARD (never inferred from a product name).
        """
        status = self.status(manufacturer, model)
        support = status.get("support_status")
        eos = status.get("end_of_support")
        pqc = status.get("pqc_capability", "UNKNOWN")
        eolish = support in (LifecycleStatus.END_OF_SUPPORT.value,
                             LifecycleStatus.END_OF_LIFE.value)
        no_pqc = pqc in ("UNKNOWN", "NOT_SUPPORTED")
        critical = pqc_required and no_pqc and eolish
        high = (eolish and not critical) or (pqc_required and no_pqc and eos)
        return {
            "manufacturer": manufacturer, "model": model,
            "lifecycle": status,
            "pqc_required": pqc_required,
            "candidate": "CRITICAL" if critical else ("HIGH" if high else "STANDARD"),
        }

    def entries(self) -> list[dict[str, Any]]:
        return [entry.to_dict() for entry in self._entries]
