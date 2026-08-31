"""Vendor Firmware Monitoring (24/7 spec §11).

Track vendor / product / model / firmware / previous firmware / support
status / crypto capability per asset. A firmware change triggers capability
re-discovery → crypto re-discovery → PQC capability check → risk
recalculation.

Invariant: never assume a firmware update makes a product PQC-capable —
PQC verdicts stay evidence-backed (§22/§15).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from universal_vendor.models import PqcCapability


@dataclass
class FirmwareRecord:
    asset_id: str
    vendor: str
    product: str
    model: Optional[str] = None
    firmware: Optional[str] = None
    previous_firmware: Optional[str] = None
    support_status: Optional[str] = None      # from lifecycle DB
    crypto_capability: list[str] = field(default_factory=list)
    pqc_capability: str = PqcCapability.UNKNOWN.value
    firmware_changed_at: Optional[str] = None
    last_checked: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {"asset_id": self.asset_id, "vendor": self.vendor,
                "product": self.product, "model": self.model,
                "firmware": self.firmware,
                "previous_firmware": self.previous_firmware,
                "support_status": self.support_status,
                "crypto_capability": list(self.crypto_capability),
                "pqc_capability": self.pqc_capability,
                "firmware_changed_at": self.firmware_changed_at,
                "last_checked": self.last_checked}


class FirmwareMonitor:
    def __init__(self, lifecycle_db=None, pqc_db=None) -> None:
        self._records: dict[str, FirmwareRecord] = {}
        self._changes: list[dict[str, Any]] = []
        self.lifecycle = lifecycle_db
        self.pqc = pqc_db

    def record(self, *, asset_id: str, vendor: str, product: str,
               firmware: str, model: Optional[str] = None,
               crypto_capability: Optional[list[str]] = None,
               recheck_pqc: Optional[callable] = None) -> dict[str, Any]:
        """Register a firmware observation. Returns change summary."""
        now = datetime.now(timezone.utc).isoformat()
        record = self._records.get(asset_id)
        firmware_changed = record is not None and record.firmware != firmware

        if record is None:
            record = FirmwareRecord(asset_id=asset_id, vendor=vendor,
                                    product=product, model=model,
                                    firmware=firmware, last_checked=now)
        else:
            record.model = model or record.model
            record.last_checked = now
            if firmware_changed:
                record.previous_firmware = record.firmware
                record.firmware = firmware
                record.firmware_changed_at = now

        if crypto_capability is not None:
            record.crypto_capability = list(crypto_capability)

        # support status from the versioned lifecycle DB when available
        if self.lifecycle is not None:
            status = self.lifecycle.status(vendor, product, firmware)
            record.support_status = status.get("support_status")

        # PQC capability is evidence-backed (never inferred from the name):
        # recheck with the DB (or an operator-provided recheck callback).
        if self.pqc is not None:
            verdict = self.pqc.verdict(vendor, product, firmware)
            record.pqc_capability = verdict.get("pqc_capability",
                                                PqcCapability.UNKNOWN.value)
        elif recheck_pqc is not None:
            record.pqc_capability = str(recheck_pqc(vendor, product, firmware))

        self._records[asset_id] = record
        if firmware_changed:
            self._changes.append({"asset_id": asset_id, "vendor": vendor,
                                  "product": product,
                                  "previous_firmware": record.previous_firmware,
                                  "firmware": firmware,
                                  "pqc_capability": record.pqc_capability,
                                  "timestamp": now})
            return {"changed": True, "previous_firmware": record.previous_firmware,
                    "firmware": firmware,
                    "pqc_capability": record.pqc_capability}
        return {"changed": False, "firmware": firmware,
                "pqc_capability": record.pqc_capability}

    def records(self) -> list[FirmwareRecord]:
        return list(self._records.values())

    def changes(self) -> list[dict[str, Any]]:
        return list(self._changes)
