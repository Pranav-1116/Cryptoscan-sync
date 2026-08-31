"""Hardware fingerprinting (§4).

Detect hardware from multiple evidence sources (DMI/SMBIOS, PCI IDs, USB IDs,
MAC/OUI, SNMP, LLDP, CDP, BMC, vendor API, firmware, device banner, cloud
metadata) and compute a hardware identity confidence.

Example: manufacturer Dell + model PowerEdge + serial evidence + DMI evidence
+ BMC evidence → confidence HIGH.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from universal_vendor.hardware.models import HardwareConfidence

# weight per corroborating evidence source
_EVIDENCE_WEIGHTS: dict[str, float] = {
    "dmi": 1.0, "smbios": 1.0, "serial": 0.8, "bmc": 0.8, "snmp": 0.7,
    "vendor_api": 0.7, "firmware": 0.6, "mac_oui": 0.5, "lldp": 0.5,
    "cdp": 0.5, "pci": 0.4, "usb": 0.3, "device_banner": 0.4,
    "cloud_metadata": 0.4,
}


@dataclass
class HardwareFingerprint:
    manufacturer: str = ""
    model: str = ""
    serial_reference: Optional[str] = None
    device_type: str = "other"
    firmware: Optional[str] = None
    evidence_sources: list[str] = field(default_factory=list)
    confidence: str = HardwareConfidence.LOW.value

    @property
    def score(self) -> float:
        return sum(_EVIDENCE_WEIGHTS.get(source, 0.0) for source in self.evidence_sources)

    def to_dict(self) -> dict[str, Any]:
        return {"manufacturer": self.manufacturer, "model": self.model,
                "serial_reference": self.serial_reference,
                "device_type": self.device_type, "firmware": self.firmware,
                "evidence_sources": list(self.evidence_sources),
                "confidence": self.confidence, "score": round(self.score, 2)}


def _confidence_for(score: float) -> str:
    if score >= 1.8:
        return HardwareConfidence.HIGH.value
    if score >= 0.9:
        return HardwareConfidence.MEDIUM.value
    return HardwareConfidence.LOW.value


def fingerprint_hardware(signals: dict[str, Any]) -> HardwareFingerprint:
    """Compute a hardware fingerprint from a dict of evidence signals.

    Keys: dmi, serial, bmc, snmp, vendor_api, firmware, mac_oui, lldp, cdp,
    pci, usb, device_banner, cloud_metadata — each non-empty string/dict
    counts as corroborating evidence.
    """
    sources = [key for key, value in signals.items()
               if key in _EVIDENCE_WEIGHTS and value]
    score = sum(_EVIDENCE_WEIGHTS.get(key, 0.0) for key in sources)

    dmi = signals.get("dmi") or {}
    if isinstance(dmi, str):
        dmi = {}
    return HardwareFingerprint(
        manufacturer=str(signals.get("manufacturer")
                         or (dmi.get("manufacturer") if isinstance(dmi, dict) else "")
                         or ""),
        model=str(signals.get("model")
                  or (dmi.get("product") if isinstance(dmi, dict) else "")
                  or ""),
        serial_reference=signals.get("serial")
        or (dmi.get("serial") if isinstance(dmi, dict) else None),
        device_type=str(signals.get("device_type") or "other"),
        firmware=signals.get("firmware"),
        evidence_sources=sources,
        confidence=_confidence_for(score),
    )


class FingerprintTracker:
    """Per-asset fingerprint history for drift detection (§17)."""

    def __init__(self) -> None:
        self._current: dict[str, str] = {}
        self._previous: dict[str, str] = {}

    def observe(self, asset_id: str, fingerprint: HardwareFingerprint) -> dict[str, Any]:
        import hashlib
        import json

        digest = hashlib.sha256(
            json.dumps(fingerprint.to_dict(), sort_keys=True, default=str).encode()
        ).hexdigest()[:16]
        previous = self._current.get(asset_id)
        self._previous[asset_id] = previous or digest
        self._current[asset_id] = digest
        return {"asset_id": asset_id, "fingerprint_hash": digest,
                "previous_hash": self._previous[asset_id],
                "changed": previous is not None and previous != digest,
                "first_seen": previous is None}
