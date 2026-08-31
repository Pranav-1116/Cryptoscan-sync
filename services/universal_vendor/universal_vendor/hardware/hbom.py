"""Hardware CBOM / HBOM (§19).

HBOM — Hardware Bill of Materials: physical hardware, firmware, security
hardware (TPM/HSM), hardware capabilities. Combined with CBOM + SBOM + live
dependency graph this forms a complete technology inventory.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from universal_vendor.hardware.models import HardwareObservation

try:  # guarded import: reuse the shared CBOM generator when available
    from cbom.generator import CbomGenerator

    _HAS_CBOM = True
except Exception:  # pragma: no cover
    CbomGenerator = None  # type: ignore[assignment]
    _HAS_CBOM = False


class HbomGenerator:
    def __init__(self) -> None:
        self._hardware: dict[str, dict[str, Any]] = {}
        self._firmware: list[dict[str, Any]] = []
        self._security_hardware: list[dict[str, Any]] = []
        self._version = 1

    def add(self, observation: HardwareObservation) -> None:
        asset_id = observation.asset_id
        entry = {
            "bom-ref": f"hw:{asset_id}",
            "type": observation.device_type,
            "manufacturer": observation.manufacturer,
            "model": observation.model,
            "serial": observation.serial_reference,
            "firmware": observation.firmware,
            "revision": observation.hardware_revision,
            "environment": observation.environment,
            "confidence": observation.confidence,
            "visibility": observation.visibility,
        }
        self._hardware[asset_id] = entry

        for component, version in (observation.firmware_components or {}).items():
            self._firmware.append({"asset_id": asset_id, "component": component,
                                   "version": version})

        security_kinds = ("hsm", "tpm", "secure_element", "smart_card")
        if observation.device_type in security_kinds:
            self._security_hardware.append(entry)
        if observation.tpm:
            self._security_hardware.append({"asset_id": asset_id,
                                            "type": "tpm", "tpm": observation.tpm})

    # ── output ────────────────────────────────────────────────────────

    def hardware(self) -> list[dict[str, Any]]:
        return list(self._hardware.values())

    def firmware(self) -> list[dict[str, Any]]:
        return list(self._firmware)

    def security_hardware(self) -> list[dict[str, Any]]:
        return list(self._security_hardware)

    def to_document(self, *, name: str = "zelinx-hbom") -> dict[str, Any]:
        return {
            "hbomFormat": "ZELNX-HBOM",
            "version": self._version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "name": name,
            "hardware": self.hardware(),
            "firmware": self.firmware(),
            "security_hardware": self.security_hardware(),
        }

    def to_cyclonedx(self, *, name: str = "zelinx-hbom") -> dict[str, Any]:
        """Serializable CycloneDX-style document."""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": self._version,
            "metadata": {"component": {"type": "device", "name": name},
                         "timestamp": datetime.now(timezone.utc).isoformat()},
            "components": [
                {
                    "type": "device",
                    "name": f"{entry['manufacturer']} {entry['model']}".strip(),
                    "version": entry.get("firmware") or "unknown",
                    "bom-ref": entry["bom-ref"],
                    "properties": [
                        {"name": "asset_id", "value": asset_id},
                        {"name": "device_type", "value": entry["type"]},
                        {"name": "serial", "value": entry.get("serial") or ""},
                        {"name": "hardware_type", "value": entry["type"]},
                    ],
                }
                for asset_id, entry in self._hardware.items()
            ],
        }

    def combined_inventory(self, cbom_components: list[dict[str, Any]] | None = None,
                           sbom_components: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """HBOM + CBOM + SBOM in one technology inventory (§19)."""
        return {
            "hbom_hardware": len(self._hardware),
            "hbom_firmware": len(self._firmware),
            "hbom_security_hardware": len(self._security_hardware),
            "cbom_components": len(cbom_components or []),
            "sbom_components": len(sbom_components or []),
            "note": "HBOM + CBOM + SBOM + live dependency graph form the "
                    "complete technology inventory",
        }
