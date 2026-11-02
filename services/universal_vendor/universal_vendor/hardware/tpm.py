"""TPM scanner (§6).

Detect: TPM present, version (1.2/2.0), manufacturer, firmware, capabilities,
supported algorithms (SHA-256, RSA, ECC…), PCR capabilities, secure boot
relationship.

The scanner NEVER extracts secret TPM material — no SRK private key, no
attestation key material, no endorsement-key secrets. Only public metadata.
"""

from __future__ import annotations

from typing import Any

from universal_vendor.hardware.models import TpmInfo
from universal_vendor.hardware.safety import refuse_secret_material

_FORBIDDEN_TPM_MATERIAL = ("endorsement_key", "srk", "attestation_key",
                           "storage_root_key", "auth_value", "secret")


class TpmScanner:
    def parse(self, raw: dict[str, Any]) -> TpmInfo:
        """Parse public TPM metadata. Refuses secret material."""
        refuse_secret_material(raw, _FORBIDDEN_TPM_MATERIAL, surface="TPM scanner")
        return TpmInfo(
            present=bool(raw.get("present", False)),
            version=str(raw.get("version") or "") or None,
            manufacturer=raw.get("manufacturer"),
            firmware=raw.get("firmware"),
            capabilities=[str(c) for c in raw.get("capabilities") or []],
            supported_algorithms=[str(a) for a in raw.get("supported_algorithms") or []],
            pcr_capabilities=[str(p) for p in raw.get("pcr_capabilities") or []],
            secure_boot_relationship=raw.get("secure_boot_relationship"),
        )

    def to_observation(self, tpm: TpmInfo) -> dict[str, Any]:
        return {
            "crypto_type": "hardware-security",
            "algorithm": "TPM",
            "tpm": tpm.to_dict(),
            "vendor_specific": {"note": "public metadata only — no TPM "
                                        "secret material extracted"},
        }

    def drift(self, expected: TpmInfo, current: TpmInfo) -> str | None:
        """§17 example: expected TPM present, current unavailable →
        SECURITY_HARDWARE_DRIFT."""
        if expected.present and not current.present:
            return "SECURITY_HARDWARE_DRIFT"
        if expected.present and current.present:
            if expected.version and current.version and expected.version != current.version:
                return "TPM_DRIFT"
        return None
