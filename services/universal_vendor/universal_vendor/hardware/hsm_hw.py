"""HSM hardware scanner (§7) — integrates with the vendor HSM plugins.

Collects manufacturer, model, firmware, partition metadata, crypto
capabilities, supported algorithms, key type METADATA, certificate
dependencies and PQC capability. Tracks HSM_CAPABILITY_CHANGED /
FIRMWARE_CHANGED / CRYPTO_SUPPORT_CHANGED / CONFIGURATION_CHANGED.

Never collects private keys or secret key material (hard assertion).
"""

from __future__ import annotations

from typing import Any, Optional

from universal_vendor.hardware.models import HardwareType
from universal_vendor.hardware.safety import refuse_secret_material

try:  # guarded import: reuse vendor HSM plugin models when available
    from universal_vendor.plugins.hsm import (
        AwsCloudHsmPlugin,
        EntrustNshieldPlugin,
        ThalesLunaPlugin,
        UtimacoPlugin,
    )

    _VENDOR_HSM_PLUGINS = [ThalesLunaPlugin, EntrustNshieldPlugin,
                           UtimacoPlugin, AwsCloudHsmPlugin]
except Exception:  # pragma: no cover
    _VENDOR_HSM_PLUGINS = []

#: Tokens refused in an HSM payload. The space-separated spellings matter: PEM
#: armour announces a key with "BEGIN PRIVATE KEY" in upper case, and a guard that
#: only knew the underscore spelling accepted the whole block. Found by running the
#: guard against a PEM payload rather than by reading it.
_FORBIDDEN = ("private_key", "private key", "master_key", "master key",
              "secret_key", "secret key", "wrapped_key", "wrapped key",
              "pin", "secret", "password", "passphrase", "plaintext",
              "key_material", "key material", "token_value", "key_value")


class HsmHardwareScanner:
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    def scan(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Parse HSM metadata. Refuses any secret material."""
        refuse_secret_material(raw, _FORBIDDEN, surface="HSM hardware scanner")
        observation = {
            "device_type": HardwareType.HSM.value,
            "manufacturer": raw.get("manufacturer", ""),
            "model": raw.get("model", ""),
            "firmware": raw.get("firmware"),
            "crypto_capabilities": list(raw.get("crypto_capabilities") or []),
            "supported_algorithms": list(raw.get("supported_algorithms") or []),
            "key_type_metadata": list(raw.get("key_type_metadata") or []),
            "certificate_dependencies": list(raw.get("certificate_dependencies") or []),
            "partition_metadata": raw.get("partition_metadata"),
            "pqc_capability": raw.get("pqc_capability", "UNKNOWN"),
            # §4 depth: an HSM is a cluster member before it is a model number, and
            # "which of the two appliances failed" is the question an operator asks
            "serial_reference": raw.get("serial_reference"),
            "cluster": raw.get("cluster"),
            "ha_state": raw.get("ha_state", "UNKNOWN"),
            "pqc_algorithms": list(raw.get("pqc_algorithms") or []),
            "firmware_verified_at": raw.get("firmware_verified_at"),
            "vendor_specific": {k: v for k, v in raw.items()
                                if k not in (
                                    "manufacturer", "model", "firmware",
                                    "crypto_capabilities", "supported_algorithms",
                                    "key_type_metadata", "certificate_dependencies",
                                    "partition_metadata", "pqc_capability",
                                    "serial_reference", "cluster", "ha_state",
                                    "pqc_algorithms", "firmware_verified_at")},
        }
        return observation

    def vendor_plugin_metadata(self, vendor: str) -> Optional[dict[str, Any]]:
        """Surface the matching vendor HSM plugin's advertised capabilities."""
        for plugin_cls in _VENDOR_HSM_PLUGINS:
            if plugin_cls.vendor.lower() == vendor.lower():
                return {"plugin_id": plugin_cls.plugin_id,
                        "vendor": plugin_cls.vendor,
                        "product": plugin_cls.product,
                        "supported_features": list(plugin_cls.supported_features)}
        return None

    # ── §7 event tracking ─────────────────────────────────────────────

    def track_event(self, *, asset_id: str, event_type: str,
                    detail: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        assert event_type in ("HSM_CAPABILITY_CHANGED", "FIRMWARE_CHANGED",
                              "CRYPTO_SUPPORT_CHANGED", "CONFIGURATION_CHANGED")
        event = {"asset_id": asset_id, "event_type": event_type,
                 "detail": detail or {}}
        self._events.append(event)
        return event

    def events(self) -> list[dict[str, Any]]:
        return list(self._events)
