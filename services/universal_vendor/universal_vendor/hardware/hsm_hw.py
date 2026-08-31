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

_FORBIDDEN = ("private_key", "master_key", "pin", "secret", "password",
              "key_material", "token_value", "key_value")


class HsmHardwareScanner:
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    def scan(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Parse HSM metadata. Refuses any secret material."""
        lowered = str(raw).lower()
        for token in _FORBIDDEN:
            assert token not in lowered, f"HSM hardware scanner refused {token}"
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
            "vendor_specific": {k: v for k, v in raw.items()
                                if k not in (
                                    "manufacturer", "model", "firmware",
                                    "crypto_capabilities", "supported_algorithms",
                                    "key_type_metadata", "certificate_dependencies",
                                    "partition_metadata", "pqc_capability")},
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
