"""Smart card / secure element discovery (§8).

Where authorized, identify smart-card readers, secure elements,
hardware-backed credential devices and cryptographic token interfaces.
Record METADATA ONLY: vendor, model, interface, firmware, supported
algorithms, certificate references, application dependencies.

Never secret credentials, never private keys, never PINs.
"""

from __future__ import annotations

from typing import Any

_FORBIDDEN = ("private_key", "credential_secret", "pin", "password",
              "key_value", "certificate_private", "secret")


class SmartCardScanner:
    def parse(self, raw: dict[str, Any]) -> dict[str, Any]:
        lowered = str(raw).lower()
        for token in _FORBIDDEN:
            assert token not in lowered, f"smart-card scanner refused {token}"
        return {
            "device_type": raw.get("device_type", "smart_card"),
            "vendor": raw.get("vendor", ""),
            "model": raw.get("model", ""),
            "interface": raw.get("interface", ""),        # PC/SC, CCID, T=1, …
            "firmware": raw.get("firmware"),
            "supported_algorithms": list(raw.get("supported_algorithms") or []),
            "certificate_references": list(raw.get("certificate_references") or []),
            "application_dependencies": list(raw.get("application_dependencies") or []),
            "vendor_specific": {k: v for k, v in raw.items()
                                if k not in (
                                    "vendor", "model", "interface", "firmware",
                                    "supported_algorithms",
                                    "certificate_references",
                                    "application_dependencies", "device_type")},
        }
