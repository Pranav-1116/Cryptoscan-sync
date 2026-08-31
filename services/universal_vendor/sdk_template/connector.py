"""connector.py — connection/credential validation for the vendor plugin.

The connector is read-only: it only verifies that the provided artifact
(config text, banner, API metadata) or credentials are usable. It never
modifies the target and never reads secret material.
"""

from __future__ import annotations

from typing import Any

from universal_vendor.models import ConnectionResult, DetectionResult
from universal_vendor.plugin import UniversalVendorPlugin


class MyVendorPluginConnector(UniversalVendorPlugin):
    """Minimal connector — adjust `_required_keys` to your artifact surface."""

    _required_keys = ("config",)

    def detect(self, context: dict[str, Any]) -> DetectionResult:
        # Implement your own multi-signal detection here (spec §16).
        # Example: a regex over banner/config fields.
        return self._detect_banner(
            context,
            patterns=[
                (r"myvendor", "MyVendor", "MyProduct", 0.85),
            ],
        )

    def validate_connection(self, context: dict[str, Any]) -> ConnectionResult:
        missing = [key for key in self._required_keys if key not in context]
        if missing:
            return ConnectionResult(
                connected=False,
                message=f"missing artifact(s): {', '.join(missing)}",
            )
        if not self.detect(context).detected:
            return ConnectionResult(
                connected=False,
                message="artifact does not match MyVendor MyProduct",
            )
        return ConnectionResult(connected=True, message="artifact present and recognized")
