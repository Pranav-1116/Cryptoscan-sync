"""discovery.py — inventory / configuration / crypto / certificate discovery.

Return *raw* dict records; the normalizer converts them into the canonical
UniversalObservation shape. Keep raw records free of secret material —
the platform scrubs known secret fields automatically, but the plugin
should not collect them in the first place.
"""

from __future__ import annotations

import re
from typing import Any

from universal_vendor.plugins._helpers import extract_algorithms
from .connector_plugin import MyVendorPluginConnector  # noqa: F401  (re-export)


class DiscoveryMixin:
    """Mixin that supplies the discovery methods for MyVendor.

    Combine with the connector class:

        class MyVendorPlugin(MyVendorPluginConnector, DiscoveryMixin): ...
    """

    def discover_inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Inventory records: model, version, serial, licenses."""
        inventory = []
        model = context.get("model")
        if model:
            inventory.append({
                "vendor": self.vendor,
                "product": self.product,
                "asset_id": context.get("asset_id", "myvendor"),
                "crypto_type": "configuration",
                "algorithm": "inventory",
                "configuration": {"model": model,
                                  "version": context.get("version")},
            })
        return inventory

    def discover_configuration(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Crypto-relevant configuration records (metadata only)."""
        config = context.get("config", "") or ""
        records = []
        if "tls" in config.lower():
            records.append({
                "vendor": self.vendor,
                "product": self.product,
                "asset_id": context.get("asset_id", "myvendor"),
                "crypto_type": "configuration",
                "algorithm": "TLS",
                "protocol": "TLS",
                "configuration": {"tls": "enabled"},
            })
        return records

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Crypto observations: algorithms, key sizes, protocols."""
        config = context.get("config", "") or ""
        observations = []
        for algo in extract_algorithms(config):
            observations.append({
                "vendor": self.vendor,
                "product": self.product,
                "asset_id": context.get("asset_id", "myvendor"),
                "crypto_type": "algorithm",
                "algorithm": algo,
            })
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Certificate observations (public metadata only)."""
        certs = []
        for match in re.finditer(r"cert\s+(\S+)",
                                 context.get("config", "") or ""):
            certs.append({"name": match.group(1), "type": "server"})
        return [{
            "vendor": self.vendor,
            "product": self.product,
            "asset_id": context.get("asset_id", "myvendor"),
            "crypto_type": "certificate",
            "certificate": cert,
        } for cert in certs]

    def discover_dependencies(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Dependency edges for the universal vendor graph (spec §21)."""
        return [{
            "asset_id": context.get("asset_id", "myvendor"),
            "target_asset": target,
            "relationship": "DEPENDS_ON",
        } for target in (context.get("depends_on") or [])]
