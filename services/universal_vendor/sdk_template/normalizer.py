"""normalizer.py — raw records -> canonical UniversalObservation (spec §1, §20).

The canonical observation preserves every vendor-specific field verbatim in
``vendor_specific`` so nothing is lost during normalization.
"""

from __future__ import annotations

from typing import Any

from universal_vendor.models import AssetType, UniversalObservation, Visibility
from universal_vendor.plugin import scrub_secrets
from .connector_plugin import MyVendorPluginConnector  # noqa: F401  (re-export)


class NormalizerMixin:
    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor,
            product=self.product,
            product_version=raw.get("product_version"),
            asset_id=raw.get("asset_id") or "myvendor",
            asset_type=AssetType.ROUTER.value,  # adjust per product
            crypto_type=raw.get("crypto_type", "algorithm"),
            algorithm=raw.get("algorithm"),
            protocol=raw.get("protocol"),
            certificate=raw.get("certificate"),
            configuration=raw.get("configuration"),
            source=self.plugin_id,
            confidence=raw.get("confidence", 0.85),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),  # preserved verbatim (spec §20)
        )
