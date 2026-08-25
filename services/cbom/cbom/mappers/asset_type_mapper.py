"""Map CryptoScan asset records onto CycloneDX crypto `assetType`."""

from __future__ import annotations

from typing import Any


def map_asset_type(asset: Any) -> str:
    if isinstance(asset, dict):
        explicit = asset.get("asset_type") or (asset.get("cryptoProperties") or {}).get("assetType")
        if explicit:
            return _normalize(explicit)
        if asset.get("library") or asset.get("manager") or asset.get("vendor"):
            return "related-crypto-material"
        name = str(asset.get("type") or "")
        if "cert" in name.lower():
            return "certificate"
        if "library" in name.lower() or "package" in name.lower():
            return "related-crypto-material"
    else:
        kind = str(getattr(asset, "asset_type", "") or "")
        if kind:
            return _normalize(kind)
        if getattr(asset, "library", None) or getattr(asset, "vendor", None):
            return "related-crypto-material"
    return "algorithm"


def _normalize(value: str) -> str:
    raw = str(value).strip().lower().replace("_", "-")
    aliases = {
        "algorithm-use": "algorithm",
        "algo": "algorithm",
        "library": "related-crypto-material",
        "related-crypto-material": "related-crypto-material",
        "certificate": "certificate",
        "protocol": "protocol",
        "cert": "certificate",
    }
    return aliases.get(raw, raw or "algorithm")
