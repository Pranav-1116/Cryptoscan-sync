"""Node labels and identity properties for the CryptoScan graph."""

from __future__ import annotations

NODE_LABELS = (
    "CryptoAsset",
    "System",
    "BusinessProcess",
    "BusinessOwner",
    "ComplianceScope",
    "Certificate",
    "CloudResource",
    "Vendor",
)

IDENTITY_PROPERTY = {
    "CryptoAsset": "asset_id",
    "System": "system_id",
    "BusinessProcess": "process_id",
    "BusinessOwner": "owner_id",
    "ComplianceScope": "standard_name",
    "Certificate": "cert_id",
    "CloudResource": "resource_id",
    "Vendor": "vendor_id",
    "NetworkResource": "network_id",
}

KIND_PREFIX = {
    "System": "system",
    "CryptoAsset": "asset",
    "BusinessProcess": "process",
    "BusinessOwner": "owner",
    "ComplianceScope": "scope",
    "Certificate": "cert",
    "CloudResource": "cloud",
    "Vendor": "vendor",
    "NetworkResource": "network",
}
