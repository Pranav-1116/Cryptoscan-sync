"""§21/§22 Live CBOM + HBOM — one standard-based BOM for the whole estate.

The platform combines the CycloneDX 1.6 cryptography BOM (algorithms,
certificates, key metadata, protocols, libraries, providers,
implementations, relationships) with the hardware BOM (components,
firmware, BIOS, TPM, HSM, NIC, crypto capabilities) into a single
``bomFormat: CycloneDX`` document. OIDs come from the crypto registry
(§35 of the crypto spec); hardware components carry ``hwVersion``/``swVersion``
where the adapters provided them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from universal_platform.assets import PlatformAsset


class CombinedBomProducer:
    """Produce a combined CycloneDX CBOM + HBOM from platform assets."""

    def produce(self, assets: dict[str, PlatformAsset],
                relationships: Optional[list[dict[str, Any]]] = None,
                crypto_oids: Optional[dict[str, str]] = None) -> dict[str, Any]:
        oids = crypto_oids or {}
        components: list[dict[str, Any]] = []
        comp_ids: dict[str, str] = {}

        def add(comp_id: str, comp_type: str, name: str, **extra: Any) -> None:
            if comp_id in comp_ids:
                return
            comp: dict[str, Any] = {
                "type": comp_type, "name": name, "bom-ref": comp_id,
            }
            comp.update(extra)
            components.append(comp)
            comp_ids[comp_id] = comp_id

        for asset in assets.values():
            identity = asset.identity
            attrs = asset.attributes
            if asset.asset_type == "algorithm":
                add(identity, "cryptography", identity,
                    cryptography={"algorithm": {
                        "name": identity,
                        "oid": oids.get(identity, ""),
                        "properties": [{"name": "quantum_status",
                                        "value": str(attrs.get("quantum_status") or "")},
                                       {"name": "operation",
                                        "value": str(attrs.get("operation") or "")}]}})
            elif asset.asset_type == "certificate":
                add(identity, "cryptography", identity,
                    cryptography={"certificate": {
                        "subject": identity,
                        "properties": [
                            {"name": "signature_algorithm",
                             "value": str(attrs.get("signature_algorithm") or "")},
                            {"name": "public_key_algorithm",
                             "value": str(attrs.get("public_key_algorithm") or "")},
                            {"name": "expired",
                             "value": str(attrs.get("expired") or "")}]}})
            elif asset.asset_type == "crypto_library":
                add(identity, "library", identity,
                    properties=[{"name": "version",
                                 "value": str(attrs.get("version") or "")},
                                {"name": "provider",
                                 "value": str(attrs.get("provider") or "")}])
            elif asset.asset_type == "key_metadata":
                add(identity, "cryptography", identity,
                    cryptography={"algorithm": {"name": str(attrs.get("algorithm") or "")}},
                    properties=[{"name": "usage", "value": str(attrs.get("usage") or "")}])
            elif asset.asset_type in ("hsm", "tpm", "secure_element",
                                      "crypto_accelerator"):
                add(identity, "device", identity,
                    properties=[{"name": "hardware_type", "value": asset.asset_type},
                                {"name": "firmware",
                                 "value": str(attrs.get("firmware") or "")},
                                {"name": "crypto_capabilities",
                                 "value": ",".join(sorted(
                                     attrs.get("crypto_capabilities") or []))}])
            elif asset.asset_type == "firmware":
                add(identity, "firmware", identity,
                    properties=[{"name": "device",
                                 "value": str(attrs.get("device") or "")}])
            elif asset.asset_type in ("cpu", "gpu", "nic", "storage", "raid",
                                      "hba", "bios", "uefi", "bmc"):
                add(identity, "device", identity,
                    properties=[{"name": "hardware_type", "value": asset.asset_type}])
            else:
                add(identity, "application" if asset.domain == "application"
                    else "device", identity,
                    properties=[{"name": "domain", "value": asset.domain}])

        rels: list[dict[str, Any]] = []
        for rel in relationships or []:
            if rel["from"] in comp_ids and rel["to"] in comp_ids:
                rels.append({
                    "ref": rel["from"], "dependsOn": rel["to"],
                })
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:platform-{int(datetime.now().timestamp())}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "component": {"type": "platform", "name": "ZELNX platform"},
                "properties": [
                    {"name": "combined", "value": "cbom+hbom"},
                    {"name": "generator", "value": "universal_platform"},
                ],
            },
            "components": components,
            "dependencies": rels,
        }


def produce_combined_bom(assets: dict[str, PlatformAsset],
                         relationships: Optional[list[dict[str, Any]]] = None,
                         crypto_oids: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """Module-level entry point."""
    return CombinedBomProducer().produce(assets, relationships, crypto_oids)
