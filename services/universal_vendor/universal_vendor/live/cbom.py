"""Live Vendor CBOM (24/7 spec §26).

Vendor Event → Event Log → State Transition → CBOM Materializer → LIVE
VENDOR CBOM. Every event (VENDOR_DISCOVERED, ASSET_DISCOVERED,
CONFIG_CHANGED, FIRMWARE_CHANGED, CERTIFICATE_CHANGED, CRYPTO_CHANGED,
VPN_CHANGED, KEY_CHANGED, …) is materialized into the canonical CBOM
component set, and each materialization is versioned.
"""

from __future__ import annotations

from typing import Any, Optional

from universal_vendor.live.events import UniversalVendorEvent

try:  # guard: cbom service may not be importable in minimal deployments
    from cbom.generator import CbomGenerator

    _HAS_CBOM = True
except Exception:  # pragma: no cover
    CbomGenerator = None  # type: ignore[assignment]
    _HAS_CBOM = False


class LiveCbom:
    """Event-sourced vendor CBOM materializer.

    Component key = (asset_id, algorithm, event_type) so repeated events of
    the same kind update rather than duplicate while distinct crypto-surface
    changes stay distinct; each materialize() bumps the document version.
    """

    def __init__(self) -> None:
        self._components: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._event_log: list[dict[str, Any]] = []
        self._version = 1

    def materialize(self, event: UniversalVendorEvent) -> dict[str, Any]:
        """Apply one vendor event to the CBOM state. Returns the event record."""
        record = event.to_dict()
        self._event_log.append(record)
        if event.event_type == "ASSET_REMOVED":
            self._remove_asset(event)
        else:
            self._upsert_components(event)
        self._version += 1
        return record

    def _upsert_components(self, event: UniversalVendorEvent) -> None:
        asset_id = event.asset_id or f"{event.vendor}:{event.product}"
        algorithms = event.vendor_metadata.get("algorithms") or []
        if not algorithms:
            algorithms = [event.vendor_metadata.get("algorithm") or "unknown"]
        event_type = event.event_type.value if hasattr(event.event_type, "value") \
            else str(event.event_type)
        for algorithm in algorithms:
            key = (asset_id, str(algorithm), event_type)
            self._components[key] = {
                "type": "crypto-asset",
                "group": event.asset_type or "other",
                "name": asset_id,
                "version": event.product_version or "unknown",
                "purl": f"pkg:vendor/{event.vendor.lower()}/{event.product.lower()}",
                "properties": [
                    {"name": "vendor", "value": event.vendor},
                    {"name": "product", "value": event.product},
                    {"name": "algorithm", "value": str(algorithm)},
                    {"name": "source", "value": event.source},
                    {"name": "evidence_reference",
                     "value": event.evidence_reference or ""},
                ],
                "bom-ref": f"{asset_id}:{algorithm}",
            }

    def _remove_asset(self, event: UniversalVendorEvent) -> None:
        asset_id = event.asset_id or f"{event.vendor}:{event.product}"
        for key in [k for k in self._components if k[0] == asset_id]:
            del self._components[key]

    # ── output ────────────────────────────────────────────────────────

    def components(self) -> list[dict[str, Any]]:
        return list(self._components.values())

    def event_log(self) -> list[dict[str, Any]]:
        return list(self._event_log)

    def version(self) -> int:
        return self._version

    def generate_document(self, *, name: str = "live-vendor-cbom",
                          tool_version: str = "universal-vendor-live") -> dict[str, Any]:
        """Serialize to CycloneDX via the shared CbomGenerator when present."""
        if not _HAS_CBOM:
            return {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": self._version,
                "name": name,
                "components": self.components(),
                "note": "cbom service unavailable; emitted canonical components",
            }
        records = [self._component_as_record(c) for c in self.components()]
        return CbomGenerator().from_records(
            records,
            name=name,
            version=f"v{self._version}",
            tool_version=tool_version,
        )

    @staticmethod
    def _component_as_record(component: dict[str, Any]) -> dict[str, Any]:
        props = {p["name"]: p["value"] for p in component.get("properties", [])}
        return {
            "vendor": props.get("vendor", "unknown"),
            "product": props.get("product", "unknown"),
            "algorithm": props.get("algorithm", "unknown"),
            "source": props.get("source", "unknown"),
            "asset_id": component["name"],
            "product_version": component.get("version"),
            "purpose": "vendor-crypto",
            "file_path": "",
            "line_number": None,
            "mode": None,
            "key_size": None,
            "nist_status": None,
            "quantum_vulnerable": None,
            "pqc_replacement": None,
            "finding_data": {},
        }
