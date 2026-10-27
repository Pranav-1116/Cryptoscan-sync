"""Universal hardware plugin framework (§25).

Same universal plugin architecture used for vendors: every hardware plugin
implements detect() / identify() / inventory() / discover_firmware() /
discover_crypto() / discover_capabilities() / collect_evidence() /
normalize() / health_check(). Plugins are read-only and metadata-only by
contract; the registry tracks them by hardware category.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareIdentity,
    HardwareObservation,
    HardwareType,
)
from universal_vendor.plugin import scrub_secrets


class HardwarePluginRegistry:
    """Registry of hardware plugins, grouped by hardware category."""

    def __init__(self) -> None:
        self._plugins: dict[str, type["UniversalHardwarePlugin"]] = {}

    def register(self, plugin_cls: type["UniversalHardwarePlugin"]) -> type["UniversalHardwarePlugin"]:
        plugin_id = plugin_cls.plugin_id
        if not plugin_id:
            raise ValueError(f"hardware plugin {plugin_cls.__name__} has no plugin_id")
        if plugin_id in self._plugins:
            raise ValueError(f"hardware plugin {plugin_id!r} already registered")
        self._plugins[plugin_id] = plugin_cls
        return plugin_cls

    def get(self, plugin_id: str) -> type["UniversalHardwarePlugin"]:
        if plugin_id not in self._plugins:
            raise KeyError(f"unknown hardware plugin {plugin_id!r}")
        return self._plugins[plugin_id]

    def instantiate(self, plugin_id: str) -> "UniversalHardwarePlugin":
        return self.get(plugin_id)()

    def all(self) -> list[type["UniversalHardwarePlugin"]]:
        return sorted(self._plugins.values(),
                      key=lambda cls: (cls.category.value, cls.plugin_id))

    def by_category(self, category: HardwareType | str) -> list[type["UniversalHardwarePlugin"]]:
        wanted = category.value if isinstance(category, HardwareType) else str(category)
        return [cls for cls in self.all() if cls.category.value == wanted]

    def by_manufacturer(self, manufacturer: str) -> list[type["UniversalHardwarePlugin"]]:
        wanted = manufacturer.lower()
        return [cls for cls in self.all() if cls.manufacturer.lower() == wanted]

    def plugin_ids(self) -> list[str]:
        return sorted(self._plugins)

    def count(self) -> int:
        return len(self._plugins)


class UniversalHardwarePlugin(ABC):
    """Common hardware plugin contract (spec §25)."""

    plugin_id: str = ""
    manufacturer: str = ""                 # Dell, HPE, Cisco, Thales, …
    product: str = ""
    category: HardwareType = HardwareType.OTHER
    discovery_methods: list[str] = ["agent", "network", "api"]
    read_only: bool = True                 # never violated (§23)

    # ── detection ──────────────────────────────────────────────────────

    @abstractmethod
    def detect(self, context: dict[str, Any]) -> dict[str, Any]:
        """Return {detected: bool, manufacturer, model, confidence}."""

    # ── identity (§3) ──────────────────────────────────────────────────

    @abstractmethod
    def identify(self, context: dict[str, Any]) -> HardwareIdentity:
        """Build the canonical multi-signal hardware identity."""

    # ── discovery ──────────────────────────────────────────────────────

    def inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Raw inventory records (chassis, slots, components)."""
        return []

    def discover_firmware(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Raw firmware observations: {component, version}."""
        return []

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Raw crypto-relevant hardware observations."""
        return []

    def discover_capabilities(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Raw crypto capability records (supported vs used)."""
        return []

    def collect_evidence(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        raw: list[dict[str, Any]] = []
        raw.extend(self.inventory(context))
        raw.extend(self.discover_firmware(context))
        raw.extend(self.discover_crypto(context))
        raw.extend(self.discover_capabilities(context))
        return raw

    # ── normalization ──────────────────────────────────────────────────

    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> HardwareObservation:
        """Normalize one raw record into the canonical shape."""

    def normalize_all(self, raw_items: Iterable[dict[str, Any]]) -> list[HardwareObservation]:
        return [self.normalize(item) for item in raw_items]

    # ── health (§25) ───────────────────────────────────────────────────

    def health_check(self, context: dict[str, Any]) -> dict[str, Any]:
        return {"plugin_id": self.plugin_id, "ok": True,
                "read_only": self.read_only}

    # ── shared helpers ─────────────────────────────────────────────────

    def _raw(
        self,
        *,
        asset_id: str,
        manufacturer: str = "",
        model: str = "",
        device_type: str = "",
        **extra: Any,
    ) -> dict[str, Any]:
        item: dict[str, Any] = {
            "asset_id": asset_id,
            "manufacturer": manufacturer or self.manufacturer,
            "model": model or self.product,
            "device_type": device_type or self.category.value,
            "source": self.plugin_id,
        }
        item.update(extra)
        return item

    def _detect_banner(
        self,
        context: dict[str, Any],
        patterns: Iterable[tuple[str, str, str]],
    ) -> dict[str, Any]:
        """patterns: (regex, manufacturer, model). Highest-weight match wins."""
        import re

        import json

        haystacks: list[str] = []
        for field in ("banner", "ssh_banner", "server_header", "config",
                      "snmp_sysdescr", "dmi", "api_metadata", "manufacturer",
                      "model", "device_type"):
            value = context.get(field)
            if isinstance(value, str) and value.strip():
                haystacks.append(value)
            elif isinstance(value, (dict, list, tuple)) and value:
                # Structured DMI/API evidence is as authoritative for vendor
                # matching as a banner. Serialize only for matching; the raw
                # context is never copied into a plugin detection result.
                haystacks.append(json.dumps(value, sort_keys=True, default=str))
        joined = " ".join(haystacks)
        for regex, manufacturer, model in patterns:
            if re.search(regex, joined, re.IGNORECASE):
                return {"detected": True, "manufacturer": manufacturer,
                        "model": model, "confidence": HardwareConfidence.HIGH.value}
        return {"detected": False, "manufacturer": "", "model": "",
                "confidence": HardwareConfidence.LOW.value}

    @staticmethod
    def _scrubbed(item: dict[str, Any]) -> dict[str, Any]:
        return scrub_secrets(item)

    # keys consumed into the canonical HardwareObservation fields — anything
    # else in a raw record is vendor-specific and belongs in vendor_specific
    _CANONICAL_RAW_KEYS = frozenset({
        "asset_id", "manufacturer", "model", "device_type", "source",
        "serial_reference", "firmware", "hardware_revision", "environment",
        "region", "confidence", "visibility", "cpu", "tpm", "hsm",
        "capabilities", "firmware_components", "evidence", "vendor_specific",
    })

    def _canonical_vendor_specific(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Vendor-specific fields, scrubbed of secret material (§25)."""
        nested = raw.get("vendor_specific")
        if isinstance(nested, dict):
            return self._scrubbed(nested)
        return self._scrubbed({k: v for k, v in raw.items()
                               if k not in self._CANONICAL_RAW_KEYS})
