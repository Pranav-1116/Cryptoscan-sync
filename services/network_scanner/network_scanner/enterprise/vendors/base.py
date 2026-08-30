"""NetworkVendorPlugin — the multi-vendor plugin contract.

Every vendor integration (Cisco, Juniper, Palo Alto, Fortinet, Check Point,
F5, Arista, Huawei, MikroTik, Ubiquiti, VMware, generic SNMP, cloud LB…)
implements the same seven capabilities; the discovery engine drives plugins
by capability, never by vendor name.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from network_scanner.enterprise.credentials import CredentialRef, CredentialVault


class NetworkVendorPlugin(ABC):
    """Vendor-neutral plugin contract."""

    vendor: str = "generic"
    device_types: tuple[str, ...] = ("unknown",)

    def __init__(self, *, vault: CredentialVault | None = None, **options: Any) -> None:
        self.vault = vault or CredentialVault()
        self.options = dict(options)

    # ------------------------------------------------------------------ API

    @abstractmethod
    def discover_devices(self, targets: list[str], **kw: Any) -> list[dict[str, Any]]:
        """Return raw device records (identity, addresses, model, OS…)."""

    @abstractmethod
    def collect_inventory(self, device: dict[str, Any], **kw: Any) -> dict[str, Any]:
        """Structured inventory for one device (interfaces, versions, licenses)."""

    @abstractmethod
    def collect_crypto_configuration(self, device: dict[str, Any], **kw: Any) -> dict[str, Any]:
        """VPN / SSH / TLS / routing-auth crypto configuration (metadata only)."""

    @abstractmethod
    def collect_certificates(self, device: dict[str, Any], **kw: Any) -> list[dict[str, Any]]:
        """Certificates and trust anchors the device uses."""

    @abstractmethod
    def collect_protocols(self, device: dict[str, Any], **kw: Any) -> list[dict[str, Any]]:
        """Protocol observations with classification status."""

    @abstractmethod
    def collect_topology(self, devices: list[dict[str, Any]], **kw: Any) -> list[dict[str, Any]]:
        """Topology relationships (CONNECTED_TO / ROUTES_TO / USES_VPN …)."""

    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize a raw device record into the shared asset schema."""

    # ------------------------------------------------------------------ helpers

    def credential_for(self, device: dict[str, Any], cred_type: str) -> CredentialRef | None:
        """Pick a credential ref for a device from options, if configured."""
        refs = self.options.get("credentials") or {}
        ref = refs.get(cred_type) or refs.get(device.get("vendor", "").lower())
        if ref is None:
            return None
        if isinstance(ref, dict):
            return CredentialRef(type=cred_type, **ref)
        return CredentialRef(type=cred_type, ref=str(ref))

    def can_handle(self, device_type: str) -> bool:
        return device_type in self.device_types or "unknown" in self.device_types


class PluginRegistry:
    """Registry of NetworkVendorPlugin classes, keyed by vendor name."""

    def __init__(self) -> None:
        self._plugins: dict[str, type[NetworkVendorPlugin]] = {}

    def register(self, plugin_cls: type[NetworkVendorPlugin]) -> type[NetworkVendorPlugin]:
        self._plugins[plugin_cls.vendor.lower()] = plugin_cls
        return plugin_cls

    def get(self, vendor: str) -> type[NetworkVendorPlugin] | None:
        return self._plugins.get(str(vendor).strip().lower())

    def names(self) -> list[str]:
        return sorted(self._plugins)

    def instantiate(self, vendor: str, **options: Any) -> NetworkVendorPlugin:
        cls = self.get(vendor)
        if cls is None:
            raise KeyError(f"no vendor plugin registered for '{vendor}' (have: {', '.join(self.names())})")
        return cls(**options)


REGISTRY = PluginRegistry()


def register_plugin(plugin_cls: type[NetworkVendorPlugin]) -> type[NetworkVendorPlugin]:
    return REGISTRY.register(plugin_cls)
