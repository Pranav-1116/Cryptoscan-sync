"""Plugin registry + vendor capability registry (spec §17, §18).

The plugin registry is the central source of truth for every vendor plugin:
PLUGIN_ID / VENDOR / PRODUCT / CATEGORY / VERSION / STATUS /
SUPPORTED_FEATURES / MINIMUM_VERSION / API_REQUIREMENTS / AUTH_METHODS.

Trust gating (spec §18): untrusted plugins may be registered (they are
inspectable) but cannot be selected for automatic execution.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from universal_vendor.models import VendorCapabilities, VendorCategory
from universal_vendor.plugin import UniversalVendorPlugin


class DuplicatePluginError(Exception):
    """Raised when a plugin_id is registered twice."""


class UnknownPluginError(Exception):
    """Raised when a plugin_id is not registered."""


class UntrustedPluginError(Exception):
    """Raised when an untrusted plugin would auto-run (spec §18)."""


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, type[UniversalVendorPlugin]] = {}

    def register(self, plugin_cls: type[UniversalVendorPlugin]) -> type[UniversalVendorPlugin]:
        plugin_id = plugin_cls.plugin_id
        if not plugin_id:
            raise ValueError(f"plugin {plugin_cls.__name__} has no plugin_id")
        if plugin_id in self._plugins:
            raise DuplicatePluginError(f"plugin {plugin_id!r} already registered")
        self._plugins[plugin_id] = plugin_cls
        return plugin_cls

    def get(
        self,
        plugin_id: str,
        *,
        trusted_only: bool = False,
    ) -> type[UniversalVendorPlugin]:
        if plugin_id not in self._plugins:
            raise UnknownPluginError(f"unknown plugin {plugin_id!r}")
        plugin_cls = self._plugins[plugin_id]
        if trusted_only and not plugin_cls.trusted:
            raise UntrustedPluginError(
                f"plugin {plugin_id!r} is untrusted and cannot auto-run"
            )
        return plugin_cls

    def instantiate(
        self,
        plugin_id: str,
        *,
        trusted_only: bool = True,
        **options: Any,
    ) -> UniversalVendorPlugin:
        return self.get(plugin_id, trusted_only=trusted_only)(**options)

    def all(self) -> list[type[UniversalVendorPlugin]]:
        return sorted(self._plugins.values(), key=lambda cls: (cls.category.value, cls.plugin_id))

    def by_category(self, category: VendorCategory | str) -> list[type[UniversalVendorPlugin]]:
        wanted = category.value if isinstance(category, VendorCategory) else str(category)
        return [cls for cls in self.all() if cls.category.value == wanted]

    def by_vendor(self, vendor: str) -> list[type[UniversalVendorPlugin]]:
        wanted = vendor.lower()
        return [cls for cls in self.all() if cls.vendor.lower() == wanted]

    def plugin_ids(self) -> list[str]:
        return sorted(self._plugins.keys())

    def catalog(self) -> list[dict[str, Any]]:
        """The full registry catalog (spec §18 columns)."""
        rows = []
        for cls in self.all():
            rows.append(
                {
                    "plugin_id": cls.plugin_id,
                    "vendor": cls.vendor,
                    "product": cls.product,
                    "category": cls.category.value,
                    "version": cls.version,
                    "status": cls.status.value,
                    "supported_features": list(cls.supported_features),
                    "minimum_version": cls.minimum_version,
                    "api_requirements": list(cls.api_requirements),
                    "auth_methods": list(cls.auth_methods),
                    "trusted": cls.trusted,
                }
            )
        return rows

    def count(self) -> int:
        return len(self._plugins)


class CapabilityRegistry:
    """Spec §17 — what each vendor/product can actually discover."""

    def __init__(self, plugins: Iterable[type[UniversalVendorPlugin]] | None = None) -> None:
        self._capabilities: dict[tuple[str, str], VendorCapabilities] = {}
        for cls in plugins or ():
            self.register(cls().capabilities())

    def register(self, capabilities: VendorCapabilities) -> None:
        key = (capabilities.vendor.lower(), capabilities.product.lower())
        self._capabilities[key] = capabilities

    def register_plugin(self, plugin_cls: type[UniversalVendorPlugin]) -> None:
        self.register(plugin_cls.capabilities())

    def lookup(self, vendor: str, product: str) -> Optional[VendorCapabilities]:
        return self._capabilities.get((vendor.lower(), product.lower()))

    def supports(self, vendor: str, product: str, capability: str) -> bool:
        caps = self.lookup(vendor, product)
        return bool(caps and caps.supports(capability))

    def capabilities_for(self, vendor: str, product: str) -> list[str]:
        caps = self.lookup(vendor, product)
        return list(caps.capabilities) if caps else []

    def all(self) -> list[VendorCapabilities]:
        return list(self._capabilities.values())

    def count(self) -> int:
        return len(self._capabilities)
