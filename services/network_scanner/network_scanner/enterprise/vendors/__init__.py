"""Multi-vendor network plugin system (Cisco, SNMP, generic vendor plugins)."""

from network_scanner.enterprise.vendors.base import (
    NetworkVendorPlugin,
    PluginRegistry,
    REGISTRY,
    register_plugin,
)
from network_scanner.enterprise.vendors import base, snmp  # noqa: F401  (registers plugins)
from network_scanner.enterprise.vendors import cisco, generic  # noqa: F401
from network_scanner.enterprise.vendors.cisco import CiscoPlugin
from network_scanner.enterprise.vendors.generic import GenericSNMPPlugin

__all__ = [
    "NetworkVendorPlugin",
    "PluginRegistry",
    "REGISTRY",
    "register_plugin",
    "CiscoPlugin",
    "GenericSNMPPlugin",
]
