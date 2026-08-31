"""Plugin registry + capability registry tests (spec §17, §18)."""

from __future__ import annotations

import pytest

from universal_vendor.models import PluginStatus, VendorCapabilities
from universal_vendor.plugins import build_registry
from universal_vendor.plugins.network import CiscoPlugin
from universal_vendor.registry import (
    CapabilityRegistry,
    DuplicatePluginError,
    UnknownPluginError,
    UntrustedPluginError,
)


def test_registry_builds_all_categories(registry):
    assert registry.count() >= 60
    categories = {cls.category.value for cls in registry.all()}
    for expected in ("network", "firewall", "load_balancer", "cloud", "pki",
                     "hsm", "identity", "database", "middleware", "os", "edr",
                     "siem", "devops", "container", "kubernetes", "saas"):
        assert expected in categories


def test_catalog_columns_cover_spec_18(registry):
    rows = registry.catalog()
    assert rows, "catalog must not be empty"
    required = {
        "plugin_id", "vendor", "product", "category", "version", "status",
        "supported_features", "minimum_version", "api_requirements",
        "auth_methods", "trusted",
    }
    for row in rows[:5]:
        assert required <= set(row)


def test_duplicate_plugin_rejected(registry):
    with pytest.raises(DuplicatePluginError):
        registry.register(CiscoPlugin)


def test_unknown_plugin(registry):
    with pytest.raises(UnknownPluginError):
        registry.get("does_not_exist")


def test_trusted_gating(registry):
    # bundled plugins are trusted and instantiable
    plugin = registry.instantiate("cisco_ios_xe", trusted_only=True)
    assert plugin.vendor == "Cisco"


def test_by_category_and_vendor(registry):
    firewalls = registry.by_category("firewall")
    assert all(cls.category.value == "firewall" for cls in firewalls)
    assert any(cls.plugin_id == "paloalto_panos" for cls in firewalls)
    cisco = registry.by_vendor("cisco")
    assert all(cls.vendor.lower() == "cisco" for cls in cisco)


def test_capability_registry_spec_17(registry):
    caps = CapabilityRegistry(plugins=registry.all())
    assert caps.supports("Cisco", "IOS-XE", "ssh_crypto")
    assert caps.supports("Palo Alto", "PAN-OS", "tls_inspection")
    assert not caps.supports("Cisco", "IOS-XE", "quantum_hsm")
    assert caps.lookup("cisco", "ios-xe") is not None


def test_capability_plugin_hook():
    caps = CiscoPlugin().capabilities()
    assert isinstance(caps, VendorCapabilities)
    assert caps.vendor == "Cisco"
    assert caps.supports("ssh_crypto")


def test_bundled_plugins_are_trusted(registry):
    # first-party plugins are trusted; untrusted gating still enforced for
    # anything flagged untrusted (see SDK test)
    assert all(cls.trusted for cls in registry.all())


def test_status_default_stable(registry):
    plugin = registry.get("mikrotik_routeros")
    assert plugin.status is PluginStatus.STABLE
