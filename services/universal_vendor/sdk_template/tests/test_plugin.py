"""Bundled test suite for the MyVendor plugin (spec §19 tests/)."""

from __future__ import annotations

from universal_vendor.plugins import build_registry
from universal_vendor.sdk import load_plugin_package

PLUGIN_DIR = __file__.rsplit("/tests", 1)[0]


def test_load_package_registers_plugin():
    manifest, plugin = load_plugin_package(PLUGIN_DIR, register=False)
    assert manifest["plugin_id"] == "my_vendor_product"
    assert plugin.vendor == "MyVendor"
    assert plugin.product == "MyProduct"


def test_trust_gating_defaults_to_untrusted():
    manifest, _ = load_plugin_package(PLUGIN_DIR, register=False)
    assert manifest["trusted"] is False  # third-party default (spec §18)


def test_detect_and_discover():
    _, plugin = load_plugin_package(PLUGIN_DIR, register=False)
    context = {
        "banner": "MyVendor MyProduct v1.0",
        "config": "tls on\ncert server.pem\nAES-256-GCM enabled",
        "asset_id": "unit-test",
    }
    detection = plugin.detect(context)
    assert detection.detected_vendor == "MyVendor"
    assert detection.confidence >= 0.5

    raw = plugin.collect_evidence(context)
    observations = plugin.normalize_all(raw)
    assert observations, "expected at least one observation"
    assert all(obs.vendor == "MyVendor" for obs in observations)
    algorithms = {obs.algorithm for obs in observations
                  if obs.crypto_type == "algorithm"}
    assert "AES" in algorithms or "AES-256-GCM" in algorithms


def test_register_in_registry_with_trust_gate():
    registry = build_registry()
    manifest, plugin = load_plugin_package(PLUGIN_DIR, registry=registry)
    assert registry.get("my_vendor_product") is not None
    # untrusted -> trusted_only selection must raise
    import pytest

    from universal_vendor.registry import UntrustedPluginError

    with pytest.raises(UntrustedPluginError):
        registry.instantiate("my_vendor_product", trusted_only=True)
