"""Vendor plugin SDK tests (spec §19, §18 trust gating)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from universal_vendor.models import PluginStatus
from universal_vendor.registry import UntrustedPluginError
from universal_vendor.sdk import (
    ManifestError,
    PluginPackageError,
    load_plugin_package,
    parse_manifest,
)

TEMPLATE = Path(__file__).resolve().parents[1] / "sdk_template"


def test_template_layout_matches_spec_19():
    for expected in ("manifest.yaml", "connector.py", "discovery.py",
                     "normalizer.py", "schemas", "tests"):
        assert (TEMPLATE / expected).exists(), f"missing {expected}"


def test_parse_manifest_ok():
    manifest = parse_manifest(TEMPLATE)
    assert manifest["plugin_id"] == "my_vendor_product"
    assert manifest["vendor"] == "MyVendor"
    assert manifest["category"] == "network"
    assert manifest["trusted"] is False  # third-party default


def test_parse_manifest_missing_file():
    with pytest.raises(ManifestError):
        parse_manifest("/nonexistent/path/manifest.yaml")


def test_parse_manifest_bad_category(tmp_path):
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "plugin_id: x\nvendor: V\nproduct: P\ncategory: not_a_category\nversion: 1.0\n"
    )
    with pytest.raises(ManifestError):
        parse_manifest(manifest)


def test_load_plugin_package_registers_untrusted():
    registry = None
    from universal_vendor.registry import PluginRegistry

    registry = PluginRegistry()
    manifest, plugin = load_plugin_package(TEMPLATE, registry=registry)
    assert manifest["trusted"] is False
    assert registry.get("my_vendor_product") is not None
    # trust gate: untrusted plugin refuses automatic execution
    with pytest.raises(UntrustedPluginError):
        registry.instantiate("my_vendor_product", trusted_only=True)


def test_load_plugin_package_detects_and_discovers():
    _, plugin = load_plugin_package(TEMPLATE, register=False)
    context = {"banner": "MyVendor MyProduct v2.0",
               "config": "tls on\ncert server.pem\nAES-256-GCM",
               "asset_id": "unit"}
    detection = plugin.detect(context)
    assert detection.detected_vendor == "MyVendor"
    assert detection.confidence >= 0.5

    raw = plugin.collect_evidence(context)
    observations = plugin.normalize_all(raw)
    assert observations
    assert all(obs.vendor == "MyVendor" for obs in observations)
    algorithms = {o.algorithm for o in observations
                  if o.crypto_type == "algorithm"}
    assert algorithms, "expected algorithm observations"


def test_load_plugin_package_missing_init(tmp_path):
    bad = tmp_path / "bad_plugin"
    bad.mkdir()
    (bad / "manifest.yaml").write_text(
        "plugin_id: x\nvendor: V\nproduct: P\ncategory: network\nversion: 1.0\n"
    )
    with pytest.raises(PluginPackageError):
        load_plugin_package(bad)


def test_manifest_metadata_applied_to_class():
    _, plugin = load_plugin_package(TEMPLATE, register=False)
    assert plugin.status is PluginStatus.EXPERIMENTAL
    assert plugin.category.value == "network"
    assert plugin.version == "1.0.0"


def test_copy_template_remains_loadable(tmp_path):
    """A vendor copies the template, tweaks the manifest, and it still loads."""
    copy = tmp_path / "copied_plugin"
    shutil.copytree(TEMPLATE, copy)
    (copy / "manifest.yaml").write_text(
        (copy / "manifest.yaml").read_text().replace(
            "trusted: false", "trusted: true")
    )
    manifest, plugin = load_plugin_package(copy, register=False)
    assert manifest["trusted"] is True
    assert plugin.vendor == "MyVendor"
