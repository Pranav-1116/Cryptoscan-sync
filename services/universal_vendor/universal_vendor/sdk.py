"""Vendor plugin SDK — manifest parsing and plugin package loading (spec §19).

A third-party vendor plugin is a directory containing ``manifest.yaml`` plus
Python modules:

    vendor_plugin/
        manifest.yaml        # plugin metadata + trust declaration
        __init__.py          # package marker (relative imports inside)
        connector.py         # connection/credential validation
        discovery.py         # inventory / configuration / crypto / certificates
        normalizer.py        # raw -> UniversalObservation
        schemas/             # JSON Schemas for the raw records
        tests/               # pytest suite bundled with the plugin

``load_plugin_package(path)`` parses the manifest, imports the modules and
registers the plugin class into a :class:`PluginRegistry` — respecting the
trust flag (untrusted plugins can be inspected but never auto-run).
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from typing import Any, Optional

import yaml

from universal_vendor.models import PluginStatus, VendorCategory
from universal_vendor.plugin import UniversalVendorPlugin
from universal_vendor.registry import PluginRegistry

MANIFEST_FILENAME = "manifest.yaml"


class ManifestError(Exception):
    """Raised when a plugin manifest is missing or invalid."""


class PluginPackageError(Exception):
    """Raised when a plugin package cannot be imported or registered."""


def parse_manifest(path: str | Path) -> dict[str, Any]:
    """Parse and validate a vendor plugin ``manifest.yaml``."""
    manifest_path = Path(path)
    if manifest_path.is_dir():
        manifest_path = manifest_path / MANIFEST_FILENAME
    if not manifest_path.exists():
        raise ManifestError(f"manifest not found: {manifest_path}")
    with manifest_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ManifestError(f"manifest {manifest_path} must be a YAML mapping")
    required = ("plugin_id", "vendor", "product", "category", "version")
    missing = [key for key in required if not data.get(key)]
    if missing:
        raise ManifestError(f"manifest {manifest_path} missing: {', '.join(missing)}")
    category = data["category"]
    if category not in {member.value for member in VendorCategory}:
        raise ManifestError(
            f"manifest {manifest_path} has unknown category {category!r}"
        )
    data.setdefault("status", "EXPERIMENTAL")
    if data["status"] not in {status.value for status in PluginStatus}:
        raise ManifestError(f"manifest {manifest_path} has unknown status {data['status']!r}")
    data.setdefault("trusted", False)  # third-party plugins default to untrusted
    return data


def _package_name(package_dir: Path) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_]", "_", package_dir.name) or "plugin"
    return f"vendor_plugin_{sanitized}"


def load_plugin_package(
    path: str | Path,
    *,
    registry: Optional[PluginRegistry] = None,
    register: bool = True,
) -> tuple[dict[str, Any], UniversalVendorPlugin]:
    """Load a plugin package from a directory.

    Returns ``(manifest, plugin_instance)``. The plugin class must inherit
    :class:`UniversalVendorPlugin` and implement ``detect``, ``validate_connection``
    and ``normalize``.

    Registration uses the manifest ``trusted`` flag — untrusted plugins are
    registered but gated against automatic execution (spec §18).
    """
    package_dir = Path(path)
    if not package_dir.is_dir():
        raise PluginPackageError(f"plugin package directory not found: {package_dir}")
    manifest = parse_manifest(package_dir)

    package_name = _package_name(package_dir)
    if package_name in sys.modules:
        del sys.modules[package_name]
    init_file = package_dir / "__init__.py"
    if not init_file.exists():
        raise PluginPackageError(
            f"plugin package {package_dir} is missing __init__.py"
        )
    spec = importlib.util.spec_from_file_location(
        package_name, init_file, submodule_search_locations=[str(package_dir)]
    )
    if spec is None or spec.loader is None:
        raise PluginPackageError(f"cannot load plugin package {package_dir}")
    package = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = package
    spec.loader.exec_module(package)

    # Search every top-level .py module (skipping tests/) for the plugin class.
    plugin_cls: Optional[type[UniversalVendorPlugin]] = None
    for module_path in sorted(package_dir.glob("*.py")):
        if module_path.name == "__init__.py":
            continue
        module_name = f"{package_name}.{module_path.stem}"
        if module_name in sys.modules:
            del sys.modules[module_name]
        try:
            module = __import__(module_name, fromlist=["*"])
        except Exception as exc:  # pragma: no cover - defensive
            raise PluginPackageError(
                f"failed importing {module_name}: {exc}"
            ) from exc
        for attr in vars(module).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, UniversalVendorPlugin)
                and attr is not UniversalVendorPlugin
                and getattr(attr, "plugin_id", None) == manifest["plugin_id"]
            ):
                plugin_cls = attr
                break
        if plugin_cls is not None:
            break
    if plugin_cls is None:
        raise PluginPackageError(
            f"no UniversalVendorPlugin subclass with plugin_id "
            f"{manifest['plugin_id']!r} found in {package_dir}"
        )

    # Apply manifest metadata onto the class (trust declaration included).
    plugin_cls.plugin_id = manifest["plugin_id"]
    plugin_cls.vendor = manifest["vendor"]
    plugin_cls.product = manifest["product"]
    plugin_cls.category = VendorCategory(manifest["category"])
    plugin_cls.version = str(manifest["version"])
    plugin_cls.status = PluginStatus(manifest["status"])
    plugin_cls.supported_features = list(manifest.get("supported_features", []))
    plugin_cls.minimum_version = str(manifest.get("minimum_version", ""))
    plugin_cls.api_requirements = list(manifest.get("api_requirements", []))
    plugin_cls.auth_methods = list(manifest.get("auth_methods", []))
    plugin_cls.trusted = bool(manifest.get("trusted", False))

    instance = plugin_cls()
    if registry is not None and register:
        registry.register(plugin_cls)
    return manifest, instance
