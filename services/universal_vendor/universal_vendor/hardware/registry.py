"""Hardware plugin registry — same universal architecture as vendors (§25)."""

from __future__ import annotations

from typing import Iterable, Type

from universal_vendor.hardware.plugin import (
    HardwarePluginRegistry,
    UniversalHardwarePlugin,
)


def build_hardware_registry(
    plugin_classes: Iterable[Type[UniversalHardwarePlugin]],
) -> HardwarePluginRegistry:
    registry = HardwarePluginRegistry()
    for plugin_cls in plugin_classes:
        registry.register(plugin_cls)
    return registry
