"""Hardware plugin package (§25).

hardware_plugins/: server / network / hsm / tpm / storage / gpu /
virtualization / embedded / iot / industrial — each plugin implements
detect(), identify(), inventory(), discover_firmware(), discover_crypto(),
discover_capabilities(), collect_evidence(), normalize(), health_check().
"""

from __future__ import annotations

from universal_vendor.hardware.plugins.gpu import (
    AmdGpuPlugin,
    IntelGpuPlugin,
    NvidiaGpuPlugin,
)
from universal_vendor.hardware.plugins.hsm import (
    EntrustNshieldHwPlugin,
    ThalesLunaHwPlugin,
    UtimacoHwPlugin,
)
from universal_vendor.hardware.plugins.industrial import (
    AbbPlcPlugin,
    RockwellPlcPlugin,
    SchneiderPlcPlugin,
    SiemensPlcPlugin,
)
from universal_vendor.hardware.plugins.iot import (
    CiscoIotGatewayPlugin,
    DellIotGatewayPlugin,
)
from universal_vendor.hardware.plugins.network import (
    AristaHwPlugin,
    CiscoHwPlugin,
    FortinetHwPlugin,
    JuniperHwPlugin,
)
from universal_vendor.hardware.plugins.server import (
    DellServerPlugin,
    HpeServerPlugin,
    IbmServerPlugin,
    LenovoServerPlugin,
    SupermicroServerPlugin,
)
from universal_vendor.hardware.plugins.storage import (
    DellEmeStoragePlugin,
    HpeStoragePlugin,
    NetappStoragePlugin,
)
from universal_vendor.hardware.plugins.tpm import (
    AmdFirmwareTpmPlugin,
    IntelPlatformTpmPlugin,
    TpmGenericPlugin,
)
from universal_vendor.hardware.plugins.virtualization import (
    HyperVHostPlugin,
    KvmHostPlugin,
    VmwareEsxiHwPlugin,
)
from universal_vendor.hardware.registry import build_hardware_registry

ALL_HARDWARE_PLUGINS: list[type] = [
    # compute
    DellServerPlugin, HpeServerPlugin, IbmServerPlugin, LenovoServerPlugin,
    SupermicroServerPlugin,
    NvidiaGpuPlugin, AmdGpuPlugin, IntelGpuPlugin,
    VmwareEsxiHwPlugin, HyperVHostPlugin, KvmHostPlugin,
    # network
    CiscoHwPlugin, JuniperHwPlugin, AristaHwPlugin, FortinetHwPlugin,
    # security
    ThalesLunaHwPlugin, EntrustNshieldHwPlugin, UtimacoHwPlugin,
    TpmGenericPlugin, IntelPlatformTpmPlugin, AmdFirmwareTpmPlugin,
    # storage
    DellEmeStoragePlugin, NetappStoragePlugin, HpeStoragePlugin,
    # IoT / industrial
    CiscoIotGatewayPlugin, DellIotGatewayPlugin,
    SiemensPlcPlugin, RockwellPlcPlugin, SchneiderPlcPlugin, AbbPlcPlugin,
]


def build_registry():
    return build_hardware_registry(ALL_HARDWARE_PLUGINS)


__all__ = ["ALL_HARDWARE_PLUGINS", "build_registry"]
