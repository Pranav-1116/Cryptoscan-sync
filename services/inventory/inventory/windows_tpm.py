"""One fixed-size TBS public metadata call; no TPM contexts or commands.

Reserved/interface/revision fields are intentionally neither interpreted nor
emitted. Real Windows/native lifecycle/cancellation qualification is pending.
"""

import ctypes as c
import hashlib
import sys
from shared_models.windows_tpm import WindowsTpmFact, device_resource, device_bytes


class DeviceInfo(c.Structure):
    _fields_ = [
        ("structure_version", c.c_uint32),
        ("tpm_version", c.c_uint32),
        ("reserved_interface", c.c_uint32),
        ("reserved_revision", c.c_uint32),
    ]


def _api():
    from inventory.host import Refused

    if sys.platform != "win32":
        raise ValueError("Native Windows required")
    try:
        api = c.WinDLL("tbs.dll", use_last_error=True, winmode=0x800)
        api.Tbsi_GetDeviceInfo.argtypes = [c.c_uint32, c.c_void_p]
        api.Tbsi_GetDeviceInfo.restype = c.c_uint32  # TBS_RESULT, not BOOL/GetLastError.
        return api
    except (OSError, AttributeError):
        raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE") from None


def collect_device(item, limit, charge):
    from inventory.host import Refused

    device_resource(item.path)
    consumed = 0

    def claim(size):
        nonlocal consumed
        if size > limit - consumed:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        charge(size)
        consumed += size

    claim(c.sizeof(DeviceInfo))
    api = _api()
    info = DeviceInfo()  # Entirely output per SDK prototype. No context-version input.
    status = api.Tbsi_GetDeviceInfo(c.sizeof(info), c.byref(info)) & 0xFFFFFFFF
    if status == 0x8028400F:  # TBS_E_TPM_NOT_FOUND; interface availability, not physical absence proof.
        raise FileNotFoundError("OS TPM metadata unavailable")
    if status != 0:
        raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE")
    # SDK header documents structure version 1. Unknown layouts must not be guessed.
    if info.structure_version != 1 or info.tpm_version not in {1, 2}:
        raise Refused("UNSUPPORTED", "INVALID_FORMAT")
    specification = {1: "1.2", 2: "2.0"}[info.tpm_version]
    raw = device_bytes(specification)
    claim(len(raw))
    fact = WindowsTpmFact(
        kind="WINDOWS_TPM_METADATA", tpm_specification=specification, interface_sha256=hashlib.sha256(raw).hexdigest()
    )
    return raw, [fact]
