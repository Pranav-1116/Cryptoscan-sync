"""Read default legacy CSP label only; no context/provider/key acquisition."""

import ctypes as c
import hashlib
import sys
from shared_models.windows_capi import WindowsCapiFact, PROVIDER_TYPES, provider_resource, provider_bytes

MAX_NAME_BYTES = 512


def _api():
    from inventory.host import Refused

    if sys.platform != "win32":
        raise ValueError("Native Windows required")
    try:
        api = c.WinDLL("advapi32.dll", use_last_error=True, winmode=0x800)
        api.CryptGetDefaultProviderW.argtypes = [
            c.c_uint32,
            c.POINTER(c.c_uint32),
            c.c_uint32,
            c.POINTER(c.c_uint16),
            c.POINTER(c.c_uint32),
        ]
        api.CryptGetDefaultProviderW.restype = c.c_int32  # BOOL: GetLastError only on FALSE.
        return api
    except (AttributeError, OSError):
        raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE") from None


def _error():
    from inventory.host import Refused

    code = c.get_last_error() & 0xFFFFFFFF
    if code == 5:
        raise PermissionError("Default-provider metadata denied")
    if code in {2, 0x80090013}:
        raise FileNotFoundError("Default-provider metadata unavailable")
    if code == 234:
        raise Refused("INVALID", "INPUT_CHANGED")
    raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE")


def collect_default_provider(item, limit, charge):
    from inventory.host import Refused

    selected = PROVIDER_TYPES[provider_resource(item.path)]
    consumed = 0

    def claim(size):
        nonlocal consumed
        if size > limit - consumed:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        charge(size)
        consumed += size

    api = None
    names = []
    for _ in range(2):
        claim(c.sizeof(c.c_uint32))
        if api is None:
            api = _api()
        size = c.c_uint32(0)
        # NULL reserved, CRYPT_USER_DEFAULT only. Lengths are BYTES, not wchar count.
        if not api.CryptGetDefaultProviderW(selected, None, 2, None, c.byref(size)):
            _error()
        capacity = size.value
        if capacity > MAX_NAME_BYTES:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        if capacity < 4 or capacity % 2:
            raise ValueError("Invalid CAPI provider-name byte size")
        claim(capacity)
        buffer = (c.c_uint16 * (capacity // 2))()
        if not api.CryptGetDefaultProviderW(selected, None, 2, buffer, c.byref(size)):
            _error()
        if size.value < 4 or size.value > capacity or size.value % 2:
            raise ValueError("Invalid returned CAPI length")
        raw = c.string_at(buffer, size.value)
        if raw[-2:] != b"\0\0":
            raise ValueError("Unterminated CAPI label")
        name = raw[:-2].decode("utf-16-le", errors="strict")
        if "\0" in name:
            raise ValueError("Embedded NUL in CAPI label")
        names.append(name)
    if names[0] != names[1]:
        raise Refused("INVALID", "INPUT_CHANGED")
    raw = provider_bytes(selected, names[1])
    claim(len(raw))
    fact = WindowsCapiFact(
        kind="WINDOWS_CAPI_DEFAULT_PROVIDER",
        provider_type=selected,
        provider_name=names[1],
        identity_key=f"windows-capi:current-user:{selected}:default-provider",
        interface_sha256=hashlib.sha256(raw).hexdigest(),
    )
    return raw, [fact]
