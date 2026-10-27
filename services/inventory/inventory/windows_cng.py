"""Exact local CNG registration query with bounded caller-owned storage.

Does not open a provider/algorithm/key, invoke crypto, enumerate global providers,
resolve image filenames or call registration mutation APIs. Native qualification
and independent native-call cancellation remain pending.
"""

import ctypes as c
import hashlib
import sys
from shared_models.windows_cng import WindowsCngFact, PROVIDER, INTERFACES, registration_resource, registration_bytes

MAX_REGISTRATION_BYTES = 65536
BUFFER_TOO_SMALL = 0xC0000023


class InterfaceReg(c.Structure):
    _fields_ = [("interface", c.c_uint32), ("flags", c.c_uint32), ("count", c.c_uint32), ("functions", c.c_void_p)]


class ImageReg(c.Structure):
    _fields_ = [("image", c.c_void_p), ("count", c.c_uint32), ("interfaces", c.c_void_p)]


class ProviderReg(c.Structure):
    _fields_ = [("count", c.c_uint32), ("aliases", c.c_void_p), ("user", c.c_void_p), ("kernel", c.c_void_p)]


def _api():
    if sys.platform != "win32":
        raise ValueError("Native Windows required")
    try:
        api = c.WinDLL("bcrypt.dll", use_last_error=True, winmode=0x800)
        api.BCryptQueryProviderRegistration.argtypes = [
            c.POINTER(c.c_uint16),
            c.c_uint32,
            c.c_uint32,
            c.POINTER(c.c_uint32),
            c.POINTER(c.c_void_p),
        ]
        api.BCryptQueryProviderRegistration.restype = c.c_int32  # NTSTATUS, not GetLastError/BOOL.
        return api
    except (OSError, AttributeError):
        from inventory.host import Refused

        raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE") from None


def _error(status):
    from inventory.host import Refused

    status &= 0xFFFFFFFF
    if status == 0xC0000022:
        raise PermissionError("CNG registration denied")
    if status == 0xC0000225:
        raise FileNotFoundError("CNG registration unavailable")
    if status == BUFFER_TOO_SMALL:
        raise Refused("INVALID", "INPUT_CHANGED")
    raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE")


class BoundedView:
    """Validate every dereferenced address/count against the reported caller block."""

    def __init__(self, buffer, size):
        self.buffer = buffer  # Pin Python ownership for all nested pointers.
        self.start = c.addressof(buffer)
        self.end = self.start + size

    def span(self, address, size, alignment=1):
        if not address or address % alignment or size < 0 or address < self.start or address + size > self.end:
            raise ValueError("CNG pointer outside bounded result or unaligned")
        return address

    def struct(self, address, cls):
        self.span(address, c.sizeof(cls), c.alignment(cls))
        return cls.from_buffer_copy(c.string_at(address, c.sizeof(cls)))

    def pointers(self, address, count):
        if not 1 <= count <= 64:
            raise ValueError("Unsupported CNG registration table count")
        self.span(address, count * c.sizeof(c.c_void_p), c.alignment(c.c_void_p))
        array = (c.c_void_p * count).from_buffer_copy(c.string_at(address, count * c.sizeof(c.c_void_p)))
        return list(array)

    def label(self, address):
        values = bytearray()
        for offset in range(65):
            self.span(address, (offset + 1) * 2, 2)
            pair = c.string_at(address + offset * 2, 2)
            if pair == b"\0\0":
                return values.decode("utf-16-le", errors="strict")
            values.extend(pair)
        raise ValueError("Unterminated or overlong CNG registration label")


def collect_registration(item, limit, charge):
    from inventory.host import Refused

    selected = registration_resource(item.path)
    consumed = 0

    def claim(size):
        nonlocal consumed
        if size > limit - consumed:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        charge(size)
        consumed += size

    encoded = PROVIDER.encode("utf-16-le") + b"\0\0"
    claim(len(encoded) + 2 * c.sizeof(c.c_uint32) + c.sizeof(c.c_void_p))
    provider = (c.c_uint16 * (len(encoded) // 2)).from_buffer_copy(encoded)
    api = _api()
    size = c.c_uint32(0)
    # ppBuffer NULL (not address of a null pointer): size query, no native allocation transfer.
    status = api.BCryptQueryProviderRegistration(provider, 1, INTERFACES[selected], c.byref(size), None) & 0xFFFFFFFF
    if status != BUFFER_TOO_SMALL:
        if status == 0:
            raise ValueError("Unexpected successful CNG size query")
        _error(status)
    capacity = size.value
    if capacity < c.sizeof(ProviderReg):
        raise ValueError("Undersized CNG registration result")
    if capacity > MAX_REGISTRATION_BYTES:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    claim(capacity)
    buffer = c.create_string_buffer(capacity)
    pointer = c.c_void_p(c.addressof(buffer))
    status = (
        api.BCryptQueryProviderRegistration(provider, 1, INTERFACES[selected], c.byref(size), c.byref(pointer))
        & 0xFFFFFFFF
    )
    if status != 0:
        _error(status)
    if pointer.value != c.addressof(buffer) or not c.sizeof(ProviderReg) <= size.value <= capacity:
        raise ValueError("Changed caller buffer or invalid returned CNG length")
    view = BoundedView(buffer, size.value)
    root = view.struct(pointer.value, ProviderReg)
    if root.kernel:
        raise ValueError("Kernel registration outside approved user-mode scope")
    image = view.struct(root.user, ImageReg)
    if image.count != 1:
        raise ValueError("Unselected interface or incomplete registration query")
    interface = view.struct(view.pointers(image.interfaces, 1)[0], InterfaceReg)
    if interface.interface != INTERFACES[selected]:
        raise ValueError("CNG returned interface outside scope")
    functions = sorted(view.label(p) for p in view.pointers(interface.functions, interface.count))
    raw = registration_bytes(selected, interface.flags, functions)
    claim(len(raw))
    fact = WindowsCngFact(
        registration_interface=selected,
        registration_flags=interface.flags,
        registered_functions=functions,
        identity_key=f"microsoft-primitive:user:{selected}",
        interface_sha256=hashlib.sha256(raw).hexdigest(),
    )
    return raw, [fact]
