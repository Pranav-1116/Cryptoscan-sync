"""Read only an approved local address-family TCP listener table, no packets.

Never opens processes, sockets, modules, remote connections or UDP/connection
state tables. Native isolation/latency/cancellation qualification remains pending.
"""

import ctypes as c
import hashlib
import ipaddress
import sys
from shared_models.windows_listeners import (
    WindowsListener,
    WindowsListenerFact,
    MAX_LISTENERS,
    listener_resource,
    listener_bytes,
    row_key,
)

MAX_TABLE_BYTES = 65536


class Row4(c.Structure):
    _fields_ = [
        (name, c.c_uint32) for name in ("state", "local_address", "local_port", "remote_address", "remote_port", "pid")
    ]


class Row6(c.Structure):
    _fields_ = [
        ("local_address", c.c_ubyte * 16),
        ("local_scope", c.c_uint32),
        ("local_port", c.c_uint32),
        ("remote_address", c.c_ubyte * 16),
        ("remote_scope", c.c_uint32),
        ("remote_port", c.c_uint32),
        ("state", c.c_uint32),
        ("pid", c.c_uint32),
    ]


def _api():
    from inventory.host import Refused

    if sys.platform != "win32":
        raise ValueError("Native Windows required")
    try:
        api = c.WinDLL("iphlpapi.dll", use_last_error=True, winmode=0x800)
        api.GetExtendedTcpTable.argtypes = [
            c.c_void_p,
            c.POINTER(c.c_uint32),
            c.c_int32,
            c.c_uint32,
            c.c_int32,
            c.c_uint32,
        ]
        api.GetExtendedTcpTable.restype = c.c_uint32  # Direct error code, NOT GetLastError.
        return api
    except (AttributeError, OSError):
        raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE") from None


def _error(status):
    from inventory.host import Refused

    if status == 5:
        raise PermissionError("TCP listener metadata denied")
    if status == 122:
        raise Refused("INVALID", "INPUT_CHANGED")
    raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE")


def parse_table(buffer, size, family):
    from inventory.host import Refused

    if not 4 <= size <= c.sizeof(buffer):
        raise ValueError("Invalid returned TCP table length")
    count = c.c_uint32.from_buffer_copy(buffer).value
    if count > MAX_LISTENERS:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    cls = Row4 if family == "ipv4" else Row6
    if 4 + count * c.sizeof(cls) > size:
        raise ValueError("TCP rows outside caller buffer")
    rows = []
    for index in range(count):
        row = cls.from_buffer_copy(buffer, 4 + index * c.sizeof(cls))
        if row.state != 2:
            raise ValueError("Non-listener row outside approved table class")
        address = c.string_at(c.addressof(row) + cls.local_address.offset, 4 if family == "ipv4" else 16)
        # Only the low WORD is specified. Port bytes are network order, high WORD ignored.
        port = int.from_bytes((row.local_port & 0xFFFF).to_bytes(2, "little"), "big")
        rows.append(
            WindowsListener(
                address=str(ipaddress.ip_address(address)),
                port=port,
                owning_pid=row.pid,
                scope_id=0 if family == "ipv4" else row.local_scope,
            )
        )
    return sorted(rows, key=row_key)


def collect_listeners(item, limit, charge):
    from inventory.host import Refused

    family = listener_resource(item.path)
    consumed = 0

    def claim(size):
        nonlocal consumed
        if size > limit - consumed:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        charge(size)
        consumed += size

    api = None
    samples = []
    for _ in range(2):
        claim(c.sizeof(c.c_uint32))
        if api is None:
            api = _api()
        size = c.c_uint32(0)
        # Windows AF_INET6 is 23, NOT the Linux socket module's value of 10.
        af = 2 if family == "ipv4" else 23
        status = api.GetExtendedTcpTable(None, c.byref(size), 0, af, 3, 0) & 0xFFFFFFFF
        if status != 122:
            if status == 0:
                raise ValueError("Unexpected successful NULL TCP table query")
            _error(status)
        capacity = size.value
        if capacity > MAX_TABLE_BYTES:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        if capacity < 4:
            raise ValueError("Undersized TCP table")
        claim(capacity)
        buffer = c.create_string_buffer(capacity)
        status = api.GetExtendedTcpTable(buffer, c.byref(size), 0, af, 3, 0) & 0xFFFFFFFF
        if status:
            _error(status)
        samples.append(parse_table(buffer, size.value, family))
    if samples[0] != samples[1]:
        raise Refused("INVALID", "INPUT_CHANGED")
    raw = listener_bytes(family, samples[1])
    claim(len(raw))
    fact = WindowsListenerFact(
        kind="WINDOWS_TCP_LISTENER_TABLE",
        address_family=family,
        listener_count=len(samples[1]),
        listeners=samples[1],
        identity_key=f"windows-tcp-table:{family}:owner-pid-listener",
        interface_sha256=hashlib.sha256(raw).hexdigest(),
    )
    return raw, [fact]
