"""Candidate exact-PID loader metadata, not VM reads, execution or crypto use."""

import ctypes as c
import hashlib
import sys
from shared_models.windows_images import WindowsImageFact, process_resource, image_path, metadata_bytes

MAX_MODULES = 256
PATH_CHARS = 1024
STILL_ACTIVE = 259
INVALID_HANDLE = c.c_void_p(-1).value


class FileTime(c.Structure):
    _fields_ = [("low", c.c_uint32), ("high", c.c_uint32)]


class ModuleEntry(c.Structure):
    _fields_ = [
        ("size", c.c_uint32),
        ("module_id", c.c_uint32),
        ("pid", c.c_uint32),
        ("global_usage", c.c_uint32),
        ("process_usage", c.c_uint32),
        ("base", c.c_void_p),
        ("base_size", c.c_uint32),
        ("module", c.c_void_p),
        ("name", c.c_uint16 * 256),
        ("path", c.c_uint16 * 260),
    ]


def _api():
    if sys.platform != "win32":
        raise ValueError("Native Windows required")
    api = c.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
    signatures = {
        "OpenProcess": ([c.c_uint32, c.c_int32, c.c_uint32], c.c_void_p),
        "GetProcessTimes": ([c.c_void_p, *([c.POINTER(FileTime)] * 4)], c.c_int32),
        "QueryFullProcessImageNameW": (
            [c.c_void_p, c.c_uint32, c.POINTER(c.c_uint16), c.POINTER(c.c_uint32)],
            c.c_int32,
        ),
        "GetExitCodeProcess": ([c.c_void_p, c.POINTER(c.c_uint32)], c.c_int32),
        "WaitForSingleObject": ([c.c_void_p, c.c_uint32], c.c_uint32),
        "CreateToolhelp32Snapshot": ([c.c_uint32, c.c_uint32], c.c_void_p),
        "Module32FirstW": ([c.c_void_p, c.POINTER(ModuleEntry)], c.c_int32),
        "Module32NextW": ([c.c_void_p, c.POINTER(ModuleEntry)], c.c_int32),
        "CloseHandle": ([c.c_void_p], c.c_int32),
    }
    for name, (args, result) in signatures.items():
        call = getattr(api, name)
        call.argtypes = args
        call.restype = result
    return api


def _error():
    from inventory.host import Refused

    code = c.get_last_error() & 0xFFFFFFFF
    if code == 5:
        raise PermissionError("Process metadata query denied")
    if code in {87, 1168}:
        raise FileNotFoundError("Approved process unavailable")
    if code == 24:
        raise Refused("INVALID", "INPUT_CHANGED")  # ERROR_BAD_LENGTH; no automatic retries.
    raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE")  # Includes cross-bitness ERROR_PARTIAL_COPY.


def _text(buffer):
    values = list(buffer)
    if 0 not in values:
        raise ValueError("Unterminated native UTF-16 result")
    end = values.index(0)
    return bytes(buffer)[: end * 2].decode("utf-16-le", errors="strict")


def collect_images(item, limit, charge):
    from inventory.host import Refused

    pid, expected = process_resource(item.path)
    consumed = 0

    def claim(size):
        nonlocal consumed
        if size > limit - consumed:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        charge(size)
        consumed += size

    # Refuse before native open if even fixed caller buffers cannot fit.
    claim(4 * c.sizeof(FileTime) + 8 + PATH_CHARS * 2)
    api = _api()
    handle = api.OpenProcess(0x00101000, False, pid)  # QUERY_LIMITED_INFORMATION | SYNCHRONIZE; no VM_READ/ALL_ACCESS.
    if not handle or handle == INVALID_HANDLE:
        _error()

    def identity():
        times = [FileTime() for _ in range(4)]
        if not api.GetProcessTimes(handle, *(c.byref(t) for t in times)):
            _error()
        creation = str((times[0].high << 32) | times[0].low)
        code = c.c_uint32()
        if not api.GetExitCodeProcess(handle, c.byref(code)):
            _error()
        state = api.WaitForSingleObject(handle, 0)  # Zero-time liveness check; exit code 259 alone is ambiguous.
        if state == 0xFFFFFFFF:
            _error()
        if creation != expected or code.value != STILL_ACTIVE or state != 258:
            raise Refused("INVALID", "INPUT_CHANGED")
        buf = (c.c_uint16 * PATH_CHARS)()
        size = c.c_uint32(PATH_CHARS)
        if not api.QueryFullProcessImageNameW(handle, 0, buf, c.byref(size)):
            _error()
        if not 0 < size.value < PATH_CHARS or buf[size.value] != 0:
            raise ValueError("Invalid image-path length")
        result = _text(buf)
        if len(result.encode("utf-16-le")) // 2 != size.value:
            raise ValueError("Image-path count mismatch")
        return image_path(result)

    def modules():
        claim(c.sizeof(ModuleEntry))
        snapshot = api.CreateToolhelp32Snapshot(0x18, pid)  # MODULE | MODULE32 only, no process/heap/thread discovery.
        if not snapshot or snapshot == INVALID_HANDLE:
            _error()
        try:
            rows = []
            entry = ModuleEntry()
            entry.size = c.sizeof(entry)
            if not api.Module32FirstW(snapshot, c.byref(entry)):
                _error()
            while True:
                if entry.size != c.sizeof(entry) or entry.pid != pid:
                    raise Refused("INVALID", "INPUT_CHANGED")
                name, path = _text(entry.name), _text(entry.path)
                image_path(path)
                if not name or name != path.rsplit("\\", 1)[-1] or len(path) >= 259:
                    raise ValueError("Truncated or inconsistent module path")
                rows.append((name, path))
                if len(rows) > MAX_MODULES:
                    raise Refused("BUDGET_EXCEEDED", "LIMIT")
                claim(c.sizeof(ModuleEntry))
                entry = ModuleEntry()
                entry.size = c.sizeof(entry)
                if not api.Module32NextW(snapshot, c.byref(entry)):
                    if c.get_last_error() & 0xFFFFFFFF != 18:
                        _error()  # ERROR_NO_MORE_FILES only.
                    break
            if len({p.casefold() for _, p in rows}) != len(rows):
                raise ValueError("Ambiguous duplicate image path")
            return sorted(rows)
        finally:
            if not api.CloseHandle(snapshot):
                raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE")

    try:
        initial = identity()
        first = modules()
        second = modules()
        claim(4 * c.sizeof(FileTime) + 8 + PATH_CHARS * 2)
        if first != second or identity() != initial:
            raise Refused("INVALID", "INPUT_CHANGED")
        raw = metadata_bytes(pid, expected, initial, first)
        claim(len(raw))
        sha = hashlib.sha256(raw).hexdigest()
        key = f"pid:{pid}:created:{expected}"
        common = {"pid": pid, "creation_filetime": expected, "interface_sha256": sha}
        facts = [WindowsImageFact(**common, kind="WINDOWS_PROCESS_IMAGE", image_path=initial, identity_key=key)]
        facts += [
            WindowsImageFact(
                **common,
                kind="WINDOWS_MODULE",
                image_path=path,
                module_name=name,
                identity_key=key + ":path-sha256:" + hashlib.sha256(path.encode()).hexdigest(),
            )
            for name, path in first
        ]
        return raw, facts
    finally:
        if not api.CloseHandle(handle):
            raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE")
