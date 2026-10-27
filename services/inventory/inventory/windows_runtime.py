"""Phase 3 candidate: named, local SCM query only. Native qualification pending.

No service enumeration/start/stop/config changes, remote SCM, executable paths,
credentials, PowerShell, shell or service binary execution.
"""

import ctypes
import hashlib
import json
import sys
from shared_models.host_runtime import RuntimeFact
from shared_models.host_runtime_scope import resource


class ServiceStatusProcess(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_uint32)
        for name in (
            "service_type",
            "state",
            "controls",
            "win32_exit",
            "service_exit",
            "checkpoint",
            "wait_hint",
            "pid",
            "flags",
        )
    ]


def status_fact(unit, status):
    states = {
        1: "STOPPED",
        2: "START_PENDING",
        3: "STOP_PENDING",
        4: "RUNNING",
        5: "CONTINUE_PENDING",
        6: "PAUSE_PENDING",
        7: "PAUSED",
    }
    if status.state not in states:
        raise ValueError("Unknown SCM state")
    # Windows documents dwProcessId as valid only in these states.
    pid = status.pid if status.state in {4, 5, 6, 7} else None
    if pid == 0:
        pid = None
    source = {name: getattr(status, name) for name, _ in status._fields_}
    return RuntimeFact(
        kind="SERVICE",
        interface="WINDOWS_SCM",
        identity_key=unit,
        service_name=unit,
        service_state=states[status.state],
        pid=pid,
        interface_sha256=hashlib.sha256(json.dumps(source, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    )


def query_status(unit):
    if sys.platform != "win32":
        raise ValueError("SCM requires native Windows")
    from ctypes import wintypes as w

    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.OpenSCManagerW.argtypes = [w.LPCWSTR, w.LPCWSTR, w.DWORD]
    api.OpenSCManagerW.restype = w.HANDLE
    api.OpenServiceW.argtypes = [w.HANDLE, w.LPCWSTR, w.DWORD]
    api.OpenServiceW.restype = w.HANDLE
    api.QueryServiceStatusEx.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)]
    api.QueryServiceStatusEx.restype = w.BOOL
    api.CloseServiceHandle.argtypes = [w.HANDLE]
    api.CloseServiceHandle.restype = w.BOOL

    def error():
        code = ctypes.get_last_error()
        if code == 5:
            raise PermissionError("SCM query denied")
        if code == 1060:
            raise FileNotFoundError("Named service unavailable")
        raise OSError(code, "SCM query unavailable")

    manager = api.OpenSCManagerW(None, None, 0x0001)  # SC_MANAGER_CONNECT only
    if not manager:
        error()
    try:
        service = api.OpenServiceW(manager, unit, 0x0004)  # SERVICE_QUERY_STATUS only
        if not service:
            error()
        try:
            results = []
            for _ in range(2):
                status = ServiceStatusProcess()
                needed = w.DWORD()
                if not api.QueryServiceStatusEx(
                    service, 0, ctypes.byref(status), ctypes.sizeof(status), ctypes.byref(needed)
                ):
                    error()
                # pcbBytesNeeded is only specified on insufficient-buffer failure.
                results.append(status)
            if (results[0].state, results[0].pid) != (results[1].state, results[1].pid):
                from inventory.host import Refused

                raise Refused("INVALID", "INPUT_CHANGED")
            return results[1]
        finally:
            api.CloseServiceHandle(service)
    finally:
        api.CloseServiceHandle(manager)


def collect_service(item, limit, charge):
    from inventory.host import Refused

    # Reserve both fixed native query buffers before invoking SCM. This is a
    # conservative charged-byte budget, not a byte-for-byte RPC traffic metric.
    reserved = 2 * ctypes.sizeof(ServiceStatusProcess)
    if limit < reserved:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    charge(reserved)
    unit = resource(item.kind, item.path)
    fact = status_fact(unit, query_status(unit))
    data = json.dumps([fact.model_dump(mode="json")], sort_keys=True, separators=(",", ":")).encode()
    charge(min(len(data), limit - reserved))
    if len(data) > limit - reserved:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    return data, [fact]


def collect_os_version(item, limit, charge):
    if sys.platform != "win32" or item.path != "windows-os://local/current-version":
        raise ValueError("Unsupported native OS scope")
    import winreg
    from inventory.host import _registry_value, Refused
    from shared_models.host_collection import HostFact

    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        0,
        winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY,
    ) as key:
        name = _registry_value(key, "ProductName")
        try:
            version = _registry_value(key, "CurrentBuildNumber")
        except FileNotFoundError:
            version = None
    fact = HostFact(
        kind="OS_RELEASE",
        local_basis="DECLARED",
        purpose="OS_RELEASE_METADATA",
        software_name=name,
        software_version=version,
    )
    raw = json.dumps([fact.model_dump(mode="json")], sort_keys=True, separators=(",", ":")).encode()
    charge(min(len(raw), limit))
    if len(raw) > limit:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    return raw, [fact]
