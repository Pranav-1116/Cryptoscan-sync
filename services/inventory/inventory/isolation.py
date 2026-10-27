"""Linux x86_64 read-only stage: Landlock + seccomp, no privilege escalation.

Installed only in a fresh child after imports/input parsing, never the API.
No network, exec/clone, filesystem mutation or writes except result pipe/stdout.
Not a production admission or signed executable attestation.
"""

import ctypes
import errno
import os
import platform


class IsolationUnavailable(ValueError):
    pass


class Ruleset(ctypes.Structure):
    _fields_ = [("handled", ctypes.c_uint64)]


class PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(Filter))]


def install(read_paths, kernel_paths=None):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise IsolationUnavailable("Unsupported isolation ABI")
    from inventory.host import elevated

    if elevated():
        raise IsolationUnavailable("Ordinary user required")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(444, 0, 0, 1)
    if abi < 1:
        raise IsolationUnavailable("Landlock unavailable")
    if libc.prctl(38, 1, 0, 0, 0):
        raise IsolationUnavailable("no_new_privs unavailable")
    # ABI 1+2 filesystem access. ABI 1 lacks REFER but already denies cross-dir
    # reparenting. Seccomp separately denies all mutation and O_TRUNC (ABI <3).
    mask = (1 << 13) - 1
    if abi >= 2:
        mask |= 1 << 13
    rules = Ruleset(mask)
    fd = libc.syscall(444, ctypes.byref(rules), ctypes.sizeof(rules), 0)
    if fd < 0:
        raise IsolationUnavailable("Landlock ruleset refused")
    try:
        from inventory.host import _linux_fd

        for path in sorted(set(read_paths)):
            try:
                with _linux_fd(path) as leaf:
                    rule = PathRule(1 << 2, leaf)
                    if libc.syscall(445, fd, 1, ctypes.byref(rule), 0):
                        raise IsolationUnavailable("Landlock rule refused")
            except (FileNotFoundError, PermissionError):
                pass  # no permission granted; collection still emits a bounded gap
        from inventory.linux_runtime import kernel_fd

        for path, magic in sorted((kernel_paths or {}).items()):
            try:
                with kernel_fd(path, magic) as leaf:
                    rule = PathRule(1 << 2, leaf)
                    if libc.syscall(445, fd, 1, ctypes.byref(rule), 0):
                        raise IsolationUnavailable("Kernel Landlock rule refused")
            except (FileNotFoundError, PermissionError):
                # No permission fallback. The collection stage emits a gap.
                pass
        if libc.syscall(446, fd, 0):
            raise IsolationUnavailable("Landlock enforcement refused")
    finally:
        os.close(fd)
    # Classic BPF on seccomp_data: arch at 4, nr at 0, args at 16.
    LD = 0x20
    JEQ = 0x15
    JSET = 0x45
    RET = 0x06
    allow = 0x7FFF0000
    deny = 0x50000 | errno.EPERM
    kill = 0x80000000
    code = [Filter(LD, 0, 0, 4), Filter(JEQ, 1, 0, 0xC000003E), Filter(RET, 0, 0, kill), Filter(LD, 0, 0, 0)]
    # open/openat: forbid write/create/truncate/append/tmpfile, including
    # O_RDONLY|O_TRUNC on old Landlock kernels. openat2 is not allowed.
    flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND | 0x400000  # __O_TMPFILE
    for syscall, offset in [(2, 24), (257, 32)]:
        code.extend(
            [
                Filter(JEQ, 0, 4, syscall),
                Filter(LD, 0, 0, offset),
                Filter(JSET, 0, 1, flags),
                Filter(RET, 0, 0, deny),
                Filter(RET, 0, 0, allow),
            ]
        )
    # Only stdout/stderr are writable. Child closes all unrelated inherited FDs.
    code.extend(
        [
            Filter(JEQ, 0, 5, 1),
            Filter(LD, 0, 0, 16),
            Filter(JEQ, 1, 0, 1),
            Filter(JEQ, 0, 1, 2),
            Filter(RET, 0, 0, allow),
            Filter(RET, 0, 0, deny),
        ]
    )
    allowed = [
        0,
        3,
        4,
        5,
        6,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        21,
        24,
        25,
        28,
        35,
        39,
        60,
        63,
        72,
        89,
        97,
        98,
        99,
        102,
        104,
        107,
        108,
        110,
        111,
        125,
        131,
        137,
        138,
        158,
        186,
        202,
        218,
        228,
        230,
        231,
        262,
        267,
        273,
        318,
        332,
        334,
    ]
    # fcntl/ioctl are excluded below: no descriptor duplication or arbitrary
    # device controls. getrlimit/capget etc are needed by the existing collector.
    allowed = [n for n in allowed if n not in {16, 72}]
    for syscall in allowed:
        code.extend([Filter(JEQ, 0, 1, syscall), Filter(RET, 0, 0, allow)])
    code.append(Filter(RET, 0, 0, deny))
    array = (Filter * len(code))(*code)
    program = Program(len(code), array)
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise IsolationUnavailable("Seccomp unavailable")
    return {
        "profile": "linux-landlock-seccomp/v1",
        "landlock_abi": abi,
        "network": "DENIED",
        "exec_clone": "DENIED",
        "filesystem": "EXPLICIT_READ_LEAVES",
        "production_execution_qualified": False,
    }


def set_limits():
    import resource

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    # Virtual memory, not a resident-set/whole-machine capacity claim.
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))


def approved_paths(manifest):
    # Explicit checked file/proc/sysfs leaves only. Systemd bus/exec and native
    # Windows still require distinct reviewed sandboxes.
    supported = {
        "PUBLIC_CERTIFICATE",
        "NGINX_TLS_CONFIG",
        "BINARY_METADATA",
        "DPKG_STATUS",
        "APK_INSTALLED",
        "LINUX_OS_RELEASE",
        "RPM_SQLITE",
        "LINUX_PROCESS",
        "LINUX_PROCESS_MAPS",
        "LINUX_LISTENERS",
        "LINUX_HARDWARE",
    }
    if manifest.platform != "linux" or any(i.kind not in supported for i in manifest.inputs):
        raise IsolationUnavailable("Interface not supported by isolated file stage; no fallback")
    from inventory.host import _linux_fd

    for item in manifest.inputs:
        if item.kind in {"LINUX_PROCESS", "LINUX_PROCESS_MAPS", "LINUX_LISTENERS", "LINUX_HARDWARE"}:
            continue
        try:
            with _linux_fd(item.path):
                pass  # no-follow/type/FS check; absent/denied scope gets no grant
        except (FileNotFoundError, PermissionError):
            pass
    return [
        i.path
        for i in manifest.inputs
        if i.kind not in {"LINUX_PROCESS", "LINUX_PROCESS_MAPS", "LINUX_LISTENERS", "LINUX_HARDWARE"}
    ]


def approved_kernel_paths(manifest):
    from shared_models.host_runtime_scope import resource

    proc, sysfs = 0x9FA0, 0x62656572
    paths = {}
    for item in manifest.inputs:
        if item.kind not in {"LINUX_PROCESS", "LINUX_PROCESS_MAPS", "LINUX_LISTENERS", "LINUX_HARDWARE"}:
            continue
        selected = resource(item.kind, item.path)
        if item.kind in {"LINUX_PROCESS", "LINUX_PROCESS_MAPS"}:
            pid = os.getpid() if selected == "self" else int(selected)
            names = ["stat", "comm", "cgroup"] if item.kind == "LINUX_PROCESS" else ["stat", "maps"]
            paths.update({f"/proc/{pid}/{name}": proc for name in names})
            paths["/proc/sys/kernel/random/boot_id"] = proc
        elif item.kind == "LINUX_LISTENERS":
            paths[f"/proc/self/net/{selected}"] = proc
            paths["/proc/sys/kernel/random/boot_id"] = proc
        elif selected.startswith("cpu"):
            root = f"/sys/devices/system/cpu/{selected}/topology"
            paths.update({root + "/core_id": sysfs, root + "/physical_package_id": sysfs})
        elif selected == "dmi":
            paths.update(
                {
                    f"/sys/devices/virtual/dmi/id/{name}": sysfs
                    for name in ["sys_vendor", "product_name", "bios_version"]
                }
            )
        else:
            link = "/sys/class/tpm/" + selected
            if not os.path.lexists(link):
                continue
            root = os.path.realpath(link)
            if not root.startswith("/sys/devices/"):
                raise IsolationUnavailable("TPM scope escape")
            paths[root + "/tpm_version_major"] = sysfs
    return paths


def collect_isolated(target, timeout=15, *, checkpoint=None, stage_root=None):
    """Fixed child command, input file, bounded stdout, kill/reap on every error."""
    import selectors
    import signal
    import subprocess
    import sys
    import tempfile
    import time
    from pathlib import Path
    from inventory.collection import OfflineLinuxCollector
    from shared_models.host_collection import HostSnapshot, digest
    from shared_models.qualified_export import bounded_json

    if not isinstance(timeout, int) or not 1 <= timeout <= 30:
        raise ValueError("Invalid isolated deadline")
    OfflineLinuxCollector().validate_scope(target)
    from inventory.host import elevated

    if elevated():
        raise IsolationUnavailable("Ordinary user required")
    script = (
        (Path(stage_root) if stage_root is not None else Path(__file__).resolve().parents[3])
        / "scripts"
        / "_isolated_host_stage.py"
    )
    command = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        # Arm parent-death SIGKILL before stage imports. Recheck PPID to close
        # the race where the supervisor dies immediately before prctl.
        f"import sys,runpy,ctypes,os;libc=ctypes.CDLL(None);"
        f"os._exit(64) if libc.prctl(1,9,0,0,0)!=0 or os.getppid()!={os.getpid()} else None;"
        f'sys.path.insert(0,{str(script.parent)!r});runpy.run_path({str(script)!r},run_name="__main__")',
    ]
    raw = target.model_dump_json().encode()
    if len(raw) > 131072:
        raise ValueError("Target size limit")
    if checkpoint is not None:
        checkpoint()
    with tempfile.TemporaryFile() as source, tempfile.TemporaryDirectory(prefix="cryptoscan-isolated-") as cwd:
        source.write(raw)
        source.seek(0)
        proc = subprocess.Popen(
            command,
            stdin=source,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
            close_fds=True,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        try:
            deadline = time.monotonic() + timeout
            result = bytearray()
            os.set_blocking(proc.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if checkpoint is not None:
                        checkpoint()
                    if remaining <= 0:
                        raise IsolationUnavailable("Isolated deadline exceeded")
                    if not selector.select(min(remaining, 0.2)):
                        continue
                    chunk = os.read(proc.stdout.fileno(), min(65536, 1500001 - len(result)))
                    if not chunk:
                        break
                    result.extend(chunk)
                    if len(result) > 1500000:
                        raise IsolationUnavailable("Isolated output limit")
            if proc.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                raise IsolationUnavailable("Isolated child refused; no fallback")
            value = bounded_json(bytes(result), max_bytes=1500000)
            if (
                set(value) != {"snapshot", "isolation"}
                or value["isolation"].get("profile") != "linux-landlock-seccomp/v1"
            ):
                raise IsolationUnavailable("Invalid isolation result")
            snapshot = HostSnapshot.model_validate(value["snapshot"])
            if snapshot.manifest_sha256 != digest(target.manifest) or snapshot.started_at < target.not_before:
                raise IsolationUnavailable("Isolated target mismatch")
            return snapshot, value["isolation"]
        except subprocess.TimeoutExpired:
            raise IsolationUnavailable("Isolated deadline exceeded") from None
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            proc.stdout.close()
