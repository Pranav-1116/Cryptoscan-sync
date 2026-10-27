"""Explicit passive kernel interfaces and one fixed read-only systemd command.

No discovery loops over PIDs, app execution, shell, packets, key operations or
arbitrary /proc paths. Every source byte and command output is bounded.
"""

import ctypes
from contextlib import contextmanager, ExitStack
import errno
import hashlib
import ipaddress
import json
import os
import re
import selectors
import signal
import stat
import struct
import subprocess
import time
from shared_models.host_runtime import RuntimeFact
from shared_models.host_runtime_scope import resource


class ProbeError(Exception):
    def __init__(self, status, reason):
        self.status, self.reason = status, reason


_PINNED_NET_TABLES = {}


@contextmanager
def pinned_network_tables(paths):
    # proc net table lookups can receive fresh inodes on each open. Retain only
    # explicitly selected read-only kernel descriptors as capabilities; never
    # grant an entire /proc subtree to work around Landlock inode semantics.
    with ExitStack() as stack:
        try:
            for path in paths:
                if path in {"/proc/self/net/tcp", "/proc/self/net/tcp6"}:
                    try:
                        _PINNED_NET_TABLES[path] = stack.enter_context(kernel_fd(path, 0x9FA0))
                    except (FileNotFoundError, PermissionError):
                        pass
            yield
        finally:
            _PINNED_NET_TABLES.clear()


@contextmanager
def kernel_fd(path, magic):
    if path in _PINNED_NET_TABLES:
        fd = _PINNED_NET_TABLES[path]
        os.lseek(fd, 0, os.SEEK_SET)
        yield fd
        return
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        buffer = ctypes.create_string_buffer(512)
        if (
            not stat.S_ISREG(os.fstat(fd).st_mode)
            or ctypes.CDLL(None, use_errno=True).fstatfs(fd, buffer) != 0
            or ctypes.c_long.from_buffer(buffer).value != magic
        ):
            raise ProbeError("UNSUPPORTED", "INVALID_FORMAT")
        yield fd
    finally:
        os.close(fd)


def kernel_bytes(path, limit, magic, on_chunk=None):
    with kernel_fd(path, magic) as fd:
        chunks = []
        count = 0
        while True:
            data = os.read(fd, min(65536, limit + 1 - count))
            if not data:
                break
            if on_chunk:
                on_chunk(data[: max(0, limit - count)])
            count += len(data)
            if count > limit:
                raise ProbeError("BUDGET_EXCEEDED", "LIMIT")
            chunks.append(data)
        return b"".join(chunks)


class Reader:
    def __init__(self, limit, charge):
        self.limit, self.charge, self.used = limit, charge, 0
        self.digest = hashlib.sha256()

    def add(self, data):
        remaining = self.limit - self.used
        count = min(len(data), remaining)
        self.used += count
        self.charge(count)
        if len(data) > remaining:
            raise ProbeError("BUDGET_EXCEEDED", "LIMIT")
        self.digest.update(len(data).to_bytes(8, "big"))
        self.digest.update(data)
        return data

    def read(self, path, magic=0x9FA0):
        return kernel_bytes(path, self.limit - self.used, magic, self.add)

    def finish(self, facts):
        facts = [f.model_copy(update={"interface_sha256": self.digest.hexdigest()}) for f in facts]
        data = json.dumps([f.model_dump(mode="json") for f in facts], sort_keys=True, separators=(",", ":")).encode()
        self.add(data)
        return data, facts


def boot_id(reader):
    text = reader.read("/proc/sys/kernel/random/boot_id").decode().strip()
    if not re.fullmatch("[0-9a-f-]{36}", text):
        raise ValueError("Invalid boot identity")
    return text


def process_start(raw, pid):
    text = raw.decode()
    end = text.rfind(")")
    if end < 0 or not text.startswith(str(pid) + " ("):
        raise ValueError("Invalid process identity")
    fields = text[end + 2 :].split()
    if len(fields) < 20 or not fields[19].isdigit() or int(fields[19]) < 1:
        raise ValueError("Invalid process start")
    return int(fields[19])


def mapping_paths(raw):
    paths = {}
    for line in raw.decode().splitlines():
        fields = line.split(None, 5)
        if len(fields) < 6 or not fields[5].startswith("/"):
            continue
        path = fields[5]
        deleted = path.endswith(" (deleted)")
        if deleted:
            path = path[:-10]
        # Shared objects only; no executable arguments, environment or memory.
        if not re.search(r"\.so(?:\.[^/]*)?$", path):
            continue
        paths[(path, deleted)] = True
    return paths


def process(reader, selected, maps):
    pid = os.getpid() if selected == "self" else int(selected)
    boot = boot_id(reader)
    start = process_start(reader.read(f"/proc/{pid}/stat"), pid)
    facts = []
    if maps:
        raw = reader.read(f"/proc/{pid}/maps")
        if len(raw.splitlines()) > 4096:
            raise ProbeError("BUDGET_EXCEEDED", "LIMIT")
        paths = mapping_paths(raw)
        for path, deleted in sorted(paths):
            facts.append(
                RuntimeFact(
                    kind="LOADED_LIBRARY",
                    interface="LINUX_PROCFS",
                    identity_key=f"{boot}:{pid}:{start}:{hashlib.sha256(path.encode()).hexdigest()}:{int(deleted)}",
                    pid=pid,
                    process_start_ticks=start,
                    boot_id=boot,
                    library_path=path,
                    mapped_file_deleted=deleted,
                    mapping_basis="SHARED_OBJECT_PATH_SUFFIX_ONLY",
                )
            )
    else:
        name = reader.read(f"/proc/{pid}/comm").decode().rstrip("\n")
        cgroup = reader.read(f"/proc/{pid}/cgroup").decode()
        units = set(re.findall(r"(?:^|/)([A-Za-z0-9_][A-Za-z0-9_.@:-]{0,110}\.service)(?:/|$)", cgroup, re.M))
        facts = [
            RuntimeFact(
                kind="PROCESS",
                interface="LINUX_PROCFS",
                identity_key=f"{boot}:{pid}:{start}",
                pid=pid,
                process_start_ticks=start,
                boot_id=boot,
                process_name=name,
                service_name=next(iter(units)) if len(units) == 1 else None,
            )
        ]
    if maps:
        if paths != mapping_paths(reader.read(f"/proc/{pid}/maps")):
            raise ProbeError("INVALID", "INPUT_CHANGED")
    elif (
        name != reader.read(f"/proc/{pid}/comm").decode().rstrip("\n")
        or cgroup != reader.read(f"/proc/{pid}/cgroup").decode()
    ):
        raise ProbeError("INVALID", "INPUT_CHANGED")
    if start != process_start(reader.read(f"/proc/{pid}/stat"), pid) or boot != boot_id(reader):
        raise ProbeError("INVALID", "INPUT_CHANGED")
    return facts


def parse_listeners(raw, family, namespace, boot):
    lines = raw.decode("ascii").splitlines()
    if not lines or "local_address" not in lines[0]:
        raise ValueError("Invalid socket table")
    if len(lines) > 4097:
        raise ProbeError("BUDGET_EXCEEDED", "LIMIT")
    facts = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10:
            raise ValueError("Invalid socket record")
        if fields[3] != "0A":
            continue
        address, port = fields[1].split(":")
        width = 32 if family == "tcp6" else 8
        if not re.fullmatch("[0-9A-Fa-f]{" + str(width) + "}", address):
            raise ValueError("Invalid listener address")
        packed = b"".join(struct.pack("=I", int(address[i : i + 8], 16)) for i in range(0, len(address), 8))
        ip = str(ipaddress.ip_address(packed))
        port = int(port, 16)
        inode = int(fields[9])
        facts.append(
            RuntimeFact(
                kind="LISTENER",
                interface="LINUX_PROCFS",
                identity_key=f"{boot}:{namespace}:{inode}",
                boot_id=boot,
                network_namespace=namespace,
                address=ip,
                port=port,
                transport="TCP6" if family == "tcp6" else "TCP",
                socket_inode=inode,
            )
        )
    return facts


def listeners(reader, family):
    boot = boot_id(reader)
    namespace = os.readlink("/proc/self/ns/net")
    raw = reader.read("/proc/self/net/" + family)
    facts = parse_listeners(raw, family, namespace, boot)
    if (
        facts != parse_listeners(reader.read("/proc/self/net/" + family), family, namespace, boot)
        or namespace != os.readlink("/proc/self/ns/net")
        or boot != boot_id(reader)
    ):
        raise ProbeError("INVALID", "INPUT_CHANGED")
    return facts


def hardware(reader, selected):
    if selected.startswith("cpu"):
        index = int(selected[3:])
        root = f"/sys/devices/system/cpu/cpu{index}/topology"
        core = int(reader.read(root + "/core_id", 0x62656572).decode().strip())
        package = int(reader.read(root + "/physical_package_id", 0x62656572).decode().strip())
        if (core, package) != (
            int(reader.read(root + "/core_id", 0x62656572).decode().strip()),
            int(reader.read(root + "/physical_package_id", 0x62656572).decode().strip()),
        ):
            raise ProbeError("INVALID", "INPUT_CHANGED")
        return [
            RuntimeFact(
                kind="HARDWARE",
                interface="LINUX_SYSFS",
                identity_key=selected,
                hardware_type="CPU_TOPOLOGY",
                cpu_index=index,
                core_id=core,
                package_id=package,
            )
        ]
    if selected == "dmi":
        root = "/sys/devices/virtual/dmi/id"
        values = {}
        for key, name in [
            ("manufacturer", "sys_vendor"),
            ("model", "product_name"),
            ("firmware_version", "bios_version"),
        ]:
            try:
                values[key] = reader.read(root + "/" + name, 0x62656572).decode().strip() or None
            except FileNotFoundError:
                values[key] = None
        if not any(values.values()):
            return []
        return [
            RuntimeFact(
                kind="HARDWARE", interface="LINUX_SYSFS", identity_key="dmi", hardware_type="SYSTEM_DMI", **values
            )
        ]
    # The only deliberate symlink exception: a kernel-controlled sysfs class
    # link, pinned under /sys/devices and verified as SYSFS after opening.
    os.lstat("/sys/class/tpm/" + selected)
    root = os.path.realpath("/sys/class/tpm/" + selected)
    if not root.startswith("/sys/devices/"):
        raise ProbeError("UNSUPPORTED", "INVALID_FORMAT")
    version = reader.read(root + "/tpm_version_major", 0x62656572).decode().strip()
    if version not in {"1", "2"}:
        raise ValueError("Unknown TPM version")
    return [
        RuntimeFact(
            kind="HARDWARE",
            interface="LINUX_SYSFS",
            identity_key=selected,
            hardware_type="TPM",
            tpm_major_version=int(version),
        )
    ]


def systemd_output(unit, limit, on_chunk):
    # Pin an ELF supplied through root-owned non-writable OS directories.
    for path in ["/", "/usr", "/usr/bin"]:
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ProbeError("UNSUPPORTED", "INVALID_FORMAT")
    fd = os.open("/usr/bin/systemctl", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
            or os.pread(fd, 4, 0) != b"\x7fELF"
        ):
            raise ProbeError("UNSUPPORTED", "INVALID_FORMAT")
        try:
            os.getxattr(fd, "security.capability")
        except OSError as exc:
            if exc.errno not in {errno.ENODATA, errno.ENOTSUP}:
                raise ProbeError("DENIED", "LEAST_PRIVILEGE_UNPROVEN") from None
        else:
            raise ProbeError("DENIED", "LEAST_PRIVILEGE_UNPROVEN")
        command = [
            f"/proc/self/fd/{fd}",
            "--system",
            "--no-pager",
            "--no-ask-password",
            "show",
            "--property=LoadState,ActiveState,MainPID",
            "--",
            unit,
        ]
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            pass_fds=(fd,),
            start_new_session=True,
            close_fds=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "SYSTEMD_BUS_TIMEOUT": "2s"},
        )
        try:
            os.set_blocking(proc.stdout.fileno(), False)
            data = bytearray()
            deadline = time.monotonic() + 3
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProbeError("UNAVAILABLE", "INTERFACE_UNAVAILABLE")
                    if not selector.select(remaining):
                        raise ProbeError("UNAVAILABLE", "INTERFACE_UNAVAILABLE")
                    chunk = os.read(proc.stdout.fileno(), min(65536, limit + 1 - len(data)))
                    if not chunk:
                        break
                    on_chunk(chunk[: max(0, limit - len(data))])
                    data.extend(chunk)
                    if len(data) > limit:
                        raise ProbeError("BUDGET_EXCEEDED", "LIMIT")
            if proc.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                raise ProbeError("UNAVAILABLE", "INTERFACE_UNAVAILABLE")
            return bytes(data)
        except subprocess.TimeoutExpired:
            raise ProbeError("UNAVAILABLE", "INTERFACE_UNAVAILABLE") from None
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            proc.stdout.close()
    finally:
        os.close(fd)


def parse_service(raw, unit):
    fields = {}
    for line in raw.decode().splitlines():
        key, value = line.split("=", 1)
        if key not in {"LoadState", "ActiveState", "MainPID"} or key in fields:
            raise ValueError("Unexpected service response")
        fields[key] = value
    if set(fields) != {"LoadState", "ActiveState", "MainPID"}:
        raise ValueError("Incomplete service response")
    if fields["LoadState"] != "loaded":
        raise ProbeError("UNAVAILABLE", "NOT_FOUND")
    pid = int(fields["MainPID"])
    return [
        RuntimeFact(
            kind="SERVICE",
            interface="SYSTEMD_READ_ONLY",
            identity_key=unit,
            service_name=unit,
            service_state=fields["ActiveState"],
            pid=pid or None,
        )
    ]


def collect_live(item, limit, charge):
    selected = resource(item.kind, item.path)
    reader = Reader(limit, charge)
    if item.kind == "LINUX_PROCESS":
        facts = process(reader, selected, False)
    elif item.kind == "LINUX_PROCESS_MAPS":
        facts = process(reader, selected, True)
    elif item.kind == "LINUX_LISTENERS":
        facts = listeners(reader, selected)
    elif item.kind == "LINUX_HARDWARE":
        facts = hardware(reader, selected)
    elif item.kind == "LINUX_SERVICE":
        facts = parse_service(systemd_output(selected, min(limit, 4096), reader.add), selected)
    else:
        raise ValueError("Unsupported live source")
    if not facts:
        raise ProbeError("UNAVAILABLE", "NOT_FOUND")
    if len(facts) > 1000:
        raise ProbeError("BUDGET_EXCEEDED", "LIMIT")
    return reader.finish(facts)
