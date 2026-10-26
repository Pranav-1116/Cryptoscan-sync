"""Explicit Linux namespace counters and path-scoped statvfs. Never sniff or configure."""

from contextlib import contextmanager
import ctypes
from datetime import datetime, timezone
import errno
import os
import socket
import stat
import sys
import time
import uuid
from shared_models.resource_monitoring import (
    NetworkCounters,
    NetworkReading,
    ResourceAuthorization,
    ResourceCapture,
    StorageReading,
)


class ResourceRefused(ValueError):
    pass


def _proc(path, maximum):
    # Only the two caller-selected constants below are permitted; no arbitrary reader.
    if path not in {"/proc/self/net/dev", "/proc/sys/kernel/random/boot_id"}:
        raise ResourceRefused("UNSUPPORTED_SOURCE")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        buffer = ctypes.create_string_buffer(512)
        if (
            not stat.S_ISREG(os.fstat(fd).st_mode)
            or ctypes.CDLL(None, use_errno=True).fstatfs(fd, buffer) != 0
            or ctypes.c_long.from_buffer(buffer).value != 0x9FA0
        ):
            raise ResourceRefused("NOT_KERNEL_PROCFS")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - total))
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > maximum:
                raise ResourceRefused("SOURCE_BUDGET")
            chunks.append(chunk)
    finally:
        os.close(fd)


def context():
    return (
        _proc("/proc/sys/kernel/random/boot_id", 64).decode("ascii").strip(),
        os.stat("/proc/self/ns/net").st_ino,
        os.stat("/proc/self/ns/mnt").st_ino,
    )


def parse_netdev(raw, selected):
    if len(raw) > 131072:
        raise ResourceRefused("SOURCE_BUDGET")
    lines = raw.decode("ascii").splitlines()
    if len(lines) < 2 or "Receive" not in lines[0] or "Transmit" not in lines[0]:
        raise ResourceRefused("INVALID_COUNTER_SOURCE")
    result = {}
    for line in lines[2:]:
        if ":" not in line:
            continue
        name, fields = line.rsplit(":", 1)
        name = name.strip()
        if name not in selected:
            continue
        fields = fields.split()
        if (
            name in result
            or len(fields) != 16
            or any(not f.isascii() or not f.isdecimal() or len(f) > 20 for f in fields)
        ):
            raise ResourceRefused("INVALID_COUNTER_SOURCE")
        values = [int(f) for f in fields]
        if any(v > 18446744073709551615 for v in values):
            raise ResourceRefused("INVALID_COUNTER_SOURCE")
        result[name] = NetworkCounters(
            rx_bytes=values[0],
            rx_packets=values[1],
            rx_errors=values[2],
            rx_dropped=values[3],
            tx_bytes=values[8],
            tx_packets=values[9],
            tx_errors=values[10],
            tx_dropped=values[11],
        )
    return result


def _network(names):
    try:
        counters = parse_netdev(_proc("/proc/self/net/dev", 131072), names)
    except PermissionError:
        return {name: ("DENIED", None, None) for name in names}
    except (OSError, ValueError, UnicodeError):
        return {name: ("INVALID", None, None) for name in names}
    result = {}
    for name in names:
        try:
            index = socket.if_nametoindex(name)
            result[name] = ("MEASURED", counters[name], index) if name in counters else ("UNAVAILABLE", None, None)
        except OSError:
            result[name] = ("UNAVAILABLE", None, None)
    return result


@contextmanager
def directory(path):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.split("/")[1:]:
            if not component:
                continue
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd
            )
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _storage(path):
    try:
        with directory(path) as fd:
            value, info = os.fstatvfs(fd), os.fstat(fd)
        unit = value.f_frsize or value.f_bsize
        if unit <= 0:
            raise ValueError("INVALID_BLOCK_SIZE")
        return StorageReading(
            **{
                "path": path,
                "status": "MEASURED",
                "total_bytes": value.f_blocks * unit,
                "free_bytes": value.f_bfree * unit,
                "available_bytes": max(0, value.f_bavail) * unit,
                "filesystem_device": f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}",
            }
        ).model_dump(mode="json")
    except PermissionError:
        status = "DENIED"
    except FileNotFoundError:
        status = "UNAVAILABLE"
    except OSError as exc:
        status = "UNSUPPORTED" if exc.errno in {errno.ELOOP, errno.ENOTDIR} else "INVALID"
    except ValueError:
        status = "INVALID"
    return {"path": path, "status": status}


def collect_resources(authorization: ResourceAuthorization, expected_record_sha256: str):
    authorization = ResourceAuthorization.model_validate(authorization.model_dump())
    if sys.platform != "linux" or os.geteuid() == 0:
        raise ResourceRefused("ORDINARY_USER_LINUX_REQUIRED")
    if authorization.plan_record_sha256 != expected_record_sha256:
        raise ResourceRefused("APPROVAL_COMMITMENT_MISMATCH")
    scope = authorization.scope
    started = datetime.now(timezone.utc)
    if not scope.not_before <= started or (scope.expires_at - started).total_seconds() < scope.interval_seconds + 2:
        raise ResourceRefused("CAPTURE_WINDOW_UNAVAILABLE")
    original_context = context()
    t1 = time.monotonic_ns()
    first = _network(scope.interfaces)
    time.sleep(scope.interval_seconds)
    t2 = time.monotonic_ns()
    second = _network(scope.interfaces)
    storage = [_storage(path) for path in scope.mount_paths]
    if context() != original_context:
        raise ResourceRefused("BOOT_OR_NAMESPACE_CHANGED")
    readings = []
    for name in scope.interfaces:
        old, new = first[name], second[name]
        if old[0] != "MEASURED" or new[0] != "MEASURED":
            readings.append(NetworkReading(interface=name, status=new[0] if new[0] != "MEASURED" else old[0]))
            continue
        reset = any(getattr(new[1], k) < getattr(old[1], k) for k in NetworkCounters.model_fields)
        status = "IDENTITY_CHANGED" if old[2] != new[2] else "COUNTER_RESET" if reset else "MEASURED"
        readings.append(
            NetworkReading(
                interface=name, status=status, first=old[1], second=new[1], first_ifindex=old[2], second_ifindex=new[2]
            )
        )
    return ResourceCapture(
        capture_id=str(uuid.uuid4()),
        authorization=authorization,
        started_at=started,
        finished_at=datetime.now(timezone.utc),
        elapsed_ns=t2 - t1,
        boot_id=original_context[0],
        network_namespace_inode=original_context[1],
        mount_namespace_inode=original_context[2],
        network=readings,
        storage=storage,
    )
