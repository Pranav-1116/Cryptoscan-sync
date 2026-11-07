"""Fail-closed Linux/x86_64 offline-reader boundary. Stacks with existing seccomp.

Landlock prevents reading ground truth and ambient home files. It is NOT a
complete host-metadata confidentiality or VM-escape/security certification.
"""

import ctypes
import errno
import os
from pathlib import Path
import resource
import struct


def apply(read_paths):
    if os.uname().machine != "x86_64" or os.geteuid() == 0:
        raise ValueError("ordinary-user Linux x86_64 required")
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.split(":")[0] in ("CapEff", "CapPrm", "CapInh", "CapAmb") and int(line.split()[1], 16):
            raise ValueError("capability-bearing reader refused")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0):
        raise OSError(ctypes.get_errno(), "NoNewPrivs")
    abi = libc.syscall(444, 0, 0, 1)
    if abi < 2:
        raise ValueError("Landlock ABI >=2 required; no unguarded fallback")
    rights = (1 << 14) - 1
    attr = ctypes.create_string_buffer(struct.pack("Q", rights))
    ruleset = libc.syscall(444, attr, 8, 0)
    if ruleset < 0:
        raise OSError(ctypes.get_errno(), "Landlock create")
    try:
        for path in read_paths:
            p = Path(path).resolve(strict=True)
            fd = os.open(p, os.O_PATH | os.O_CLOEXEC)
            try:
                access = (1 << 0) | (1 << 2) | ((1 << 3) if p.is_dir() else 0)
                rule = ctypes.create_string_buffer(struct.pack("Qi", access, fd))
                if libc.syscall(445, ruleset, 1, rule, 0):
                    raise OSError(ctypes.get_errno(), "Landlock rule")
            finally:
                os.close(fd)
        if libc.syscall(446, ruleset, 0):
            raise OSError(ctypes.get_errno(), "Landlock restrict")
    finally:
        os.close(ruleset)

    class Filter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]

    class Program(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]

    # Native arch gate; deny x32/compat via architecture and syscall bit checks.
    ins = [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, 0xC000003E),
        (0x06, 0, 0, 0x50000 | errno.EPERM),
        (0x20, 0, 0, 0),
        (0x45, 0, 1, 0x40000000),
        (0x06, 0, 0, 0x50000 | errno.EPERM),
    ]
    blocked = [
        41,
        42,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        50,
        51,
        52,
        53,
        54,
        55,
        288,
        299,
        307,  # all socket paths
        101,
        155,
        161,
        165,
        166,
        169,
        175,
        176,
        246,
        248,
        249,
        250,
        272,
        298,
        303,
        304,
        308,
        310,
        311,
        313,
        320,
        321,
        323,
        425,
        428,
        429,
        430,
        431,
        432,
        433,
        76,
        77,
        90,
        91,
        92,
        93,
        94,
        132,
        188,
        189,
        190,
        191,
        192,
        193,
        197,
        198,
        199,
        200,
        201,
        235,
        260,
        261,
        268,
        280,  # metadata writes
        57,
        58,
    ]  # fork/vfork; scanner call below runs sequentially, not a worker pool
    for nr in blocked:
        ins.extend([(0x15, 0, 1, nr), (0x06, 0, 0, 0x50000 | errno.EPERM)])
    ins.append((0x06, 0, 0, 0x7FFF0000))
    arr = (Filter * len(ins))(*(Filter(*row) for row in ins))
    program = Program(len(ins), arr)
    if libc.prctl(22, 2, ctypes.byref(program)):
        raise OSError(ctypes.get_errno(), "seccomp install")
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return {
        "landlock_abi": abi,
        "seccomp": "ACTIVE_NETWORK_DENIED",
        "oracle_mount": "NONE",
        "memory_limit_bytes": 2 * 1024**3,
    }
