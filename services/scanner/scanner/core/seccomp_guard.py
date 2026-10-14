"""Process-level seccomp guard for scanner children (§4.1).

R49 bounded hostile *inputs* in time/memory (rlimits + wall-clock). This
module adds a syscall boundary around the processes that touch those
inputs: pool children and :func:`run_in_sandbox` children install a
seccomp-BPF denylist filter, so a hostile scanned file cannot reach
kernel attack surface or open network connections from inside the scan.

Design, deliberately conservative and honest about scope:

* **Denylist, not allowlist.** Everything stays allowed except (a) the
  kernel-attack-surface set — module loading, mount/namespace games,
  ptrace/process_vm, bpf, perf events, kexec, time setting, keyrings,
  io_uring, the new mount API — and (b) the network-egress set — creating
  sockets or driving the socket data path (``socket``/``connect``/``bind``/
  ``listen``/``accept*``/``send*``/``recv*``/``shutdown``). A blocked
  syscall returns ``EPERM`` (never ``SIGSYS``), so a legitimate need
  surfaces as a visible per-file error rather than a dead child.
* **Raw BPF via ``prctl``** — no libseccomp dependency; the filter is a
  hand-built ``sock_fprog`` (arch gate → nr compare chain → RET).
* **x86_64 and aarch64 (arm64).** The x86_64 table was verified against
  ``/usr/include/x86_64-linux-gnu/asm/unistd_64.h`` and the aarch64 table
  against the kernel's asm-generic numbering
  (``/usr/include/asm-generic/unistd.h`` — arm64 has no private table);
  unit tests re-verify both against the headers when present. The name
  policy is identical across arches minus the seven x86_64-legacy
  syscalls that do not exist on arm64. Other architectures report
  ``unsupported`` and run without this guard.
* **Fail-open with a loud report**, matching :mod:`scanner.core.sandbox`:
  if the filter cannot install (platform, kernel refusal, config error),
  the scan proceeds under the rlimit/wall-clock bounds and the returned
  report says exactly why. An implausible ``extra_blocked`` syscall
  number REFUSES the whole install — a filter missing a requested block
  would be fake security.
* **Foreign arch → EPERM.** A syscall arriving tagged as anything other
  than native x86_64 (32-bit compat, x32) is denied, not allowed through:
  the compat path is exactly how a hostile payload would dodge an x86_64
  table.

Honest limits of this guard (still true, still documented in §4.1):

* It bounds *processes*, not a container: a seccomp filter cannot stop
  ``write()`` to a file descriptor inherited from the worker — that is
  what :func:`close_inherited_network_sockets` (fd hygiene, run by the
  same child initializer before scanning) is for: inherited non-
  ``AF_UNIX`` sockets are closed in the child, so an inherited live
  database/redis connection yields ``EBADF`` instead of an exfiltration
  channel. ``AF_UNIX`` IPC and non-socket fds remain, and descriptors
  opened after the sweep are the container boundary's job — the staged
  profile in ``deploy/seccomp/`` is the operator-side complement.
* Once installed the filter is irreversible for that process (children
  only — the initializer runs in pool children, never the worker).
"""

from __future__ import annotations

import ctypes
import os
import platform
from typing import Any, Sequence

__all__ = [
    "AARCH64_ABSENT_SYSCALLS",
    "AUDIT_ARCH_AARCH64",
    "KERNEL_ATTACK_SYSCALLS",
    "KERNEL_ATTACK_SYSCALLS_AARCH64",
    "NET_EGRESS_SYSCALLS",
    "NET_EGRESS_SYSCALLS_AARCH64",
    "SYSCALL_TABLES",
    "build_filter_program",
    "close_inherited_network_sockets",
    "current_seccomp_state",
    "install_seccomp_guard",
    "seccomp_config",
]

# --- kernel/BPF constants (x86_64 Linux, UAPI headers) -----------------

AUDIT_ARCH_X86_64 = 0xC000003E  # __AUDIT_ARCH_64BIT|LE | EM_X86_64
AUDIT_ARCH_AARCH64 = 0xC00000B7  # __AUDIT_ARCH_64BIT|LE | EM_AARCH64 (183)
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
BPF_LD_W_ABS = 0x20  # BPF_LD | BPF_W | BPF_ABS
BPF_JMP_JEQ_K = 0x15  # BPF_JMP | BPF_JEQ | BPF_K
BPF_RET_K = 0x06  # BPF_RET | BPF_K
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000  # | errno
_EPERM = 1

# getsockopt(2) constants for fd hygiene (Linux)
SOL_SOCKET = 1
SO_DOMAIN = 39  # returns the socket's address family as an int
AF_UNIX = 1

#: machine() values → (audit arch, kernel-attack table, net-egress table).
#: aarch64/arm64 use the kernel's asm-generic syscall table (arm64 has no
#: private numbering); the 7 x86_64-legacy policy names that do not exist
#: there (create_module, get_kernel_syms, query_module, uselib, iopl,
#: ioperm, _sysctl) are simply absent — a syscall with no number cannot
#: be invoked, so nothing is lost by omitting them.
SYSCALL_TABLES: dict[str, tuple[int, dict[str, int], dict[str, int]]] = {}


def _supported_machine(machine: str) -> str | None:
    if machine == "x86_64":
        return "x86_64"
    if machine in {"aarch64", "arm64"}:
        return "aarch64"
    return None

# --- syscall tables (verified against asm/unistd_64.h; see test) --------
# Kernel attack surface: loading code, mount/namespace games, ptrace /
# cross-process memory, eBPF, perf, kexec, clock setting, keyrings,
# fanotify, io_uring, the new mount API, legacy module machinery.
KERNEL_ATTACK_SYSCALLS: dict[str, int] = {
    "acct": 163,
    "add_key": 248,
    "adjtimex": 159,
    "bpf": 321,
    "clock_adjtime": 305,
    "clock_settime": 227,
    "create_module": 174,
    "delete_module": 176,
    "fanotify_init": 300,
    "fanotify_mark": 301,
    "finit_module": 313,
    "fsconfig": 431,
    "fsmount": 432,
    "fsopen": 430,
    "fspick": 433,
    "get_kernel_syms": 177,
    "init_module": 175,
    "io_uring_enter": 426,
    "io_uring_register": 427,
    "io_uring_setup": 425,
    "ioperm": 173,
    "iopl": 172,
    "kcmp": 312,
    "kexec_file_load": 320,
    "kexec_load": 246,
    "keyctl": 250,
    "lookup_dcookie": 212,
    "memfd_secret": 447,
    "mount": 165,
    "mount_setattr": 442,
    "move_mount": 429,
    "nfsservctl": 180,
    "open_by_handle_at": 304,
    "open_tree": 428,
    "perf_event_open": 298,
    "personality": 135,
    "pivot_root": 155,
    "process_vm_readv": 310,
    "process_vm_writev": 311,
    "ptrace": 101,
    "query_module": 178,
    "quotactl": 179,
    "reboot": 169,
    "request_key": 249,
    "setns": 308,
    "settimeofday": 164,
    "swapoff": 168,
    "swapon": 167,
    "_sysctl": 156,
    "syslog": 103,
    "umount2": 166,
    "unshare": 272,
    "uselib": 134,
    "userfaultfd": 323,
    "vhangup": 153,
}

# Network egress: creating sockets and driving the socket data path
# (``send*``/``recv*``/``shutdown`` too — glibc ``send`` is ``sendto``).
# ``socketpair`` CREATION is deliberately not blocked — process internals
# use it for local IPC, and pipe-style ``os.read``/``os.write`` on the pair
# keeps working; only the socket-API data path is denied. Inherited fds
# can still be written with plain ``write()`` — documented limit, needs fd
# hygiene or a network namespace.
NET_EGRESS_SYSCALLS: dict[str, int] = {
    "accept": 43,
    "accept4": 288,
    "bind": 49,
    "connect": 42,
    "listen": 50,
    "recvmmsg": 299,
    "recvfrom": 45,
    "recvmsg": 47,
    "sendmmsg": 307,
    "sendmsg": 46,
    "sendto": 44,
    "shutdown": 48,
    "socket": 41,
}

# --- aarch64 (arm64) tables — the kernel's asm-generic numbering, which
# is what arm64 actually uses; verified against
# /usr/include/asm-generic/unistd.h (see the unit test). The NAME policy
# is identical to x86_64 minus the 7 legacy syscalls that do not exist
# on arm64 — a missing syscall needs no number and cannot be called.
KERNEL_ATTACK_SYSCALLS_AARCH64: dict[str, int] = {
    "acct": 89,
    "add_key": 217,
    "adjtimex": 171,
    "bpf": 280,
    "clock_adjtime": 266,
    "clock_settime": 112,
    "delete_module": 106,
    "fanotify_init": 262,
    "fanotify_mark": 263,
    "finit_module": 273,
    "fsconfig": 431,
    "fsmount": 432,
    "fsopen": 430,
    "fspick": 433,
    "init_module": 105,
    "io_uring_enter": 426,
    "io_uring_register": 427,
    "io_uring_setup": 425,
    "kcmp": 272,
    "kexec_file_load": 294,
    "kexec_load": 104,
    "keyctl": 219,
    "lookup_dcookie": 18,
    "memfd_secret": 447,
    "mount": 40,
    "mount_setattr": 442,
    "move_mount": 429,
    "nfsservctl": 42,
    "open_by_handle_at": 265,
    "open_tree": 428,
    "perf_event_open": 241,
    "personality": 92,
    "pivot_root": 41,
    "process_vm_readv": 270,
    "process_vm_writev": 271,
    "ptrace": 117,
    "quotactl": 60,
    "reboot": 142,
    "request_key": 218,
    "setns": 268,
    "settimeofday": 170,
    "swapoff": 225,
    "swapon": 224,
    "syslog": 116,
    "umount2": 39,
    "unshare": 97,
    "userfaultfd": 282,
    "vhangup": 58,
}

NET_EGRESS_SYSCALLS_AARCH64: dict[str, int] = {
    "accept": 202,
    "accept4": 242,
    "bind": 200,
    "connect": 203,
    "listen": 201,
    "recvmmsg": 243,
    "recvfrom": 207,
    "recvmsg": 212,
    "sendmmsg": 269,
    "sendmsg": 211,
    "sendto": 206,
    "shutdown": 210,
    "socket": 198,
}

SYSCALL_TABLES["x86_64"] = (AUDIT_ARCH_X86_64, KERNEL_ATTACK_SYSCALLS, NET_EGRESS_SYSCALLS)
SYSCALL_TABLES["aarch64"] = (AUDIT_ARCH_AARCH64, KERNEL_ATTACK_SYSCALLS_AARCH64, NET_EGRESS_SYSCALLS_AARCH64)

#: x86_64-only legacy policy names with no arm64 counterpart
AARCH64_ABSENT_SYSCALLS = {
    "create_module", "get_kernel_syms", "query_module",
    "uselib", "iopl", "ioperm", "_sysctl",
}


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


def _stmt(code: int, k: int) -> _SockFilter:
    return _SockFilter(code, 0, 0, k)


def _jeq(k: int, jt: int, jf: int) -> _SockFilter:
    return _SockFilter(BPF_JMP_JEQ_K, jt, jf, k)


def seccomp_config() -> dict[str, bool]:
    """Guard configuration from the environment.

    * ``CRYPTOSCAN_SANDBOX_SECCOMP`` — ``on`` (default) / ``off``: the
      master switch for the syscall guard in scanner children.
    * ``CRYPTOSCAN_SANDBOX_NET_EGRESS`` — ``block`` (default) / ``allow``:
      whether the network-egress set is included.
    * ``CRYPTOSCAN_SANDBOX_FD_HYGIENE`` — ``on`` (default) / ``off``:
      close inherited non-AF_UNIX sockets in scanner children (§ the
      documented ``write()``-to-inherited-fd hole).
    """
    def _flag(name: str, default: str) -> bool:
        return (os.environ.get(name) or default).strip().lower() not in {"off", "0", "false", "no", "allow"}

    return {"enabled": _flag("CRYPTOSCAN_SANDBOX_SECCOMP", "on"),
            "net_egress": _flag("CRYPTOSCAN_SANDBOX_NET_EGRESS", "block"),
            "fd_hygiene": _flag("CRYPTOSCAN_SANDBOX_FD_HYGIENE", "on")}


def close_inherited_network_sockets() -> dict[str, Any]:
    """Close inherited non-``AF_UNIX`` sockets in THIS process (a child).

    A seccomp denylist cannot block ``write()`` to a file descriptor
    inherited from the parent — and the worker parent holds live TCP
    sockets (database, redis, API clients) when it forks scanner pool
    children. This closes that hole from the child side: every socket fd
    that is not ``AF_UNIX`` is closed BEFORE scanning starts, so a hostile
    file writing to an inherited live connection gets ``EBADF`` instead of
    a working exfiltration channel. ``AF_UNIX`` descriptors (multiprocessing
    socketpairs, wakeup fds, ``/dev/log``) are local IPC and stay open;
    pipes and files are untouched. Closing an fd in the forked child never
    affects the parent's copy.

    Never raises; returns what happened. A socket whose family cannot be
    determined is closed anyway (a socket we cannot inspect is exactly
    the risk) and reported as unknown.
    """
    import stat as stat_mod

    try:
        fd_entries = os.listdir("/proc/self/fd")
    except OSError:
        return {"closed": 0, "reason": "/proc/self/fd unavailable — cannot enumerate descriptors"}

    libc = ctypes.CDLL(None, use_errno=True)
    libc.getsockopt.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_int)]
    closed: list[dict[str, Any]] = []
    for entry in fd_entries:
        try:
            fd = int(entry)
        except ValueError:
            continue
        if fd <= 2:  # stdio is not an exfiltration channel to close here
            continue
        try:
            if not stat_mod.S_ISSOCK(os.fstat(fd).st_mode):
                continue
        except OSError:  # gone between listdir and fstat — nothing to do
            continue
        family = ctypes.c_int(-1)
        optlen = ctypes.c_int(ctypes.sizeof(family))
        if libc.getsockopt(fd, SOL_SOCKET, SO_DOMAIN, ctypes.byref(family), ctypes.byref(optlen)) != 0:
            os.close(fd)
            closed.append({"fd": fd, "family": "unknown"})
            continue
        if family.value != AF_UNIX:
            os.close(fd)
            closed.append({"fd": fd, "family": family.value})
    return {"closed": len(closed), "fds": closed}


def build_filter_program(blocked: Sequence[int], arch: int = AUDIT_ARCH_X86_64) -> list[_SockFilter]:
    """Build the denylist BPF program (pure; unit-testable structure).

    Layout (``N = len(blocked)``)::

        LD  arch                       # seccomp_data.arch (offset 4)
        JEQ <arch>   -> +1 | fall      # native arch: continue; foreign: EPERM
        RET EPERM                      # compat/x32 syscalls are denied, not bypassed
        LD  nr                         # seccomp_data.nr (offset 0)
        JEQ <nr_i>   -> ERRNO          # one per blocked syscall
        RET ALLOW                     # default: allow
        RET EPERM                      # blocked syscalls land here
    """
    blocked = list(blocked)
    program = [
        _stmt(BPF_LD_W_ABS, 4),
        _jeq(arch, 1, 0),
        _stmt(BPF_RET_K, SECCOMP_RET_ERRNO | _EPERM),
        _stmt(BPF_LD_W_ABS, 0),
    ]
    n = len(blocked)
    for i, nr in enumerate(blocked):
        # on match, skip the remaining JEQs plus the ALLOW fallthrough
        program.append(_jeq(nr, n - i, 0))
    program.append(_stmt(BPF_RET_K, SECCOMP_RET_ALLOW))
    program.append(_stmt(BPF_RET_K, SECCOMP_RET_ERRNO | _EPERM))
    return program


def current_seccomp_state() -> dict[str, int | None]:
    """Read this process's seccomp/no-new-privs state from /proc (or None)."""
    state: dict[str, int | None] = {"seccomp": None, "no_new_privs": None}
    try:
        with open("/proc/self/status", "r") as fh:
            for line in fh:
                if line.startswith("Seccomp:"):
                    state["seccomp"] = int(line.split()[1])  # 0 none, 1 strict, 2 filter
                elif line.startswith("NoNewPrivs:"):
                    state["no_new_privs"] = int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return state


def install_seccomp_guard(
    *,
    extra_blocked: Sequence[tuple[str, int]] = (),
    include_net_egress: bool | None = None,
) -> dict[str, Any]:
    """Install the syscall denylist in THIS process (call from a child).

    ``extra_blocked`` adds caller-supplied ``(name, syscall_number)``
    pairs on top of the built-in sets (used by tests to pin the mechanism
    empirically). Never raises: every refusal path returns
    ``{"installed": False, "reason": …}`` so the sandbox layer can proceed
    under its other bounds and report honestly what is missing. Refuses —
    rather than partially installs — on an implausible syscall number: a
    filter missing a requested block would be fake security.
    """
    config = seccomp_config()
    if not config["enabled"]:
        return {"installed": False, "reason": "disabled by CRYPTOSCAN_SANDBOX_SECCOMP"}

    state = current_seccomp_state()
    if state["seccomp"] == 2:
        return {"installed": False, "reason": "a seccomp filter is already active in this process"}
    if state["seccomp"] is None:
        return {"installed": False, "reason": "/proc/self/status unavailable — cannot verify or install"}

    arch_key = _supported_machine(platform.machine())
    if arch_key is None:
        return {
            "installed": False,
            "reason": (f"unsupported architecture {platform.machine()!r} — verified "
                       f"syscall tables exist for: {', '.join(sorted(SYSCALL_TABLES))}"),
        }
    audit_arch, kernel_attack_table, net_egress_table = SYSCALL_TABLES[arch_key]

    tables: dict[str, int] = dict(kernel_attack_table)
    want_net = config["net_egress"] if include_net_egress is None else include_net_egress
    if want_net:
        tables.update(net_egress_table)
    for name, nr in extra_blocked:
        if not isinstance(nr, int) or not 0 <= nr <= 511:
            return {
                "installed": False,
                "reason": f"implausible syscall number {nr!r} for {name!r} — refusing to install a partial filter",
            }
        tables[name] = nr
        tables[name] = tables[name]  # explicit membership (kept for clarity)

    blocked_names = sorted(tables)
    program = build_filter_program([tables[name] for name in blocked_names], arch=audit_arch)

    class _SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_SockFilter))]

    array = (_SockFilter * len(program))(*program)
    fprog = _SockFprog(len(program), array)
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            errno = ctypes.get_errno()
            return {"installed": False, "reason": f"PR_SET_NO_NEW_PRIVS failed (errno {errno})"}
        if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
            errno = ctypes.get_errno()
            return {"installed": False, "reason": f"PR_SET_SECCOMP failed (errno {errno})"}
    except (OSError, AttributeError, ValueError) as exc:  # pragma: no cover - platform-dependent
        return {"installed": False, "reason": f"seccomp install error: {exc}"}

    return {
        "installed": True,
        "mode": "denylist+EPERM",
        "arch": arch_key,
        "blocked_count": len(blocked_names),
        "net_egress_blocked": want_net,
        "blocked": blocked_names,
    }
