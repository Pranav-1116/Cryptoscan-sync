"""Seccomp syscall guard for scanner children (§4.1, round 51).

The tests prove the MECHANISM empirically, in forked children only (the
guard is irreversible for a process, so nothing here ever filters the
pytest process itself): a requested syscall starts returning EPERM after
the install, network egress (socket creation) is refused while file work
and local socketpair IPC keep working, the guard is off/on exactly as the
environment says, pool children that scan real files run with the filter
active, and the syscall numbers were checked against the kernel's own
unistd table.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import platform
import pytest

from scanner.core.sandbox import apply_child_limits, run_in_sandbox
from scanner.core.seccomp_guard import (
    AUDIT_ARCH_X86_64,
    BPF_JMP_JEQ_K,
    BPF_LD_W_ABS,
    KERNEL_ATTACK_SYSCALLS,
    NET_EGRESS_SYSCALLS,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO,
    build_filter_program,
    close_inherited_network_sockets,
    current_seccomp_state,
    install_seccomp_guard,
)

# empirical tests need Linux fork + the one verified syscall table
_EMPIRICAL = pytest.mark.skipif(
    platform.machine() != "x86_64" or not hasattr(os, "fork"),
    reason="guard ships a verified syscall table for x86_64 Linux only",
)

_HEADER = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"


def test_filter_program_structure_is_the_documented_layout():
    program = build_filter_program([300, 41])
    assert len(program) == 8  # 4 fixed + 2 comparisons + 2 returns
    assert (program[0].code, program[0].k) == (BPF_LD_W_ABS, 4)      # arch
    assert (program[1].code, program[1].k) == (BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64)
    assert program[1].jt == 1                                          # native arch -> next+1
    assert program[2].k == SECCOMP_RET_ERRNO | 1                       # foreign arch -> EPERM
    assert (program[3].code, program[3].k) == (BPF_LD_W_ABS, 0)       # syscall nr
    # blocked[0]=300: on match skip 1 remaining compare + ALLOW -> jt=2
    assert (program[4].code, program[4].k) == (BPF_JMP_JEQ_K, 300) and program[4].jt == 2
    # blocked[1]=41: on match skip just the ALLOW -> jt=1
    assert (program[5].code, program[5].k) == (BPF_JMP_JEQ_K, 41) and program[5].jt == 1
    assert program[6].k == SECCOMP_RET_ALLOW                           # default: allow
    assert program[7].k == SECCOMP_RET_ERRNO | 1                       # blocked: EPERM
    # empty denylist still well-formed
    empty = build_filter_program([])
    assert len(empty) == 6 and empty[-1].k == SECCOMP_RET_ERRNO | 1


def test_syscall_tables_match_the_kernel_header():
    """Every shipped number is the kernel's own __NR_* value (x86_64)."""
    if platform.machine() != "x86_64" or not os.path.exists(_HEADER):
        pytest.skip("kernel unistd header not available for verification")
    header: dict[str, int] = {}
    with open(_HEADER) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) == 3 and parts[0] == "#define" and parts[1].startswith("__NR_"):
                header[parts[1][len("__NR_"):]] = int(parts[2])
    checked = {**KERNEL_ATTACK_SYSCALLS, **NET_EGRESS_SYSCALLS,
               "uname": 63, "chdir": 80, "socketpair": 53}  # + the numbers tests rely on
    wrong = {name: (nr, header.get(name)) for name, nr in checked.items() if header.get(name) != nr}
    assert not wrong, f"table numbers diverge from { _HEADER }: {wrong}"


@_EMPIRICAL
def test_guard_blocks_a_requested_syscall_empirically(monkeypatch, tmp_path):
    """uname works before the install and returns EPERM after it — the
    filter is what changed the outcome, and only in the child."""
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_SECCOMP", raising=False)

    def _child(path: str):
        out = {"before": os.uname().sysname}
        report = install_seccomp_guard(extra_blocked=[("uname", 63)], include_net_egress=False)
        try:
            os.uname()
            out["after"] = "allowed"
        except PermissionError as exc:
            out["after"] = f"eperm-{exc.errno}"
        out["installed"] = report["installed"]
        out["state"] = current_seccomp_state()
        with open(path, "w") as fh:  # file I/O must still work under the filter
            fh.write("ok")
        return out

    out, error = run_in_sandbox(_child, (str(tmp_path / "probe"),),
                                install_seccomp=False, timeout_s=30)
    assert error is None, error
    assert out["before"] == "Linux"
    assert out["installed"] is True
    assert out["after"] == "eperm-1", "the guard must turn the syscall into EPERM, not kill or pass"
    assert out["state"]["seccomp"] == 2 and out["state"]["no_new_privs"] == 1
    assert (tmp_path / "probe").read_text() == "ok"


@_EMPIRICAL
def test_guard_blocks_network_egress_but_not_scanner_work(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_SECCOMP", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_NET_EGRESS", raising=False)

    def _child():
        import socket
        out = {}
        try:  # hostile payload phoning home from a scanner child:
            socket.create_connection(("127.0.0.1", 1), timeout=1)
            out["connect"] = "allowed"
        except PermissionError as exc:
            out["connect"] = f"eperm-{exc.errno}"
        except OSError:
            out["connect"] = "other-oserror"
        try:
            socket.socket()
            out["socket"] = "allowed"
        except PermissionError as exc:
            out["socket"] = f"eperm-{exc.errno}"
        try:  # socket-API data path must be denied even on a local pair
            a, b = socket.socketpair()
            a.send(b"ping")
            out["send"] = "allowed"
        except PermissionError as exc:
            out["send"] = f"eperm-{exc.errno}"
        # pipe-style I/O on the same pair (what mp internals use) works:
        a, b = socket.socketpair()
        os.write(a.fileno(), b"ping")
        out["socketpair"] = os.read(b.fileno(), 4).decode()
        a.close(); b.close()
        out["stat"] = os.stat("/etc/hostname").st_size > 0
        return out

    out, error = run_in_sandbox(_child, timeout_s=30)  # default config: guard on, egress blocked
    assert error is None, error
    assert out["socket"] == "eperm-1"
    assert out["connect"] == "eperm-1"
    assert out["send"] == "eperm-1"
    assert out["socketpair"] == "ping"
    assert out["stat"] is True


@_EMPIRICAL
def test_guard_off_by_environment_is_a_real_control(monkeypatch):
    """With the env switch off, sockets work and no filter exists — the
    control that proves the EPERMs above came from this guard."""
    monkeypatch.setenv("CRYPTOSCAN_SANDBOX_SECCOMP", "off")

    def _child():
        import socket
        socket.socket().close()
        return current_seccomp_state()

    out, error = run_in_sandbox(_child, timeout_s=30)
    assert error is None, error
    assert out["seccomp"] == 0 and out["no_new_privs"] == 0


def _pool_probe():
    """Runs INSIDE a pool child (module level so it pickles): reports the
    guard's state, a refused socket creation and a successful file read."""
    import socket

    out = {"state": current_seccomp_state()}
    try:
        socket.socket()
        out["socket"] = "allowed"
    except PermissionError as exc:
        out["socket"] = f"eperm-{exc.errno}"
    out["read"] = bool(open("/etc/hostname").read())
    return out


@_EMPIRICAL
def test_pool_children_scan_files_behind_the_filter(monkeypatch, tmp_path):
    """The scanner's own pool initializer hardens every child: seccomp
    filter active, no-new-privs set, socket creation refused — while the
    child still reads files (the scan work itself)."""
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_SECCOMP", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_NET_EGRESS", raising=False)

    ctx = mp.get_context("fork")
    with ctx.Pool(processes=1, initializer=apply_child_limits) as pool:
        out = pool.apply(_pool_probe)
    assert out["state"]["seccomp"] == 2 and out["state"]["no_new_privs"] == 1
    assert out["socket"] == "eperm-1"
    assert out["read"] is True


@_EMPIRICAL
def test_implausible_number_refuses_the_whole_install(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_SECCOMP", raising=False)

    def _child():
        report = install_seccomp_guard(extra_blocked=[("hax", 99999)])
        return {"report": report, "state": current_seccomp_state(),
                "uname": os.uname().release}  # nothing was blocked

    out, error = run_in_sandbox(_child, install_seccomp=False, timeout_s=30)
    assert error is None, error
    assert out["report"]["installed"] is False
    assert "refusing" in out["report"]["reason"]
    assert out["state"]["seccomp"] == 0, "a refused install must leave no filter behind"
    assert out["uname"]


@_EMPIRICAL
def test_second_install_reports_already_active_instead_of_stacking(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_SECCOMP", raising=False)

    def _child():
        first = install_seccomp_guard(include_net_egress=False)
        second = install_seccomp_guard()
        return {"first": first, "second": second}

    out, error = run_in_sandbox(_child, install_seccomp=False, timeout_s=30)
    assert error is None, error
    assert out["first"]["installed"] is True
    assert out["second"]["installed"] is False
    assert "already active" in out["second"]["reason"]


# ---------------------------------------------------------------------------
# Round 52 — fd hygiene: the write()-to-inherited-socket hole
# ---------------------------------------------------------------------------

def _loopback_pair():
    """A connected TCP pair on loopback: (listener, client). The child
    inherits the client fd at fork — exactly the "live database/redis
    socket" the guard's syscall filter cannot police."""
    import socket

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client = socket.socket()
    client.connect(server.getsockname())
    return server, client


def _count_inet_fds() -> int:
    """How many AF_INET/AF_INET6 socket fds this process still holds."""
    import stat as stat_mod
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    libc.getsockopt.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    count = 0
    for entry in os.listdir("/proc/self/fd"):
        try:
            fd = int(entry)
        except ValueError:
            continue
        try:
            if not stat_mod.S_ISSOCK(os.fstat(fd).st_mode):
                continue
        except OSError:
            continue
        family = ctypes.c_int(-1)
        optlen = ctypes.c_int(4)
        if libc.getsockopt(fd, 1, 39, ctypes.byref(family), ctypes.byref(optlen)) == 0:
            if family.value in (2, 10):  # AF_INET, AF_INET6
                count += 1
    return count


@_EMPIRICAL
def test_inherited_socket_hole_is_real_without_hygiene(monkeypatch):
    """CONTROL (the honest hole): with fd hygiene off, a scanner child —
    seccomp guard fully active — writes to the inherited TCP socket with
    plain write(), which no syscall denylist can block, and the bytes
    arrive at the listener. This is why fd hygiene exists."""
    monkeypatch.setenv("CRYPTOSCAN_SANDBOX_FD_HYGIENE", "off")
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_SECCOMP", raising=False)

    server, client = _loopback_pair()
    fd = client.fileno()

    def _child(target_fd: int):
        out = {"state": current_seccomp_state()}
        try:  # the hostile payload: exfiltrate through the inherited fd
            os.write(target_fd, b"exfil")
            out["write"] = "ok"
        except OSError as exc:
            out["write"] = f"oserror-{exc.errno}"
        report = apply_child_limits(install_seccomp=False)  # hygiene env state
        out["hygiene_reason"] = report["fd_hygiene"].get("reason")
        return out

    out, error = run_in_sandbox(_child, (fd,), timeout_s=30)
    conn, _ = server.accept()
    conn.settimeout(2)
    received = b""
    try:
        received = conn.recv(16)
    except OSError:
        pass
    assert error is None, error
    assert out["state"]["seccomp"] == 2, "the R51 guard is active in this child"
    assert out["write"] == "ok", "write() to the inherited socket must be permitted (syscall level)"
    assert received == b"exfil", "the bytes reached the listener — the hole is real"
    assert out["hygiene_reason"] == "disabled by CRYPTOSCAN_SANDBOX_FD_HYGIENE"
    client.close(); conn.close(); server.close()


@_EMPIRICAL
def test_fd_hygiene_closes_the_inherited_socket_in_the_child(monkeypatch):
    """WITH hygiene (default): the inherited TCP fd is closed in the child
    before the payload runs — write() gets EBADF, no AF_INET socket
    remains, and the parent's own copy is untouched."""
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_FD_HYGIENE", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_SECCOMP", raising=False)

    server, client = _loopback_pair()
    fd = client.fileno()

    def _child(target_fd: int):
        out = {"state": current_seccomp_state()}
        try:
            os.fstat(target_fd)
            out["fd"] = "open"
        except OSError as exc:
            out["fd"] = f"closed-{exc.errno}"
        try:
            os.write(target_fd, b"exfil")
            out["write"] = "ok"
        except OSError as exc:
            out["write"] = f"oserror-{exc.errno}"
        out["inet_fds_left"] = _count_inet_fds()
        return out

    out, error = run_in_sandbox(_child, (fd,), timeout_s=30)
    assert error is None, error
    assert out["state"]["seccomp"] == 2
    assert out["fd"] == "closed-9", "EBADF — hygiene closed the inherited socket"
    assert out["write"] == "oserror-9"
    assert out["inet_fds_left"] == 0
    os.fstat(fd)  # the PARENT's copy is unaffected
    client.close(); server.close()


@_EMPIRICAL
def test_fd_hygiene_preserves_unix_ipc_and_files(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_FD_HYGIENE", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_SECCOMP", raising=False)

    import socket
    a, b = socket.socketpair()  # AF_UNIX — local IPC, must survive hygiene

    def _child(fd_a: int, fd_b: int, path: str):
        out = {}
        os.write(fd_a, b"ping")
        out["unix_pair"] = os.read(fd_b, 4).decode()
        with open(path) as fh:
            out["file"] = fh.read()
        out["closed_report"] = close_inherited_network_sockets()  # idempotent sweep
        return out

    marker = "/etc/hostname"
    out, error = run_in_sandbox(_child, (a.fileno(), b.fileno(), marker), timeout_s=30)
    assert error is None, error
    assert out["unix_pair"] == "ping"
    assert out["file"]
    assert out["closed_report"]["closed"] == 0, "second sweep finds nothing left to close"
    a.close(); b.close()


def _pool_fd_probe(fd: int):
    """Runs INSIDE a pool child: the initializer's hygiene must have closed
    the inherited TCP fd while local file work keeps working."""
    out = {"state": current_seccomp_state()}
    try:
        os.fstat(fd)
        out["fd"] = "open"
    except OSError as exc:
        out["fd"] = f"closed-{exc.errno}"
    out["inet_fds_left"] = _count_inet_fds()
    out["read"] = bool(open("/etc/hostname").read())
    return out


@_EMPIRICAL
def test_pool_children_close_inherited_sockets(monkeypatch):
    """The scanner's own pool initializer performs fd hygiene in every
    child: inherited TCP socket closed, no AF_INET fds remain, files still
    readable."""
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_FD_HYGIENE", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_SECCOMP", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_SANDBOX_NET_EGRESS", raising=False)

    server, client = _loopback_pair()
    ctx = mp.get_context("fork")
    with ctx.Pool(processes=1, initializer=apply_child_limits) as pool:
        out = pool.apply(_pool_fd_probe, (client.fileno(),))
    assert out["state"]["seccomp"] == 2
    assert out["fd"] == "closed-9"
    assert out["inet_fds_left"] == 0
    assert out["read"] is True
    client.close(); server.close()
