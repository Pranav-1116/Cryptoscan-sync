"""Process-level crypto discovery — what's running, with which TLS libraries.

Walks /proc (no root required for same-user processes) to answer:

- which processes have TLS libraries mapped (OpenSSL, GnuTLS, NSS,
  wolfSSL, mbedTLS, BoringSSL, LibreSSL) and which *versions*
- which processes are listening on TCP (potential TLS endpoints)
- which processes are containerized (cgroup markers) or JVM-based
- risk verdicts per library version (EOL, weak-TLS capable)

The base directory is injectable so tests run against fixture /proc trees.
"""

from __future__ import annotations

import os
import re
import socket
from typing import Any

from runtime.agent.library_risk import assess_library

TLS_LIBRARY_PATTERNS: tuple[tuple[str, str], ...] = (
    ("openssl", r"lib(?:ssl|crypto)\.so(?:\.(?P<version>[\d.]+))?"),
    ("gnutls", r"libgnutls\.so(?:\.(?P<version>[\d.]+))?"),
    ("nss", r"lib(?!spr)nss3\.so"),
    ("nspr", r"libnspr4\.so"),
    ("wolfssl", r"libwolfssl\.so(?:\.(?P<version>[\d.]+))?"),
    ("mbedtls", r"libmbedcrypto\.so(?:\.(?P<version>[\d.]+))?"),
    ("boringssl", r"libboringssl(?:-dynamic)?\.so"),
    ("libressl", r"libressl-crypto\.so(?:\.(?P<version>[\d.]+))?"),
    ("java", r"libjvm\.so"),
    ("dotnet", r"libcoreclr\.so|libclrjit\.so"),
    ("go-crypto", r"/usr/local/go/|/usr/lib/go"),
)

_LISTEN_STATE = "0A"  # TCP LISTEN
_CONTAINER_MARKERS = ("docker", "containerd", "kubepods", "libpod", "lxc")


def scan_processes(
    base: str = "/proc",
    *,
    include_kernel_threads: bool = False,
    crypto_only: bool = True,
) -> dict[str, Any]:
    """Inventory processes + crypto library usage + listening sockets.

    Kernel threads (``kworker/*``, ``irq/*``, ``rcu*`` ...) have an empty
    ``cmdline`` and no userspace memory mappings, so they can never carry TLS
    libraries or listeners. They are skipped by default. With ``crypto_only``
    (the default) the returned ``processes`` list is further reduced to the
    processes that actually matter for a crypto audit — those with TLS/crypto
    libraries mapped or a listening TCP socket — while the counts over the full
    process set are still reported. Pass ``crypto_only=False`` for every
    userspace process.
    """
    inventory: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    listening_sockets = _listening_sockets(base)
    kernel_skipped = 0

    # Skip the scanner's own process (and its parent launcher, usually the
    # shell/cli wrapper): cataloguing the tool itself is noise that inflates
    # findings. Only applied when reading the real /proc.
    skip_pids: set[int] = set()
    if base == "/proc":
        skip_pids.add(os.getpid())
        ppid = os.getppid()
        if ppid and ppid != 1:
            skip_pids.add(ppid)

    for entry in _numeric_dirs(base):
        pid = int(entry)
        if pid in skip_pids:
            continue
        comm = _read_first_line(base, pid, "comm") or str(pid)
        cmdline = _read_cmdline(base, pid)
        # Kernel threads have an empty cmdline on real /proc and no userspace
        # mappings, so they never map TLS libraries or hold sockets. Skip them
        # (gated to real /proc so fixture scans are unaffected).
        if base == "/proc" and not include_kernel_threads and not cmdline:
            kernel_skipped += 1
            continue
        maps = _read_maps(base, pid)
        libs = _library_versions(maps)
        containerized = _is_containerized(base, pid)
        ports = listening_sockets.get(pid, [])

        # Resolve each library's real version (via package manager) and attach
        # the risk verdict to the inventory entry, so callers can see ALLOWED
        # and UNKNOWN (unmanaged/bundled) libraries too — not just risks.
        resolved_libs: list[dict[str, Any]] = []
        for lib in libs:
            resolved = _resolve_library_version(lib)
            verdict = assess_library(lib["library"], resolved["version"])
            enriched = {
                **lib,
                "version": resolved["version"] or lib.get("version"),
                "version_source": resolved["source"],
                "package": resolved["package"],
                "package_version": resolved["package_version"],
                "status": verdict["status"],
                "library_name": verdict["library_name"],
                "notes": verdict["notes"],
            }
            resolved_libs.append(enriched)
            # Emit a finding only for a *positive* risk verdict. UNKNOWN means
            # the version could not be established (unmanaged bundled lib),
            # which is an inventory observation, not a defect.
            if verdict["status"] in {"DISALLOWED", "DEPRECATED", "RESTRICTED"}:
                findings.append(
                    {
                        "process_name": comm,
                        "pid": pid,
                        "library": lib["library"],
                        "version": resolved["version"],
                        "version_source": resolved["source"],
                        "package": resolved["package"],
                        "package_version": resolved["package_version"],
                        **verdict,
                        "listening_ports": ports,
                        "containerized": containerized,
                    }
                )

        row: dict[str, Any] = {
            "pid": pid,
            "process_name": comm,
            "cmdline": cmdline[:200],
            "tls_libraries": [lib["library"] for lib in resolved_libs],
            "library_details": resolved_libs,
            "containerized": containerized,
            "listening_ports": ports,
            "runtime": _runtime_of(comm, cmdline, maps),
        }
        inventory.append(row)


    # Only narrow the output for a real /proc scan; injected fixture trees
    # (tests) keep their full inventory regardless of crypto_only.
    apply_crypto_filter = crypto_only and base == "/proc"
    crypto_procs = [p for p in inventory if p["tls_libraries"] or p["listening_ports"]]
    shown = crypto_procs if apply_crypto_filter else inventory
    return {
        "host": _host_identifier(),
        "process_count": len(shown),
        "total_processes_scanned": len(inventory),
        "kernel_threads_skipped": kernel_skipped,
        "processes_with_tls_libraries": sum(1 for p in inventory if p["tls_libraries"]),
        "listening_processes": sum(1 for p in inventory if p["listening_ports"]),
        "processes": shown,
        "findings": findings,
    }


# --------------------------------------------------------------------------- #
# helpers (all tolerant of missing/permission-denied /proc entries)
# --------------------------------------------------------------------------- #


def _host_identifier() -> str:
    """Best-effort hostname for this host.

    HOSTNAME is exported by most shells/systemd but is not guaranteed; fall
    back to the kernel-reported nodename, then "unknown".
    """
    name = os.environ.get("HOSTNAME") or os.environ.get("CRYPTOSCAN_HOSTNAME")
    if name:
        return name.strip() or "unknown"
    try:
        return socket.gethostname() or "unknown"
    except OSError:
        return "unknown"



def _numeric_dirs(base: str) -> list[str]:
    try:
        return [d for d in os.listdir(base) if d.isdigit()]
    except OSError:
        return []


def _read_first_line(base: str, pid: int, name: str) -> str | None:
    try:
        with open(os.path.join(base, str(pid), name), encoding="utf-8", errors="replace") as handle:
            return handle.readline().strip()
    except OSError:
        return None


def _read_cmdline(base: str, pid: int) -> str:
    try:
        with open(os.path.join(base, str(pid), "cmdline"), "rb") as handle:
            return handle.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def _read_maps(base: str, pid: int) -> str:
    try:
        with open(os.path.join(base, str(pid), "maps"), encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _resolve_library_version(lib: dict[str, Any]) -> dict[str, Any]:
    """Return {package, package_version, version, source} for a matched lib.

    The mapped filename only carries an ABI soname (e.g. libssl.so.3,
    libgnutls.so.30), which is *not* a release version. Prefer the real
    upstream version owned by the OS package manager; fall back to the
    filename-derived tag (kept only for display, treated as unversioned by the
    risk layer) for unmanaged/bundled copies.
    """
    from runtime.agent.version_resolve import resolve_path

    info = resolve_path(lib.get("path"))
    if info.get("version"):
        return {
            "package": info["package"],
            "package_version": info["package_version"],
            "version": info["version"],
            "source": info["source"],
        }
    # No OS-package owner (browser-bundled NSS/BoringSSL, snap/flatpak/opt).
    # Report the filename tag for inventory but let the risk layer return
    # UNKNOWN so no false EOL verdict is emitted.
    return {
        "package": None,
        "package_version": None,
        "version": lib.get("version"),
        "source": lib.get("note", "filename"),
    }


def _library_versions(maps: str) -> list[dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for line in maps.splitlines():
        path = line.rstrip().rsplit(" ", 1)[-1].strip()
        if not path.startswith("/"):
            continue
        for family, pattern in TLS_LIBRARY_PATTERNS:
            match = re.search(pattern, path)
            if not match:
                continue
            version = (match.groupdict().get("version") or "").rstrip(".") or None
            existing = found.get(family)
            if existing is None or (version and not existing.get("version")):
                found[family] = {
                    "library": family,
                    "version": version,
                    "path": path,
                    **({"note": "version from filename"} if version else {}),
                }
            break
    return sorted(found.values(), key=lambda item: item["library"])


def _is_containerized(base: str, pid: int) -> bool:
    try:
        with open(os.path.join(base, str(pid), "cgroup"), encoding="utf-8", errors="replace") as handle:
            text = handle.read().lower()
        return any(marker in text for marker in _CONTAINER_MARKERS)
    except OSError:
        return False


def _runtime_of(comm: str, cmdline: str, maps: str) -> str:
    cmd = (cmdline or comm).lower()
    first = cmd.split()[0].rsplit("/", 1)[-1] if cmd.split() else ""
    if "libjvm" in maps or first.startswith("java"):
        return "jvm"
    if "/usr/local/go/" in maps or first == "go" or first.startswith("go1.") or "/goroot" in maps:
        return "go"
    if first.startswith("node"):
        return "node"
    if first.startswith("python") or first.startswith("pypy"):
        return "python"
    if first.startswith("dotnet"):
        return "dotnet"
    if any(token in cmd for token in ("nginx", "envoy", "haproxy", "istio", "caddy", "traefik")):
        return "proxy"
    return "native"


def _listening_sockets(base: str) -> dict[int, list[int]]:
    """pid -> listening TCP ports, joined from /proc/net/tcp{,6} and per-pid fds."""
    port_by_inode: dict[str, int] = {}
    for table in ("net/tcp", "net/tcp6"):
        path = os.path.join(base, table)
        if not os.path.exists(path):
            continue
        try:
            lines = open(path, encoding="utf-8", errors="replace").read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != _LISTEN_STATE:
                continue
            try:
                port = int(fields[1].rsplit(":", 1)[-1], 16)
                inode = fields[9]
            except ValueError:
                continue
            if port:
                port_by_inode[inode] = port

    pid_ports: dict[int, list[int]] = {}
    if not port_by_inode:
        return pid_ports
    for entry in _numeric_dirs(base):
        pid = int(entry)
        fd_dir = os.path.join(base, entry, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target.startswith("socket:[") and target[8:-1] in port_by_inode:
                pid_ports.setdefault(pid, []).append(port_by_inode[target[8:-1]])
    for ports in pid_ports.values():
        ports.sort()
    return pid_ports
