"""Live performance samples for ZELNX Performance Intelligence.

The BOM planes say *what* a server is. This module says *how it is running*, every
``performance_interval`` seconds (default 60), from the same inside view:

| Metric (performance taxonomy)  | Read from                                                  |
| ------------------------------ | ---------------------------------------------------------- |
| ``cpu.utilization_pct``        | ``/proc/stat`` (host) · ``/proc/<pid>/stat`` (workload)     |
| ``ram.utilization_pct``        | ``/proc/meminfo`` (host) · ``VmRSS`` of the server's processes |
| ``container.memory_bytes``     | workload only: resident memory of the server's processes   |
| ``system.load``                | host only: ``/proc/loadavg``                               |
| ``process.health``             | process states (zombies make it unhealthy)                 |
| ``storage.*``                  | ``statvfs`` of the server's root filesystem                |
| ``disk.iops/throughput/latency`` | ``/proc/diskstats`` (host) · ``/proc/<pid>/io`` (workload) |
| ``network.throughput_mbps``    | ``/proc/net/dev`` (the server's own interfaces)            |
| ``network.bandwidth_mbps``     | ``/sys/class/net/<if>/speed``                              |
| ``network.connections``        | established sockets in ``/proc/net/tcp{,6}``               |
| ``network.tcp_retransmissions``| ``/proc/net/snmp`` ``RetransSegs``                          |
| ``network.interface_errors``   | ``/proc/net/dev`` error counters                           |
| ``crypto.tls_handshake_ms``    | a timed TLS handshake to each of the server's TLS listeners |
| ``crypto.tls_negotiation_failures`` | a TLS listener that handshook before and now fails    |
| ``crypto.hsm_operation_latency_ms`` | ``hsm_probe``: TLS connect + first response from the HSM |

**Scope.** On a server or VM the agent sees the whole machine (``host``). As a sidecar
container beside one workload, ``/proc/stat`` and ``/proc/meminfo`` describe the
container *host*, not the bank server — so the agent measures the server's own
processes instead (``workload``) and labels every figure with the scope it used.

Honesty rules (docs/performance/01_PRODUCT_SPEC.md): a figure the agent could not
read is sent as ``quality: missing`` with the reason — never as a zero; a rate needs
two readings, so the first sample after start takes a one-second pair; nothing here
reads a command line, a payload or a key.
"""

from __future__ import annotations

import os
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Callable

from cryptava.util import HostView

SCHEMA = "cryptoscan.cryptava-performance/1"
DEFAULT_PATH = "/api/v1/control/agents/heartbeat/performance"
MAX_TLS_PORTS = 6
NON_TLS_RETRY_SAMPLES = 15   # a port that did not speak TLS is re-tried every ~15 minutes
_CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100


# --------------------------------------------------------------------------- #
# readers — each returns raw counters; rates are computed from two readings
# --------------------------------------------------------------------------- #

def _ints(text: str | None) -> list[int]:
    out = []
    for part in (text or "").split():
        try:
            out.append(int(part))
        except ValueError:
            pass
    return out


def _proc_stat_fields(text: str) -> tuple[str, list[str]] | None:
    """``/proc/<pid>/stat`` → (state, fields after the comm). The comm may hold spaces."""
    close = text.rfind(")")
    if close < 0:
        return None
    rest = text[close + 2:].split()
    return (rest[0], rest) if rest else None


def detect_scope(config: dict[str, Any], view: HostView) -> str:
    wanted = str(config.get("performance_scope") or "auto").lower()
    if wanted in ("host", "workload"):
        return wanted
    # a sidecar reads the server through /proc/1/root; a container sees the container
    # host's /proc/stat — both mean "measure the server's processes"
    if str(view.root) != "/" and str(view.root).startswith(str(view.proc)):
        return "workload"
    for marker in ("/.dockerenv", "/run/.containerenv"):
        if os.path.exists(marker):
            return "workload"
    return "host"


class Sampler:
    """Reads counters, keeps the previous reading in memory, emits one sample."""

    def __init__(self, config: dict[str, Any], view: HostView, *,
                 tls_probe: Callable[[str, int, float], dict[str, Any] | None] | None = None,
                 hsm_probe: Callable[[str, int, float], float | None] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.config = config
        self.view = view
        self.scope = detect_scope(config, view)
        self.tls_probe = tls_probe or timed_tls_handshake
        self.hsm_probe = hsm_probe or timed_hsm_response
        self.clock = clock
        self.sleep = sleep
        self.previous: dict[str, Any] | None = None
        self.tls_ok: set[int] = set()
        self.non_tls: dict[int, int] = {}   # port -> samples until the next re-try
        self._own_root = self._root_id("self")

    # -- process view --------------------------------------------------------- #
    def _root_id(self, pid: str) -> tuple[int, int] | None:
        try:
            st = os.stat(self.view.proc / pid / "root")
        except OSError:
            return None
        return (st.st_dev, st.st_ino)

    def _server_pids(self) -> list[str]:
        """Every process of the server — in a shared PID namespace, the agent's own
        container (same root filesystem as this process) is left out."""
        try:
            entries = [e for e in os.listdir(self.view.proc) if e.isdigit()]
        except OSError:
            return []
        own = str(os.getpid())
        out = []
        for pid in entries:
            if pid == own:
                continue
            if self.scope == "workload" and self._own_root is not None and self._root_id(pid) == self._own_root:
                continue
            out.append(pid)
        return out

    def _processes(self) -> dict[str, Any]:
        ticks = rss = io_bytes = 0
        io_readable = 0
        states: dict[str, int] = {}
        pids = self._server_pids()
        for pid in pids:
            parsed = _proc_stat_fields(self.view.proc_text(f"{pid}/stat", limit=4096) or "")
            if parsed is None:
                continue
            state, fields = parsed
            states[state] = states.get(state, 0) + 1
            try:
                ticks += int(fields[11]) + int(fields[12])   # utime + stime
            except (IndexError, ValueError):
                pass
            for line in (self.view.proc_text(f"{pid}/status", limit=8192) or "").splitlines():
                if line.startswith("VmRSS:"):
                    rss += (_ints(line[6:]) or [0])[0] * 1024
                    break
            io = self.view.proc_text(f"{pid}/io", limit=2048)
            if io:
                io_readable += 1
                for line in io.splitlines():
                    if line.startswith(("read_bytes:", "write_bytes:")):
                        io_bytes += (_ints(line.split(":", 1)[1]) or [0])[0]
        return {"count": sum(states.values()), "states": states, "ticks": ticks, "rss": rss,
                "io_bytes": io_bytes if io_readable else None}

    # -- counters ------------------------------------------------------------- #
    def _read(self) -> dict[str, Any]:
        reading: dict[str, Any] = {"t": self.clock(), "procs": self._processes()}
        stat = self.view.proc_text("stat", limit=64 * 1024) or ""
        for line in stat.splitlines():
            if line.startswith("cpu "):
                values = _ints(line[4:])
                if len(values) >= 4:
                    idle = values[3] + (values[4] if len(values) > 4 else 0)
                    reading["cpu"] = (sum(values[:8]), idle)
                break
        meminfo: dict[str, int] = {}
        for line in (self.view.proc_text("meminfo", limit=16 * 1024) or "").splitlines():
            key, _, rest = line.partition(":")
            if key in ("MemTotal", "MemAvailable"):
                meminfo[key] = (_ints(rest) or [0])[0] * 1024
        reading["mem"] = meminfo
        load = (self.view.proc_text("loadavg", limit=256) or "").split()
        if load:
            try:
                reading["load1"] = float(load[0])
            except ValueError:
                pass
        disks = self._diskstats()
        if disks is not None:
            reading["disk"] = disks
        net = self._netdev()
        if net is not None:
            reading["net"] = net
        reading["retrans"] = self._retrans()
        reading["established"] = self._established()
        return reading

    def _diskstats(self) -> tuple[int, int, int] | None:
        text = self.view.proc_text("diskstats", limit=256 * 1024)
        if not text:
            return None
        ios = sectors = busy_ms = 0
        seen = False
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 14:
                continue
            name = parts[2]
            if name.startswith(("loop", "ram", "zram", "dm-", "sr", "fd")):
                continue
            # whole disks only: partitions would count every I/O twice
            if self.view.sys_text(f"block/{name}/dev") is None and os.path.isdir(self.view.sys / "block"):
                continue
            nums = _ints(" ".join(parts[3:]))
            if len(nums) < 11:
                continue
            ios += nums[0] + nums[4]
            sectors += nums[2] + nums[6]
            busy_ms += nums[3] + nums[7]
            seen = True
        return (ios, sectors, busy_ms) if seen else None

    def _netdev(self) -> dict[str, tuple[int, int]] | None:
        text = self.view.proc_text("net/dev", limit=256 * 1024)
        if not text:
            return None
        out: dict[str, tuple[int, int]] = {}
        for line in text.splitlines()[2:]:
            name, _, rest = line.partition(":")
            name = name.strip()
            if not name or name == "lo":
                continue
            nums = _ints(rest)
            if len(nums) < 16:
                continue
            out[name] = (nums[0] + nums[8], nums[2] + nums[10])   # bytes rx+tx, errs rx+tx
        return out

    def _retrans(self) -> int | None:
        lines = [line for line in (self.view.proc_text("net/snmp", limit=64 * 1024) or "").splitlines()
                 if line.startswith("Tcp:")]
        if len(lines) < 2:
            return None
        header, values = lines[0].split(), lines[1].split()
        try:
            return int(values[header.index("RetransSegs")])
        except (ValueError, IndexError):
            return None

    def _established(self) -> int | None:
        total, readable = 0, False
        for proto in ("tcp", "tcp6"):
            text = self.view.proc_text(f"net/{proto}", limit=16 * 1024 * 1024)
            if text is None:
                continue
            readable = True
            total += sum(1 for line in text.splitlines()[1:] if len(line.split()) > 3 and line.split()[3] == "01")
        return total if readable else None

    def _tls_listeners(self) -> list[tuple[str, int]]:
        excluded = {int(p) for p in (self.config.get("probe_exclude_ports") or []) if str(p).isdigit()}
        found: dict[int, str] = {}
        for proto in ("tcp", "tcp6"):
            for line in (self.view.proc_text(f"net/{proto}", limit=16 * 1024 * 1024) or "").splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4 or parts[3] != "0A":
                    continue
                try:
                    host_hex, port_hex = parts[1].split(":")
                    port = int(port_hex, 16)
                except ValueError:
                    continue
                if port in excluded or port in found:
                    continue
                if len(host_hex) == 8:
                    raw = bytes.fromhex(host_hex)[::-1]
                    address = socket.inet_ntoa(raw)
                    found[port] = "127.0.0.1" if address == "0.0.0.0" else address
                else:
                    found[port] = "::1" if set(host_hex) == {"0"} else "127.0.0.1"
        return sorted(((addr, port) for port, addr in found.items()), key=lambda item: item[1])

    # -- the sample ----------------------------------------------------------- #
    def sample(self) -> dict[str, Any]:
        if self.previous is None:
            self.previous = self._read()
            self.sleep(1.0)
        current = self._read()
        previous, self.previous = self.previous, current
        elapsed = max(current["t"] - previous["t"], 1e-6)
        observed_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        metrics: list[dict[str, Any]] = []
        base = {"scope": self.scope}

        def emit(name: str, value: float | None, reason: str = "", **labels: Any) -> None:
            entry: dict[str, Any] = {"name": name, "labels": {**base, **{k: str(v) for k, v in labels.items()}}}
            if value is None:
                entry.update(quality="missing", reason=reason or "not readable on this host")
            else:
                entry["value"] = round(float(value), 3)
            metrics.append(entry)

        procs, pprocs = current["procs"], previous["procs"]
        ncpu = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else (os.cpu_count() or 1)

        # CPU and memory
        if self.scope == "host":
            if "cpu" in current and "cpu" in previous:
                total = current["cpu"][0] - previous["cpu"][0]
                idle = current["cpu"][1] - previous["cpu"][1]
                emit("cpu.utilization_pct", (total - idle) / total * 100 if total > 0 else 0.0,
                     basis="/proc/stat")
            else:
                emit("cpu.utilization_pct", None, "/proc/stat is not readable")
            mem = current["mem"]
            if mem.get("MemTotal") and "MemAvailable" in mem:
                emit("ram.utilization_pct", (1 - mem["MemAvailable"] / mem["MemTotal"]) * 100,
                     basis="/proc/meminfo")
            else:
                emit("ram.utilization_pct", None, "/proc/meminfo is not readable")
            if "load1" in current:
                emit("system.load", current["load1"], basis="/proc/loadavg 1-minute")
        else:
            if procs["count"]:
                busy = max(procs["ticks"] - pprocs["ticks"], 0) / _CLK_TCK
                emit("cpu.utilization_pct", min(busy / (elapsed * ncpu) * 100, 100.0),
                     basis=f"server processes / {ncpu} CPUs")
                total_mem = current["mem"].get("MemTotal")
                if total_mem:
                    emit("ram.utilization_pct", procs["rss"] / total_mem * 100,
                         basis="server resident memory / MemTotal")
                emit("container.memory_bytes", procs["rss"], basis="server resident memory")
            else:
                emit("cpu.utilization_pct", None, "no server process is visible to the agent")
                emit("ram.utilization_pct", None, "no server process is visible to the agent")
        zombies = procs["states"].get("Z", 0)
        if procs["count"]:
            emit("process.health", 0 if zombies else 1, processes=procs["count"], zombies=zombies)
        else:
            emit("process.health", None, "no process is visible to the agent")

        # storage — the filesystem the server writes to
        try:
            fs = os.statvfs(self.view.host_path("/"))
            capacity = fs.f_blocks * fs.f_frsize
            available = fs.f_bavail * fs.f_frsize
            used = (fs.f_blocks - fs.f_bfree) * fs.f_frsize
            emit("storage.capacity_bytes", capacity, mount="/")
            emit("storage.used_bytes", used, mount="/")
            emit("storage.available_bytes", available, mount="/")
            emit("storage.utilization_pct", used / (used + available) * 100 if used + available else 0.0, mount="/")
        except OSError as exc:
            emit("storage.utilization_pct", None, f"statvfs failed: {exc.strerror or exc}", mount="/")

        # disk I/O
        if self.scope == "host" and "disk" in current and "disk" in previous:
            ios = current["disk"][0] - previous["disk"][0]
            sectors = current["disk"][1] - previous["disk"][1]
            busy = current["disk"][2] - previous["disk"][2]
            emit("disk.iops", max(ios, 0) / elapsed, basis="/proc/diskstats")
            emit("disk.throughput_mbps", max(sectors, 0) * 512 / elapsed / 1_000_000, basis="/proc/diskstats")
            if ios > 0:
                emit("disk.latency_ms", busy / ios, basis="/proc/diskstats average per I/O")
        elif self.scope == "workload":
            if procs["io_bytes"] is not None and pprocs["io_bytes"] is not None:
                delta = max(procs["io_bytes"] - pprocs["io_bytes"], 0)
                emit("disk.throughput_mbps", delta / elapsed / 1_000_000, basis="server processes /proc/<pid>/io")
            else:
                emit("disk.throughput_mbps", None, "/proc/<pid>/io of the server is not readable")

        # network — the server's own interfaces (shared network namespace)
        if "net" in current and "net" in previous:
            rx_tx = sum(v[0] for v in current["net"].values()) - sum(v[0] for v in previous["net"].values())
            errs = sum(v[1] for v in current["net"].values()) - sum(v[1] for v in previous["net"].values())
            emit("network.throughput_mbps", max(rx_tx, 0) * 8 / elapsed / 1_000_000,
                 interfaces=",".join(sorted(current["net"]))[:120])
            emit("network.interface_errors", max(errs, 0))
            speeds = []
            for name in current["net"]:
                speed = _ints(self.view.sys_text(f"class/net/{name}/speed"))
                if speed and speed[0] > 0:
                    speeds.append(speed[0])
            if speeds:
                emit("network.bandwidth_mbps", sum(speeds), basis="link speed (capacity, not traffic)")
        else:
            emit("network.throughput_mbps", None, "/proc/net/dev is not readable")
        if current["established"] is not None:
            emit("network.connections", current["established"], state="established")
        if current["retrans"] is not None and previous["retrans"] is not None:
            emit("network.tcp_retransmissions", max(current["retrans"] - previous["retrans"], 0))

        # cryptographic performance — the server's own TLS listeners, timed
        self._tls(emit)
        probe = str(self.config.get("hsm_probe") or "").strip()
        if probe:
            host, _, port = probe.rpartition(":")
            try:
                ms = self.hsm_probe(host or "127.0.0.1", int(port), float(self.config.get("probe_timeout") or 2.5))
            except ValueError:
                ms = None
            emit("crypto.hsm_operation_latency_ms", ms, f"no response from the HSM at {probe}",
                 operation="tls-connect+first-response", port=port)

        return {"schema": SCHEMA, "observed_at": observed_at, "interval_seconds": int(
            self.config.get("performance_interval") or 60), "scope": self.scope, "metrics": metrics}

    def _tls(self, emit: Callable[..., None]) -> None:
        timeout = float(self.config.get("probe_timeout") or 2.5)
        failures = 0
        measured = 0
        for address, port in self._tls_listeners():
            if measured >= MAX_TLS_PORTS:
                break
            if port in self.non_tls:
                self.non_tls[port] -= 1
                if self.non_tls[port] > 0:
                    continue
                del self.non_tls[port]
            result = self.tls_probe(address, port, timeout)
            if result is None:
                if port in self.tls_ok:
                    failures += 1          # it spoke TLS before: this is a negotiation failure
                else:
                    self.non_tls[port] = NON_TLS_RETRY_SAMPLES
                continue
            self.tls_ok.add(port)
            measured += 1
            labels = {"port": port}
            if result.get("version"):
                labels["tls_version"] = result["version"]
            if result.get("cipher"):
                labels["algorithm"] = result["cipher"]
            emit("crypto.tls_handshake_ms", result["ms"], **labels)
        if self.tls_ok:
            emit("crypto.tls_negotiation_failures", failures)


# --------------------------------------------------------------------------- #
# probes — this host only
# --------------------------------------------------------------------------- #

def _client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE     # timing the handshake, not judging the certificate
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
        context.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, ssl.SSLError):
        pass
    return context


def timed_tls_handshake(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """Milliseconds for TCP connect + full TLS handshake; None when the port is not TLS."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    started = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect((host, port))
            with _client_context().wrap_socket(raw) as tls:
                ms = (time.perf_counter() - started) * 1000
                cipher = tls.cipher() or (None, None, None)
                return {"ms": ms, "version": tls.version(), "cipher": cipher[0]}
    except (OSError, ssl.SSLError, ValueError):
        return None


def timed_hsm_response(host: str, port: int, timeout: float) -> float | None:
    """Milliseconds from connect to the HSM's first response line over TLS."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    started = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect((host, port))
            with _client_context().wrap_socket(raw) as tls:
                if not tls.recv(1):
                    return None
                return (time.perf_counter() - started) * 1000
    except (OSError, ssl.SSLError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# send
# --------------------------------------------------------------------------- #

def signed_sample(sample: dict[str, Any], identity: dict[str, Any], config: dict[str, Any], key: Any) -> dict[str, Any]:
    """The document the API verifies: the sample plus who and where, signed."""
    system = config.get("system") or {}
    document = {
        **sample,
        "agent_id": identity.get("agent_id"),
        "contributor": identity.get("contributor") or identity.get("name"),
        "host": config.get("fqdn") or socket.getfqdn(),
        "primary_ip": config.get("primary_ip"),
        "system": system.get("name") if isinstance(system, dict) else None,
    }
    if key is not None:
        document["signature"] = key.document_signature(document)
    return document


def send(client: Any, identity: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    return client.post(identity.get("performance_path") or DEFAULT_PATH, document)
