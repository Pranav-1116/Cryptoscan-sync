"""NBOM: what this host exposes and talks to, and how each listener protects it.

* listening TCP/UDP sockets from ``/proc/net/{tcp,tcp6,udp,udp6}``, joined to the
  owning process through ``/proc/<pid>/fd`` (needs root or CAP_SYS_PTRACE for other
  users' processes — without it the socket is still reported, with an unknown owner);
* a **protocol probe of every local TCP listener**: SSH banner, PostgreSQL SSLRequest,
  then a TLS handshake (negotiated version, cipher, key size, served certificate, which
  legacy versions are still accepted), then a plaintext HTTP / Redis check. Probes
  connect to this host only;
* established **outbound** connections (remote service endpoints this host depends on).

Process command lines are never read: they can carry passwords.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import struct
from typing import Any

from cryptava.collectors import Context, certs
from cryptava.observation import source
from cryptava.util import slug

TCP_STATES = {"0A": "LISTEN", "01": "ESTABLISHED"}
UDP_LISTEN = "07"

DATABASE_PROCESSES = {
    "postgres": "postgresql", "postmaster": "postgresql", "mysqld": "mysql", "mariadbd": "mariadb",
    "mongod": "mongodb", "redis-server": "redis", "sqlservr": "mssql", "tnslsnr": "oracle",
    "db2sysc": "db2", "cassandra": "cassandra",
}
BROKER_PROCESSES = {"beam.smp": "rabbitmq", "kafka": "kafka", "artemis": "activemq-artemis", "nats-server": "nats"}


# --------------------------------------------------------------------------- #
# /proc readers
# --------------------------------------------------------------------------- #

def _addr(hex_addr: str) -> tuple[str, int]:
    host_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)
    raw = bytes.fromhex(host_hex)
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw[::-1]), port
    words = struct.unpack("<4I", raw)
    packed = struct.pack(">4I", *words)
    address = socket.inet_ntop(socket.AF_INET6, packed)
    if address.startswith("::ffff:") and "." in address:
        address = address[7:]
    return address, port


def read_sockets(ctx: Context) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        text = ctx.view.proc_text(f"net/{proto}", limit=16 * 1024 * 1024)
        if not text:
            continue
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            state = parts[3]
            is_udp = proto.startswith("udp")
            if is_udp and state != UDP_LISTEN:
                continue
            if not is_udp and state not in TCP_STATES:
                continue
            try:
                local, lport = _addr(parts[1])
                remote, rport = _addr(parts[2])
            except (ValueError, OSError):
                continue
            out.append({"proto": "udp" if is_udp else "tcp", "state": "LISTEN" if is_udp else TCP_STATES[state],
                        "local": local, "lport": lport, "remote": remote, "rport": rport,
                        "inode": parts[9], "uid": parts[7]})
    return out


def read_processes(ctx: Context) -> tuple[dict[int, dict[str, Any]], dict[str, int], int]:
    processes: dict[int, dict[str, Any]] = {}
    inode_owner: dict[str, int] = {}
    denied = 0
    own = os.getpid()
    try:
        entries = [e for e in os.listdir(ctx.view.proc) if e.isdigit()]
    except OSError:
        return processes, inode_owner, 0
    for entry in entries:
        pid = int(entry)
        if pid == own:
            continue
        comm = (ctx.view.proc_text(f"{pid}/comm", limit=256) or "").strip()
        if not comm:
            continue
        exe = None
        try:
            exe = os.readlink(ctx.view.proc / entry / "exe")
        except OSError:
            pass
        status = ctx.view.proc_text(f"{pid}/status", limit=4096) or ""
        uid = None
        for line in status.splitlines():
            if line.startswith("Uid:"):
                uid = line.split()[1]
                break
        if exe is None and not status:
            continue
        processes[pid] = {"pid": pid, "comm": comm, "exe": exe, "uid": uid}
        try:
            fds = os.listdir(ctx.view.proc / entry / "fd")
        except OSError:
            denied += 1
            continue
        for fd in fds:
            try:
                target = os.readlink(ctx.view.proc / entry / "fd" / fd)
            except OSError:
                continue
            if target.startswith("socket:["):
                inode_owner.setdefault(target[8:-1], pid)
    return processes, inode_owner, denied


def _user(ctx: Context, uid: str | None) -> str | None:
    if uid is None:
        return None
    text = ctx.view.read_text("/etc/passwd", limit=1024 * 1024) or ""
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) > 2 and parts[2] == uid:
            return parts[0]
    return f"uid {uid}"


# --------------------------------------------------------------------------- #
# probes (this host only)
# --------------------------------------------------------------------------- #

def _connect(host: str, port: int, timeout: float) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def _banner(host: str, port: int, timeout: float) -> bytes:
    try:
        with _connect(host, port, timeout) as sock:
            sock.settimeout(0.6)
            try:
                return sock.recv(256)
            except (socket.timeout, OSError):
                return b""
    except OSError:
        return b""


def _tls_context(minimum: ssl.TLSVersion | None = None, maximum: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        context.minimum_version = minimum or ssl.TLSVersion.TLSv1
        if maximum:
            context.maximum_version = maximum
    except (ValueError, ssl.SSLError):
        pass
    return context


def _handshake(host: str, port: int, timeout: float, context: ssl.SSLContext,
               preamble: bytes | None = None, server_name: str | None = None) -> dict[str, Any] | None:
    try:
        raw = _connect(host, port, timeout)
    except OSError:
        return None
    try:
        if preamble is not None:
            raw.sendall(preamble)
            if raw.recv(1) != b"S":
                raw.close()
                return None
        with context.wrap_socket(raw, server_hostname=server_name) as tls:
            cipher = tls.cipher() or (None, None, None)
            return {"version": tls.version(), "cipher": cipher[0], "bits": cipher[2],
                    "der": tls.getpeercert(binary_form=True)}
    except (ssl.SSLError, OSError, ValueError):
        try:
            raw.close()
        except OSError:
            pass
        return None


POSTGRES_SSLREQUEST = struct.pack(">II", 8, 80877103)


def _host_slug(host: str) -> str:
    """Ref-safe host. IPv6 uses the exploded form: ``1::2:3`` and ``1:2::3`` are
    different hosts that a plain slug would both turn into ``1-2-3``."""
    try:
        addr = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return slug(host, limit=80)
    if addr.version == 6:
        return "v6-" + addr.exploded.replace(":", "-")
    return slug(host, limit=80)


def probe(host: str, port: int, *, process: str | None, timeout: float, server_name: str | None) -> dict[str, Any]:
    """What protocol a local listener speaks, and how it protects it."""
    result: dict[str, Any] = {"port": port, "app_protocol": None, "tls": None}
    banner = _banner(host, port, timeout)
    if banner.startswith(b"SSH-"):
        result["app_protocol"] = "ssh"
        result["banner"] = banner.split(b"\r\n")[0].decode("ascii", "replace")[:120]
        return result
    if banner[:4] in (b"220 ", b"220-"):
        result["app_protocol"] = "smtp/ftp"
        result["banner"] = banner.split(b"\r\n")[0].decode("ascii", "replace")[:120]
        return result
    if len(banner) > 5 and banner[4:5] == b"\x0a":
        result["app_protocol"] = "mysql"
        return result
    preamble = POSTGRES_SSLREQUEST if (process in {"postgres", "postmaster"} or port == 5432) else None
    if preamble is not None:
        result["app_protocol"] = "postgresql"
    main = _handshake(host, port, timeout, _tls_context(), preamble, server_name)
    if main:
        accepted = {main["version"]}
        for label, version in (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            if label in accepted:
                continue
            legacy = _handshake(host, port, timeout, _tls_context(version, version), preamble, server_name)
            if legacy:
                accepted.add(legacy["version"])
        for label, version in (("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)):
            if label in accepted:
                continue
            other = _handshake(host, port, timeout, _tls_context(version, version), preamble, server_name)
            if other:
                accepted.add(other["version"])
        result["tls"] = {**main, "accepted_versions": sorted(accepted)}
        result["app_protocol"] = result["app_protocol"] or "tls"
        return result
    if preamble is not None:
        result["plaintext"] = True
        return result
    try:
        with _connect(host, port, timeout) as sock:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            sock.settimeout(1.0)
            reply = sock.recv(64)
        if reply.startswith(b"HTTP/"):
            result["app_protocol"] = "http"
            result["plaintext"] = True
            return result
    except OSError:
        pass
    try:
        with _connect(host, port, timeout) as sock:
            sock.sendall(b"PING\r\n")
            sock.settimeout(1.0)
            reply = sock.recv(32)
        if reply.startswith((b"+PONG", b"-NOAUTH", b"-ERR")):
            result["app_protocol"] = "redis"
            result["plaintext"] = True
    except OSError:
        pass
    return result


# --------------------------------------------------------------------------- #
# the plane
# --------------------------------------------------------------------------- #

def _service(ctx: Context, proc: dict[str, Any], ports: list[str]) -> str:
    comm = proc["comm"]
    ref = ctx.services.get(comm)
    if ref is None:
        ref = ctx.obs.asset(f"svc:{slug(comm)}", "SERVICE", comm, identity={"name": comm, "host": ctx.fqdn},
                            attributes={"executable": proc.get("exe"), "user": _user(ctx, proc.get("uid"))},
                            source="cryptava-proc", environment=ctx.environment)
        ctx.services[comm] = ref
    return ref


def collect(ctx: Context) -> None:
    obs = ctx.obs
    sockets = read_sockets(ctx)
    processes, inode_owner, denied = read_processes(ctx)
    ctx.processes = processes
    probe_enabled = bool(ctx.config.get("probe_listeners", True))
    exclude = {int(p) for p in ctx.config.get("probe_exclude_ports") or []}
    timeout = float(ctx.config.get("probe_timeout", 2.5))
    server_name = ctx.fqdn if "." in ctx.fqdn else None

    listeners: dict[tuple[str, int, str], dict[str, Any]] = {}
    outbound: dict[tuple[str, int], dict[str, Any]] = {}
    listening_ports = {s["lport"] for s in sockets if s["state"] == "LISTEN"}
    for sock in sockets:
        owner = processes.get(inode_owner.get(sock["inode"], -1))
        if sock["state"] == "LISTEN":
            key = (sock["local"], sock["lport"], sock["proto"])
            entry = listeners.setdefault(key, {**sock, "process": owner})
            if owner and not entry.get("process"):
                entry["process"] = owner
        elif sock["state"] == "ESTABLISHED":
            remote = sock["remote"]
            if remote.startswith("127.") or remote == "::1" or sock["lport"] in listening_ports:
                continue
            if sock["rport"] >= 32768:
                continue
            entry = outbound.setdefault((remote, sock["rport"]), {"remote": remote, "port": sock["rport"],
                                                                   "processes": set()})
            if owner:
                entry["processes"].add(owner["comm"])

    # collapse dual-stack wildcard listeners (0.0.0.0:443 + [::]:443) into one endpoint
    endpoints: dict[tuple[str, int, str], dict[str, Any]] = {}
    for (local, port, proto), entry in sorted(listeners.items(), key=lambda kv: (kv[0][1], kv[0][2], kv[0][0])):
        loopback = local.startswith("127.") or local == "::1"
        wildcard = local in ("0.0.0.0", "::")
        host = (ctx.primary_ip or ctx.fqdn) if wildcard else (f"loopback@{ctx.fqdn}" if loopback else local)
        key = (host, port, proto)
        if key in endpoints:
            if entry.get("process") and not endpoints[key].get("process"):
                endpoints[key]["process"] = entry["process"]
            endpoints[key]["bind"].append(local)
            continue
        endpoints[key] = {**entry, "host": host, "bind": [local], "loopback": loopback,
                          "probe_host": "127.0.0.1" if local == "0.0.0.0" else ("::1" if local == "::" else local)}

    probed = tls_found = plaintext = 0
    for (host, port, proto), entry in endpoints.items():
        proc = entry.get("process")
        result: dict[str, Any] = {}
        if proto == "tcp" and probe_enabled and port not in exclude and probed < int(ctx.config.get("max_probes", 64)):
            result = probe(entry["probe_host"], port, process=proc["comm"] if proc else None,
                           timeout=timeout, server_name=server_name)
            probed += 1
        tls = result.get("tls")
        identity_protocol = "tls" if tls else proto
        ref = obs.asset(f"ep:{_host_slug(host)}:{port}:{identity_protocol}", "NETWORK_ENDPOINT",
                        f"{ctx.hostname}:{port}/{result.get('app_protocol') or proto}",
                        identity={"host": host, "port": str(port), "protocol": identity_protocol},
                        attributes={"transport": proto, "bind_addresses": entry["bind"],
                                    "loopback_only": entry["loopback"],
                                    "app_protocol": result.get("app_protocol"),
                                    "process": proc["comm"] if proc else None,
                                    "plaintext": result.get("plaintext"),
                                    "banner": result.get("banner")},
                        source="cryptava-netstat", environment=ctx.environment)
        ctx.endpoints[(port, identity_protocol)] = ref
        ev = obs.observe(ref, "RUNTIME_OBSERVED", {
            "listening": True, "transport": proto, "bind_addresses": entry["bind"], "port": port,
            "process": proc["comm"] if proc else None, "executable": proc.get("exe") if proc else None,
            "host": ctx.fqdn, "source": f"/proc/net/{proto}",
        }, layer="NETWORK_TRANSPORT", source="cryptava-netstat")
        if proc:
            svc = _service(ctx, proc, [])
            svc_ev = obs.observe(svc, "RUNTIME_OBSERVED", {
                "pid_owner_of_socket": True, "executable": proc.get("exe"), "user": _user(ctx, proc.get("uid")),
                "listens_on": f"{proto}/{port}", "host": ctx.fqdn, "source": "/proc/<pid>/fd",
            }, layer="PLATFORM", source="cryptava-proc")
            obs.relate(svc, "runs_on", ctx.host_ref, basis="RUNTIME_OBSERVATION", evidence=[svc_ev])
            obs.relate(svc, "exposes", ref, basis="RUNTIME_OBSERVATION", evidence=[ev, svc_ev])
            engine = DATABASE_PROCESSES.get(proc["comm"])
            if engine and not entry["loopback"]:
                db_ref = obs.asset(f"db:{engine}:{port}", "DATABASE", f"{engine} on {ctx.hostname}:{port}",
                                   identity={"host": ctx.primary_ip or ctx.fqdn, "port": str(port), "engine": engine},
                                   attributes={"engine": engine, "process": proc["comm"]},
                                   source="cryptava-proc", environment=ctx.environment)
                db_ev = obs.observe(db_ref, "RUNTIME_OBSERVED", {"engine": engine, "process": proc["comm"],
                                                                 "port": port, "host": ctx.fqdn},
                                    layer="PLATFORM", source="cryptava-proc")
                obs.relate(db_ref, "hosted_on", ctx.host_ref, basis="RUNTIME_OBSERVATION", evidence=[db_ev])
                obs.relate(db_ref, "exposes", ref, basis="RUNTIME_OBSERVATION", evidence=[db_ev, ev])
                obs.relate(svc, "deployed_as", db_ref, basis="RUNTIME_OBSERVATION", evidence=[db_ev, svc_ev])
            broker = BROKER_PROCESSES.get(proc["comm"])
            if broker and not entry["loopback"]:
                mb = obs.asset(f"mb:{broker}:{port}", "MESSAGE_BROKER", f"{broker} on {ctx.hostname}:{port}",
                               identity={"host": ctx.primary_ip or ctx.fqdn, "port": str(port), "engine": broker},
                               source="cryptava-proc")
                mb_ev = obs.observe(mb, "RUNTIME_OBSERVED", {"engine": broker, "port": port, "host": ctx.fqdn},
                                    layer="PLATFORM", source="cryptava-proc")
                obs.relate(mb, "hosted_on", ctx.host_ref, basis="RUNTIME_OBSERVATION", evidence=[mb_ev])
        else:
            obs.relate(ref, "hosted_on", ctx.host_ref, basis="RUNTIME_OBSERVATION", evidence=[ev, ctx.host_evidence])

        if result.get("app_protocol") == "ssh" and result.get("banner"):
            obs.observe(ref, "NETWORK_ACTIVE_OBSERVED", {"protocol": "SSH", "banner": result["banner"],
                                                         "role": "ssh-banner", "host": ctx.fqdn},
                        layer="NETWORK_TRANSPORT", source="cryptava-probe")
        if result.get("plaintext"):
            plaintext += 1
            obs.observe(ref, "NETWORK_ACTIVE_OBSERVED", {
                "plaintext_listener": True, "app_protocol": result.get("app_protocol"),
                "host": ctx.fqdn, "note": "no TLS on this listener",
            }, layer="NETWORK_TRANSPORT", source="cryptava-probe")
        if tls:
            tls_found += 1
            hs = obs.observe(ref, "NETWORK_ACTIVE_OBSERVED", {
                "protocol": tls["version"], "algorithm": tls["cipher"], "key_size": tls["bits"],
                "role": "negotiated-cipher-suite", "accepted_versions": tls["accepted_versions"],
                "app_protocol": result.get("app_protocol"), "host": ctx.fqdn,
            }, layer="NETWORK_TRANSPORT", source="cryptava-handshake")
            for version in tls["accepted_versions"]:
                if version in ("TLSv1", "TLSv1.1", "SSLv3"):
                    obs.observe(ref, "NETWORK_ACTIVE_OBSERVED", {
                        "protocol": version, "role": "legacy-protocol-accepted", "host": ctx.fqdn,
                    }, layer="NETWORK_TRANSPORT", source="cryptava-handshake")
            if tls.get("der"):
                registered = certs.register(ctx, tls["der"], layer="NETWORK_TRANSPORT",
                                            source="cryptava-handshake", where=f"{host}:{port}")
                if registered:
                    cert_ref, cert_ev, cert = registered
                    obs.relate(ref, "uses_certificate", cert_ref, basis="NETWORK_OBSERVATION", evidence=[hs, cert_ev])
                    ctx.served_certificates.setdefault(cert["fingerprint_sha256"], []).append(ref)
                    if proc:
                        obs.relate(ctx.services[proc["comm"]], "terminates_tls_for", ref,
                                   basis="RUNTIME_OBSERVATION", evidence=[hs])

    # -- outbound dependencies ------------------------------------------------ #
    limit = int(ctx.config.get("max_outbound", 200))
    for (remote, port), entry in sorted(outbound.items())[:limit]:
        ref = obs.asset(f"remote:{slug(remote, limit=60)}:{port}", "NETWORK_ENDPOINT", f"{remote}:{port}",
                        identity={"host": remote, "port": str(port), "protocol": "tcp"},
                        attributes={"direction": "outbound-peer"}, source="cryptava-netstat")
        ev = obs.observe(ref, "RUNTIME_OBSERVED", {
            "established_from": ctx.fqdn, "processes": sorted(entry["processes"]) or None,
            "source": "/proc/net/tcp ESTABLISHED",
        }, layer="NETWORK_TRANSPORT", source="cryptava-netstat")
        for comm in sorted(entry["processes"]):
            proc = next((p for p in processes.values() if p["comm"] == comm), None)
            if proc is None:
                continue
            svc = _service(ctx, proc, [])
            svc_ev = obs.observe(svc, "RUNTIME_OBSERVED", {"executable": proc.get("exe"), "host": ctx.fqdn,
                                                           "connects_out": True, "source": "/proc/<pid>/fd"},
                                 layer="PLATFORM", source="cryptava-proc")
            obs.relate(svc, "runs_on", ctx.host_ref, basis="RUNTIME_OBSERVATION", evidence=[svc_ev])
            obs.relate(svc, "connects_to", ref, basis="RUNTIME_OBSERVATION", evidence=[ev])
        if not entry["processes"]:
            obs.relate(ctx.host_ref, "connects_to", ref, basis="NETWORK_OBSERVATION", evidence=[ev])

    tcp_listeners = sum(1 for key in endpoints if key[2] == "tcp")
    notes = []
    if denied:
        notes.append(f"{denied} processes not inspectable (run as root or with CAP_SYS_PTRACE to attribute their sockets)")
    if not probe_enabled:
        notes.append("listener probing disabled by config")
    status = "COMPLETE" if not denied else "PARTIAL"
    if not sockets:
        status = "PARTIAL"
        notes.append("no sockets visible in /proc/net (different network namespace?)")
    provenance = [
        source("/proc/net/{tcp,tcp6,udp,udp6}", "listening and established sockets",
               "READ" if sockets else "EMPTY", len(sockets)),
        source("/proc/<pid>/fd", "which process owns each socket (never the command line)",
               "DENIED" if denied and not processes else "READ", len(processes),
               f"{denied} processes not inspectable" if denied else None),
        source("local protocol probe", "SSH banner, PostgreSQL SSLRequest, TLS handshake (version, cipher, "
               "certificate, legacy versions accepted), plaintext HTTP / Redis",
               "DISABLED" if not probe_enabled else ("READ" if probed else "EMPTY"),
               probed if probe_enabled else None, "connects to this host only"),
        source("/proc/net/tcp ESTABLISHED", "outbound peers this host depends on",
               "READ" if outbound else "EMPTY", len(outbound)),
    ]
    obs.plane("NBOM · network", status,
              f"{len(endpoints)} listeners ({tls_found} TLS, {plaintext} plaintext), {len(outbound)} outbound peers"
              + (f"; {'; '.join(notes)}" if notes else ""), expected=1, collected=1, sources=provenance)
    obs.cover(f"{ctx.hostname} · TCP listeners probed", tcp_listeners, probed if probe_enabled else 0,
              None if probe_enabled else "probing disabled")
