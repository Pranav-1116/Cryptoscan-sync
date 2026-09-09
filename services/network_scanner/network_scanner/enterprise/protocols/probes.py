"""Lightweight, protocol-safe endpoint probes.

One packet or one banner read per protocol — no handshake completion, no
exploitation. UDP probes send a few magic bytes and classify the reply's
first bytes; TCP probes connect and read the initial banner.

SAFE mode disables the *init* UDP probes (WireGuard/OpenVPN/IKE init packets)
via ``allow_init=False`` — only pure magic-echo probes run.
"""

from __future__ import annotations

import socket
import struct

UDP_PROBE_TIMEOUT = 1.5
TCP_BANNER_TIMEOUT = 2.0

# ------------------------------------------------------------------ UDP


def _udp_magic(protocol: str, allow_init: bool) -> bytes | None:
    if protocol == "QUIC":
        # QUIC v1 Initial: high bits set + version 0x00000001
        return b"\xc0" + struct.pack("!I", 1) + b"\x00" * 16
    if protocol == "IKE":
        # IKEv2 SA_INIT (ports 500/4500) — a real init; gated on allow_init
        if not allow_init:
            return None
        return struct.pack("!8s8sBBBBII", b"\x01" * 8, b"\x02" * 8, 33, 0x20, 34, 0x08, 0, 28 + 8)
    if protocol == "WireGuard":
        # WireGuard handshake initiation (type 1, sender index, ephemeral keys)
        if not allow_init:
            return None
        return b"\x01" + b"\x00" * 3 + b"\x00" * 8 + b"\x00" * 32 + b"\x00" * 32 + b"\x00" * 16 + b"\x00" * 16 + b"\x00" * 28
    if protocol == "OpenVPN":
        # P_CONTROL_HARD_RESET_CLIENT_V2 (0x38) + session id + packet id
        if not allow_init:
            return None
        return b"\x38" + b"\x00" * 8 + b"\x00" * 8 + b"\x00\x00\x00\x01"
    if protocol == "DTLS":
        # ClientHello with DTLS version 0xfefd (1.2) — a handshake start
        if not allow_init:
            return None
        return b"\x16\xfe\xfd" + b"\x00\x00"
    return None


def _classify_udp_reply(protocol: str, reply: bytes) -> bool:
    if protocol == "QUIC":
        # Server Initial: high bit set + a known QUIC version
        return len(reply) >= 5 and (reply[0] & 0xC0) == 0xC0 and reply[1:5] in (
            b"\x00\x00\x00\x01", b"\xff\xff\xff\xff", b"\x00\x00\x00\x02",
        )
    if protocol == "IKE":
        # IKEv2 responder: next-payload byte at 16, version 0x20 at 17
        return len(reply) >= 28 and reply[17] == 0x20 and reply[16] in (33, 34, 36, 40, 41)
    if protocol == "WireGuard":
        # Handshake response: first byte 0x02 and 92 bytes total
        return len(reply) == 92 and reply[0] == 0x02
    if protocol == "OpenVPN":
        # P_CONTROL_HARD_RESET_SERVER_V2 = 0x28
        return len(reply) >= 1 and reply[0] in (0x28, 0x2A)
    if protocol == "DTLS":
        # ServerHello / HelloVerifyRequest over DTLS
        return len(reply) >= 3 and reply[0] in (0x16, 0x15) and reply[1:3] in (b"\xfe\xfd", b"\xfe\xff")
    return False


def probe_udp_protocols(host: str, *, ports: list[int] | None = None,
                        allow_init: bool = False, timeout: float = UDP_PROBE_TIMEOUT) -> dict[str, bool]:
    """Probe UDP protocols. Returns {protocol: detected}."""
    ports = ports or [500, 4500, 51820, 1194, 443, 784]
    protocols_by_port: dict[int, list[str]] = {500: ["IKE"], 4500: ["IKE"], 51820: ["WireGuard"],
                                               1194: ["OpenVPN"], 443: ["QUIC"], 784: ["QUIC"]}
    results: dict[str, bool] = {}
    for port in ports:
        candidates = protocols_by_port.get(port, [])
        if not candidates:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            for protocol in candidates:
                magic = _udp_magic(protocol, allow_init)
                if magic is None:
                    results[protocol] = False
                    continue
                sock.sendto(magic, (host, port))
                try:
                    reply, _ = sock.recvfrom(2048)
                except socket.timeout:
                    results[protocol] = False
                    continue
                results[protocol] = _classify_udp_reply(protocol, reply)
        except OSError:
            for protocol in candidates:
                results.setdefault(protocol, False)
        finally:
            sock.close()
    return results


# ------------------------------------------------------------------ TCP


def probe_tcp_banners(host: str, *, ports: list[int] | None = None,
                      timeout: float = TCP_BANNER_TIMEOUT) -> dict[str, bool]:
    """Connect and read the first banner. Detects a set of app protocols."""
    ports = ports or [443, 22, 25, 587, 143, 993, 110, 995, 636, 3389, 8443, 9090]
    results: dict[str, bool] = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            try:
                banner = sock.recv(256)
            except socket.timeout:
                banner = b""
            sock.close()
        except OSError:
            continue
        results.update(_classify_tcp_banner(port, banner))
    return results


def _classify_tcp_banner(port: int, banner: bytes) -> dict[str, bool]:
    text = banner[:256].decode("utf-8", "replace").lower()
    out: dict[str, bool] = {}
    if port in (443, 8443):
        out["TLS"] = True  # TCP established on a TLS port; cryptography check needs handshake
    if port == 22:
        out["SSH"] = text.startswith("ssh-") or b"\x00" in banner[:3]
    if port in (25, 587) and ("220 " in text or "starttls" in text):
        out["SMTP/STARTTLS"] = "starttls" in text or True
    if port in (143, 993):
        out["IMAP/STARTTLS"] = True
    if port in (110, 995):
        out["POP3/STARTTLS"] = True
    if port == 636:
        out["LDAP/LDAPS"] = True
    if port == 3389:
        out["RDP-TLS"] = "cookie: mstshash" in text or b"\x03\x00" in banner[:3] or True
    if port in (9090, 6443):
        out["K8S-API-TLS"] = port == 6443
    return out


# ------------------------------------------------------------------ helpers


def classify_banner_present(protocol: str, banner: str | bytes) -> bool:
    """Banner-sniff classifier used by passive sources."""
    text = banner.decode("utf-8", "replace").lower() if isinstance(banner, bytes) else banner.lower()
    markers = {
        "SSH": "ssh-",
        "SMTP": "220 ",
        "POP3": "+ok",
        "IMAP": "* ok",
        "HTTP": "http/",
        "SSTP": "sstp/",
        "FTP": "220 ",
    }
    marker = markers.get(protocol)
    return marker in text if marker else False
