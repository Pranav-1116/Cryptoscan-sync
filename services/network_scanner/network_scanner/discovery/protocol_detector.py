"""Protocol detection from the actual response (spec 67 §5, §2).

A port number is a guess; a response is a fact. This module asks the endpoint
what it speaks, in a fixed order, and records what it tried:

    1. TLS ClientHello  — a completed handshake proves TLS whatever the port is
    2. STARTTLS / plaintext banner — SSH, SMTP, IMAP, POP3, FTP, MySQL
    3. PostgreSQL SSLRequest — ``S``/``N`` is the server's own answer

Every result keeps ``service_guess`` (from the port registry) *next to*
``detected`` so a mismatch — TLS on 8443 is normal, TLS on 5432 is not — is
visible instead of being flattened into one assumption. Nothing is inferred from
the port alone: if no response identifies the service, the answer is
``UNKNOWN`` with the attempts that were made.

The detector never sends credentials, never authenticates and never reads
application data. Banners are truncated and treated as identification strings,
not as content.
"""

from __future__ import annotations

import socket
import ssl
import struct
from typing import Any

DETECTOR_VERSION = "network-protocol-detector-v1.0"

PROTOCOLS = (
    "TLS",
    "SSH",
    "HTTP",
    "SMTP",
    "IMAP",
    "POP3",
    "FTP",
    "POSTGRESQL",
    "MYSQL",
    "UNKNOWN",
)

#: protocol families that can carry a TLS session (directly or via STARTTLS)
TLS_CAPABLE = frozenset({"TLS", "SMTP", "IMAP", "POP3", "FTP", "POSTGRESQL", "MYSQL"})

#: longest banner prefix kept — identification only, never application content
BANNER_LIMIT = 120

_STARTERS = (
    (b"SSH-", "SSH"),
    (b"HTTP/", "HTTP"),
    (b"220", "SMTP"),  # SMTP and FTP share the greeting; disambiguated below
    (b"* OK", "IMAP"),
    (b"+OK", "POP3"),
)

_FTP_MARKERS = ("ftp", "vsftpd", "proftpd", "filezilla", "pure-ftpd")
_SMTP_MARKERS = ("smtp", "postfix", "exim", "sendmail", "esmtp")


def _guess(port: int) -> dict[str, Any]:
    """Port-based guess — always labelled as a guess."""
    try:
        from shared_models.network_registry import classify_port

        info = classify_port(port)
        name = (
            getattr(info, "canonical", None)
            or getattr(info, "name", None)
            or getattr(info, "service", None)
            or "UNKNOWN"
        )
        return {"name": str(name).upper(), "source": "PORT_REGISTRY"}
    except Exception:  # the registry is optional; a guess must never break a probe
        return {"name": "UNKNOWN", "source": "PORT_REGISTRY_UNAVAILABLE"}


def _tls_probe(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """Return handshake facts when the endpoint completes a TLS handshake."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        tls = context.wrap_socket(sock, server_hostname=host if not _is_ip(host) else None)
        certificate = tls.getpeercert()
        return {
            "tls_version": tls.version(),
            "cipher_suite": (tls.cipher() or (None,))[0],
            "alpn": tls.selected_alpn_protocol(),
            "sni_sent": not _is_ip(host),
            "has_certificate": bool(certificate) or bool(tls.getpeercert(binary_form=True)),
        }
    except (ssl.SSLError, ssl.CertificateError, OSError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _is_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)


def _read(sock: socket.socket, limit: int = 512) -> bytes:
    try:
        return sock.recv(limit)
    except (socket.timeout, OSError):
        return b""


def _banner_probe(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """Read the greeting; ask HTTP explicitly because servers wait for a request."""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = _read(sock)
        if not banner:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n")
                banner = _read(sock)
            except OSError:
                return None
        if not banner:
            return None
        return {"banner": banner[:BANNER_LIMIT]}
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _classify_banner(banner: bytes) -> tuple[str, str]:
    text = banner.decode("latin-1", errors="replace")
    lowered = text.lower()
    for prefix, protocol in _STARTERS:
        if banner.startswith(prefix):
            if protocol == "SMTP":
                if any(marker in lowered for marker in _FTP_MARKERS):
                    return "FTP", "BANNER"
                if any(marker in lowered for marker in _SMTP_MARKERS) or "smtp" in lowered:
                    return "SMTP", "BANNER"
                return "SMTP", "BANNER_PREFIX"
            return protocol, "BANNER"
    # MySQL: 3-byte length, sequence id, then protocol version 10
    if len(banner) >= 5 and banner[4] == 10:
        return "MYSQL", "HANDSHAKE_PACKET"
    return "UNKNOWN", "BANNER_UNRECOGNISED"


def _postgres_probe(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """PostgreSQL SSLRequest: the server answers S (TLS) or N (plaintext)."""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(struct.pack("!II", 8, 80877103))  # length + SSLRequest code
        answer = _read(sock, 1)
        if answer in (b"S", b"N"):
            return {"ssl_supported": answer == b"S", "answer": answer.decode()}
        return None
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _mysql_probe(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """MySQL initial handshake: capability flag CLIENT_SSL (0x0800)."""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        packet = _read(sock, 512)
        if len(packet) < 5 or packet[4] != 10:
            return None
        # server version (null terminated) then connection id, then capability bits
        offset = 5
        end = packet.find(b"\x00", offset)
        if end < 0:
            return None
        version = packet[offset:end].decode("latin-1", errors="replace")[:40]
        capabilities = struct.unpack("<H", packet[end + 1 + 4 : end + 1 + 6])[0] if len(packet) >= end + 7 else 0
        return {"server_version": version, "ssl_capable": bool(capabilities & 0x0800)}
    except (OSError, struct.error):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def postgres_tls_handshake(host: str, port: int, *, timeout: float = 3.0) -> dict[str, Any] | None:
    """Negotiate TLS on a PostgreSQL connection: SSLRequest, then a real handshake.

    PostgreSQL does not accept a TLS ClientHello directly — the client asks with
    an SSLRequest and only then starts TLS. That is why a generic TLS probe
    reports "no TLS" for a database that is in fact TLS-only on that port.
    """
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(struct.pack("!II", 8, 80877103))
        answer = sock.recv(1)
        if answer != b"S":
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls = context.wrap_socket(sock)
        htype = _split_subject(tls.getpeercert())
        return {
            "tls_version": tls.version(),
            "cipher_suite": (tls.cipher() or (None,))[0],
            "has_certificate": bool(tls.getpeercert(binary_form=True)),
            "certificate_subject": htype,
            "protocol": "POSTGRESQL",
        }
    except (ssl.SSLError, OSError, ValueError, struct.error):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _split_subject(certificate: dict[str, Any] | None) -> str | None:
    """Return only the CN of a peer certificate — never the whole subject."""
    for rdn in (certificate or {}).get("subject", ()) or ():
        for key, value in rdn:
            if key == "commonName":
                return str(value)[:120]
    return None


def detect_protocol(
    host: str,
    port: int,
    *,
    timeout: float = 2.0,
    tls_probe: Any = None,
    banner_probe: Any = None,
    postgres_probe: Any = None,
    mysql_probe: Any = None,
) -> dict[str, Any]:
    """Identify what an endpoint speaks, from its response.

    ``*_probe`` parameters exist so tests can drive the decision table without
    sockets; production always uses the module functions.
    """
    attempts: list[dict[str, Any]] = []
    tls_facts = (tls_probe or _tls_probe)(host, port, timeout)
    if tls_facts:
        attempts.append({"probe": "TLS_CLIENT_HELLO", "result": "HANDSHAKE_COMPLETED"})
        guess = _guess(port)
        return {
            "schema": "cryptoscan.protocol-detection/1",
            "detector_version": DETECTOR_VERSION,
            "host": host,
            "port": port,
            "detected": "TLS",
            "detection_method": "TLS_HANDSHAKE",
            "confidence": "HIGH",
            "service_guess": guess,
            # the whole point of §5: a port is not a protocol
            "port_matches_protocol": guess["name"] in {"HTTPS", "TLS", "SSL"},
            "tls": tls_facts,
            "tls_capable": True,
            "attempts": attempts,
            "limitations": [],
        }

    attempts.append({"probe": "TLS_CLIENT_HELLO", "result": "NO_TLS_HANDSHAKE"})

    banner = (banner_probe or _banner_probe)(host, port, timeout)
    detected, method = ("UNKNOWN", "NO_RESPONSE")
    extra: dict[str, Any] = {}
    if banner:
        detected, method = _classify_banner(banner["banner"])
        extra["banner"] = banner["banner"].decode("latin-1", errors="replace")[:BANNER_LIMIT]
        attempts.append({"probe": "BANNER", "result": detected})

    if detected in {"UNKNOWN", "MYSQL"}:
        pg = (postgres_probe or _postgres_probe)(host, port, timeout)
        if pg is not None:
            detected = "POSTGRESQL"
            method = "SSL_REQUEST"
            extra["postgres"] = pg
            attempts.append({"probe": "POSTGRES_SSL_REQUEST", "result": "SUPPORTED" if pg["ssl_supported"] else "REFUSED"})
            # The TLS handshake itself is a separate, separately-approved
            # operation (TLS_HANDSHAKE) — detection only asks the question.

    if detected == "MYSQL" and "server_version" not in extra:
        my = (mysql_probe or _mysql_probe)(host, port, timeout)
        if my:
            extra["mysql"] = my
            attempts.append({"probe": "MYSQL_HANDSHAKE", "result": "CLIENT_SSL" if my["ssl_capable"] else "NO_CLIENT_SSL"})

    guess = _guess(port)
    limitations: list[str] = []
    if detected == "UNKNOWN":
        limitations.append(
            "no response identified the service — UNKNOWN is the result, not a clean port"
        )
    return {
        "schema": "cryptoscan.protocol-detection/1",
        "detector_version": DETECTOR_VERSION,
        "host": host,
        "port": port,
        "detected": detected,
        "detection_method": method,
        "confidence": "HIGH" if method in {"TLS_HANDSHAKE", "BANNER", "SSL_REQUEST", "HANDSHAKE_PACKET"} else "LOW",
        "service_guess": guess,
        "port_matches_protocol": None if detected == "UNKNOWN" else _matches(guess["name"], detected),
        "tls": tls_facts,
        "tls_capable": detected in TLS_CAPABLE,
        "attempts": attempts,
        "details": extra,
        "limitations": limitations,
        "boundary": "detection only — no authentication, no application data, no credentials sent",
    }


def _matches(guess: str, detected: str) -> bool:
    normalised = {"POSTGRESQL": {"POSTGRES", "POSTGRESQL", "PGSQL"}, "MYSQL": {"MYSQL", "MARIADB"}}
    return guess in normalised.get(detected, {detected})


def detection_summary(detections: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts for the dashboard; mismatches stay visible."""
    by_protocol: dict[str, int] = {}
    mismatches: list[dict[str, Any]] = []
    unknown = 0
    for item in detections:
        protocol = item.get("detected") or "UNKNOWN"
        by_protocol[protocol] = by_protocol.get(protocol, 0) + 1
        if protocol == "UNKNOWN":
            unknown += 1
        if item.get("port_matches_protocol") is False:
            mismatches.append(
                {
                    "endpoint": f"{item.get('host')}:{item.get('port')}",
                    "detected": protocol,
                    "port_guess": (item.get("service_guess") or {}).get("name"),
                }
            )
    return {
        "schema": "cryptoscan.protocol-detection-summary/1",
        "endpoints": len(detections),
        "by_protocol": by_protocol,
        "unknown": unknown,
        "port_protocol_mismatches": mismatches,
        "note": "a port mismatch is a normal finding (TLS on 8443, SSH on 2222), not an error",
    }
