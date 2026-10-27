"""Database transport-TLS probing (PostgreSQL, MySQL/MariaDB).

A database listening on 5432/3306 does not advertise TLS in a banner: you ask,
and the server answers. That answer is the whole point of this module:

    PostgreSQL  SSLRequest (8 bytes) -> 'S' (TLS available) / 'N' (not offered)
    MySQL       initial handshake capabilities -> CLIENT_SSL bit -> SSLRequest

When the answer is "yes", the TLS handshake is completed on the same socket so
the negotiated version, cipher suite and certificate are *observed* rather than
assumed. When the answer is "no", that refusal is recorded — it is not the same
thing as "the database has no encryption", because TDE, column encryption and
tablespace encryption are invisible from the network (§18).

Nothing here sends credentials, SQL, or application data: only the two
capability handshake messages the protocol defines.
"""

from __future__ import annotations

import socket
import struct
from typing import Any

from network_scanner.probing.tls_handshaker import handshake

#: PostgreSQL SSLRequest: length 8, code 80877103 (0x04D2162F)
PG_SSL_REQUEST = struct.pack("!II", 8, 80877103)

#: MySQL capability bit for TLS
MYSQL_CLIENT_SSL = 0x0800

DEFAULT_TIMEOUT = 5.0


def _base(host: str, port: int, engine: str) -> dict[str, Any]:
    return {
        "endpoint": f"{host}:{port}",
        "engine": engine,
        "status": "UNKNOWN",
        "tls_supported": None,
        "tls_version": None,
        "cipher_suite": None,
        "certificate": None,
        "detail": None,
        "server_note": None,
        "limitations": [
            "transport TLS says nothing about TDE, column encryption or tablespace encryption (§18)",
            "no credentials, SQL or application data are sent — only the protocol's capability exchange",
        ],
    }


def probe_postgres_tls(host: str, port: int = 5432, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Ask a PostgreSQL server whether it offers TLS, and observe it if so."""
    result = _base(host, port, "POSTGRESQL")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(PG_SSL_REQUEST)
            answer = sock.recv(1)
            if answer == b"S":
                result["tls_supported"] = True
                try:
                    hs = handshake(sock, host, timeout=timeout)
                except Exception as exc:  # noqa: BLE001 — a failed handshake is a result
                    result["status"] = "TLS_HANDSHAKE_FAILED"
                    result["detail"] = f"{type(exc).__name__}: {exc}"[:200]
                    return result
                result.update(
                    {
                        "status": "TLS_AVAILABLE",
                        "tls_version": hs.get("version"),
                        "cipher_suite": (hs.get("cipher") or (None,))[0],
                        "certificate": hs.get("certificate"),
                    }
                )
                return result
            if answer == b"N":
                result.update(
                    {
                        "status": "TLS_REFUSED",
                        "tls_supported": False,
                        "server_note": "server answered N to SSLRequest",
                    }
                )
                return result
            result["status"] = "UNEXPECTED_RESPONSE"
            result["detail"] = f"unexpected SSLRequest answer: {answer!r}"[:120]
            return result
    except (ConnectionRefusedError, socket.timeout, TimeoutError, OSError) as exc:
        result["status"] = "UNREACHABLE"
        result["detail"] = f"{type(exc).__name__}: {exc}"[:200]
        return result


def _read_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("connection closed mid-read")
        data += chunk
    return data


def parse_mysql_handshake(packet: bytes) -> dict[str, Any]:
    """Parse the MySQL/MariaDB initial handshake packet (protocol version 10)."""
    if len(packet) < 32:
        raise ValueError("handshake packet too short")
    position = 0
    protocol_version = packet[position]
    position += 1
    if protocol_version != 10:
        raise ValueError(f"unknown MySQL protocol version {protocol_version}")
    end = packet.find(b"\x00", position)
    if end < 0:
        raise ValueError("server version not terminated")
    server_version = packet[position:end].decode("utf-8", "replace")
    position = end + 1 + 4  # connection id
    auth_part_1 = packet[position : position + 8]
    position += 8 + 1  # filler
    capability_lower = struct.unpack("<H", packet[position : position + 2])[0]
    position += 2
    capabilities = capability_lower
    # extended capabilities only exist when the server speaks 4.1+
    if len(packet) >= position + 3 + 2 + 13:
        position += 1  # character set
        position += 2  # status flags
        capability_upper = struct.unpack("<H", packet[position : position + 2])[0]
        position += 2
        capabilities |= capability_upper << 16
    return {
        "protocol_version": protocol_version,
        "server_version": server_version,
        "capabilities": capabilities,
        "ssl_capable": bool(capabilities & MYSQL_CLIENT_SSL),
        "auth_plugin_data_length": len(auth_part_1),
    }


def _mysql_ssl_request() -> bytes:
    """A 32-byte SSLRequest: capability flags + max packet + charset + filler."""
    capabilities = MYSQL_CLIENT_SSL | 0x00008000 | 0x00000008  # SSL | SECURE_CONNECTION | PROTOCOL_41
    body = struct.pack("<IIB23x", capabilities, 16777216, 33)
    return struct.pack("<I", len(body))[:3] + b"\x00" + body


def probe_mysql_tls(host: str, port: int = 3306, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Read a MySQL handshake, request TLS and observe the negotiated session."""
    result = _base(host, port, "MYSQL")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            header = _read_exact(sock, 4)
            length = int.from_bytes(header[:3], "little")
            if length < 10 or length > 65535:
                result["status"] = "UNEXPECTED_RESPONSE"
                result["detail"] = f"implausible handshake length {length}"
                return result
            packet = _read_exact(sock, length)
            try:
                parsed = parse_mysql_handshake(packet)
            except ValueError as exc:
                result["status"] = "NOT_MYSQL"
                result["detail"] = str(exc)[:200]
                return result
            result["server_note"] = parsed["server_version"]
            result["tls_supported"] = parsed["ssl_capable"]
            if not parsed["ssl_capable"]:
                result["status"] = "TLS_REFUSED"
                result["server_note"] = f"{parsed['server_version']} advertises no CLIENT_SSL capability"
                return result
            sock.sendall(_mysql_ssl_request())
            try:
                hs = handshake(sock, host, timeout=timeout)
            except Exception as exc:  # noqa: BLE001
                result["status"] = "TLS_HANDSHAKE_FAILED"
                result["detail"] = f"{type(exc).__name__}: {exc}"[:200]
                return result
            result.update(
                {
                    "status": "TLS_AVAILABLE",
                    "tls_version": hs.get("version"),
                    "cipher_suite": (hs.get("cipher") or (None,))[0],
                    "certificate": hs.get("certificate"),
                }
            )
            return result
    except (ConnectionRefusedError, socket.timeout, TimeoutError, OSError) as exc:
        result["status"] = "UNREACHABLE"
        result["detail"] = f"{type(exc).__name__}: {exc}"[:200]
        return result


def probe_database(host: str, port: int, *, engine: str | None = None, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Dispatch to the right database probe, defaulting from the port."""
    engine_name = (engine or ("POSTGRESQL" if int(port) == 5432 else "MYSQL" if int(port) in {3306, 3307} else "")).upper()
    if engine_name in {"POSTGRESQL", "POSTGRES", "PG"}:
        return probe_postgres_tls(host, port, timeout=timeout)
    if engine_name in {"MYSQL", "MARIADB"}:
        return probe_mysql_tls(host, port, timeout=timeout)
    result = _base(host, port, engine_name or "UNKNOWN")
    result["status"] = "UNSUPPORTED_ENGINE"
    result["detail"] = "no transport-TLS probe for this engine — transport crypto stays NOT_OBSERVED"
    return result
