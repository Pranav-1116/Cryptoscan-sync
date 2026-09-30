"""STARTTLS protocol negotiation for non-HTTPS TLS endpoints.

Mail relays, IMAP servers, LDAP directories and databases speak TLS only
after a plaintext upgrade command. Each negotiator reads the greeting,
sends the protocol's STARTTLS command and returns once the server has
agreed — the caller then wraps the socket in TLS as usual.

Negotiators are pure functions over an open socket so tests can drive
them with scripted servers.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from typing import Any

#: well-known ports -> protocol (auto-detection when starttls="auto")
STARTTLS_BY_PORT: dict[int, str] = {
    25: "smtp",
    587: "smtp",
    143: "imap",
    110: "pop3",
    21: "ftp",
    389: "ldap",
    119: "nntp",
    5432: "postgresql",
    3306: "mysql",
    1521: "oracle",
    1433: "mssql",
}

_SUPPORTED = {"smtp", "imap", "pop3", "ftp", "ldap", "postgresql"}


def protocol_for_port(port: int) -> str | None:
    return STARTTLS_BY_PORT.get(port)


def negotiate_starttls(sock, protocol: str, *, timeout: float = 5.0) -> dict[str, Any]:
    """Perform the plaintext STARTTLS upgrade for ``protocol``.

    Returns {"ok": bool, "protocol": str, "detail": str}. On failure the
    socket state is undefined — the caller should close it.
    """
    try:
        sock.settimeout(timeout)
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
    try:
        handler = _NEGOTIATORS[protocol]
    except KeyError:
        return {"ok": False, "protocol": protocol, "detail": "unsupported STARTTLS protocol"}
    try:
        return handler(sock)
    except Exception as exc:  # noqa: BLE001 — probe boundary: report, never crash
        return {"ok": False, "protocol": protocol, "detail": f"{type(exc).__name__}: {exc}"[:200]}


def _recv_line(sock, limit: int = 4096) -> str:
    data = bytearray()
    while b"\n" not in data and len(data) < limit:
        chunk = sock.recv(256)
        if not chunk:
            break
        data.extend(chunk)
    return data.decode("utf-8", errors="replace")


def _send(sock, text: str) -> None:
    sock.sendall(text.encode("utf-8") + b"\r\n")


def _smtp(sock) -> dict[str, Any]:
    greeting = _recv_line(sock)
    if "220" not in greeting[:3]:
        return {"ok": False, "protocol": "smtp", "detail": f"unexpected greeting: {greeting[:80]!r}"}
    _send(sock, "EHLO cryptoscan.probe")
    ehlo = _recv_line(sock)
    if "250" not in ehlo[:3] and "STARTTLS" not in ehlo.upper():
        # multi-line EHLO: drain until the final response line
        while ehlo[:3] not in {"250", "251"} and not ehlo[3:4] == " " and ehlo.strip():
            ehlo = _recv_line(sock)
    _send(sock, "STARTTLS")
    response = _recv_line(sock)
    if response.startswith("220"):
        return {"ok": True, "protocol": "smtp", "detail": "220 ready"}
    return {"ok": False, "protocol": "smtp", "detail": f"STARTTLS refused: {response.strip()[:120]}"}


def _imap(sock) -> dict[str, Any]:
    greeting = _recv_line(sock)
    if "OK" not in greeting.upper():
        return {"ok": False, "protocol": "imap", "detail": f"unexpected greeting: {greeting[:80]!r}"}
    _send(sock, "a001 STARTTLS")
    response = _recv_line(sock)
    if "OK" in response.upper():
        return {"ok": True, "protocol": "imap", "detail": response.strip()[:120]}
    return {"ok": False, "protocol": "imap", "detail": f"STARTTLS refused: {response.strip()[:120]}"}


def _pop3(sock) -> dict[str, Any]:
    greeting = _recv_line(sock)
    if "+OK" not in greeting:
        return {"ok": False, "protocol": "pop3", "detail": f"unexpected greeting: {greeting[:80]!r}"}
    _send(sock, "STLS")
    response = _recv_line(sock)
    if response.startswith("+"):
        return {"ok": True, "protocol": "pop3", "detail": response.strip()[:120]}
    return {"ok": False, "protocol": "pop3", "detail": f"STLS refused: {response.strip()[:120]}"}


def _ftp(sock) -> dict[str, Any]:
    greeting = _recv_line(sock)
    if "220" not in greeting[:3]:
        return {"ok": False, "protocol": "ftp", "detail": f"unexpected greeting: {greeting[:80]!r}"}
    _send(sock, "AUTH TLS")
    response = _recv_line(sock)
    if response.startswith("234"):
        return {"ok": True, "protocol": "ftp", "detail": response.strip()[:120]}
    return {"ok": False, "protocol": "ftp", "detail": f"AUTH TLS refused: {response.strip()[:120]}"}


def _ldap(sock) -> dict[str, Any]:
    # LDAP extended operation 1.3.6.1.4.1.1466.20.037 (StartTLS) — BER encoded
    request = bytes.fromhex("301d0201" "01" "77" "188016" "312e332e362e312e342e312e313436362e32302e303337")
    sock.sendall(request)
    response = sock.recv(256)
    # a valid StartTLS response is 30 1c 02 01 01 78 17 0a 01 00 04 00 04 00
    if len(response) >= 7 and response[0] == 0x30 and b"\x78" in response[:8]:
        return {"ok": True, "protocol": "ldap", "detail": "StartTLS extended response accepted"}
    return {"ok": False, "protocol": "ldap", "detail": f"unexpected response: {response[:32].hex()}"}


def _postgresql(sock) -> dict[str, Any]:
    # PostgreSQL SSLRequest: length 8, code 80877103
    import struct

    sock.sendall(struct.pack("!II", 8, 80877103))
    response = sock.recv(1)
    if response == b"S":
        return {"ok": True, "protocol": "postgresql", "detail": "server agrees to SSL"}
    return {"ok": False, "protocol": "postgresql", "detail": f"server refused SSL ({response!r})"}


_NEGOTIATORS = {
    "smtp": _smtp,
    "imap": _imap,
    "pop3": _pop3,
    "ftp": _ftp,
    "ldap": _ldap,
    "postgresql": _postgresql,
}
