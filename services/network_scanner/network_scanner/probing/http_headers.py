"""Minimal HTTP header probe over an established TLS socket (HSTS etc.).

After the TLS handshake succeeds we can still speak HTTP inside the
encrypted channel — this sends a HEAD request and collects the security
headers that matter for transport-crypto posture:

- ``strict-transport-security`` (HSTS) with max-age parsed
- whether the response redirects to https

Failures are always non-fatal: plenty of TLS endpoints are not HTTP.
"""

from __future__ import annotations

from typing import Any


def check_http_headers(tls_socket, host: str, *, timeout: float = 4.0) -> dict[str, Any] | None:
    """Send one HEAD request; return header facts or None if not HTTP."""
    try:
        tls_socket.settimeout(timeout)
        tls_socket.sendall(
            f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: cryptoscan-tls-probe\r\nConnection: close\r\n\r\n".encode()
        )
        raw = bytearray()
        while b"\r\n\r\n" not in raw and len(raw) < 65536:
            chunk = tls_socket.recv(4096)
            if not chunk:
                break
            raw.extend(chunk)
    except Exception:
        return None
    if not raw:
        return None
    text = raw.decode("iso-8859-1", errors="replace")
    head = text.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return None

    status_code = 0
    parts = lines[0].split(" ", 2)
    if len(parts) >= 2 and parts[1].isdigit():
        status_code = int(parts[1])

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

    hsts = headers.get("strict-transport-security")
    max_age = None
    includes_subdomains = False
    preload = False
    if hsts:
        max_age = _max_age(hsts)
        includes_subdomains = "includesubdomains" in hsts.lower()
        preload = "preload" in hsts.lower()

    location = headers.get("location")
    return {
        "http_status": status_code,
        "hsts": {
            "present": hsts is not None,
            "max_age": max_age,
            "include_subdomains": includes_subdomains,
            "preload": preload,
            "raw": hsts,
        },
        "redirects_to_https": bool(location and location.lower().startswith("https://")),
        "server": headers.get("server"),
        "headers": list(headers),
    }


def _max_age(hsts_value: str) -> int | None:
    for token in hsts_value.split(";"):
        key, _, value = token.strip().partition("=")
        if key.strip().lower() == "max-age" and value.strip().isdigit():
            return int(value.strip())
    return None
