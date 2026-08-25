"""TLS handshake execution against an existing TCP socket."""

from __future__ import annotations

import ssl
from typing import Any


def handshake(sock, hostname: str, *, timeout: float | None = None) -> dict[str, Any]:
    if timeout is not None:
        try:
            sock.settimeout(timeout)
        except Exception:
            pass
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls = context.wrap_socket(sock, server_hostname=hostname)
    cipher = tls.cipher() or (None, None, None)
    der = None
    try:
        der = tls.getpeercert(binary_form=True)
    except Exception:
        der = None
    return {
        "status": "OK",
        "socket": tls,
        "version": tls.version(),
        "cipher": cipher,
        "peercert": tls.getpeercert() or {},
        "der": der,
        "hostname": hostname,
    }
