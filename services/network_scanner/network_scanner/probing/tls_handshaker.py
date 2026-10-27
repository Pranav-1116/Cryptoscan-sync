"""TLS handshake execution against an existing TCP socket."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import ssl
from typing import Any


def handshake(sock, hostname: str, *, timeout: float | None = None) -> dict[str, Any]:
    if timeout is not None:
        try:
            sock.settimeout(timeout)
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
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
    from network_scanner.certificates.cert_parser import parse_der

    return {
        "status": "OK",
        "socket": tls,
        "version": tls.version(),
        "cipher": cipher,
        "peercert": tls.getpeercert() or {},
        "der": der,
        "certificate": parse_der(der) if der else None,
        "hostname": hostname,
    }


def approved_session_engine(sni: str, version: str):
    """Constrained shared engine; caller owns exact TCP scope, budgets and fingerprint check."""
    from shared_models.tls_session import client_session

    return client_session(sni, version)
