"""Weak cipher acceptance probe — does the server still negotiate dead suites?

Pins the context to a single weak cipher (TLS 1.2 era) and attempts the
handshake. Outcomes per candidate:

- ``ACCEPTED``            the server negotiated the weak suite (finding!)
- ``REFUSED``             server refused — healthy
- ``LOCAL_UNSUPPORTED``   this scanner's OpenSSL cannot offer the suite
  (default OpenSSL 3 builds disable RC4/3DES) — reported honestly, never
  silently skipped
"""

from __future__ import annotations

import socket
import ssl
from typing import Any

#: candidate -> registry severity class when accepted
WEAK_CIPHER_CANDIDATES: list[tuple[str, str]] = [
    ("RC4-SHA", "DISALLOWED"),
    ("RC4-MD5", "DISALLOWED"),
    ("DES-CBC3-SHA", "DISALLOWED"),   # 3DES
    ("NULL-SHA", "DISALLOWED"),
    ("AES128-SHA", "CBC"),            # TLS 1.2 CBC — restricted, not dead
    ("AES256-SHA", "CBC"),
]


def probe_weak_ciphers(
    host: str,
    port: int,
    *,
    ip: str | None = None,
    timeout: float = 4.0,
    sni: str | None = None,
) -> dict[str, Any]:
    """Try each weak candidate; report accepted/refused/local-unsupported."""
    accepted: list[dict[str, str]] = []
    refused: list[str] = []
    local_unsupported: list[str] = []
    for cipher_name, severity in WEAK_CIPHER_CANDIDATES:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.set_ciphers(cipher_name)
        except ssl.SSLError:
            local_unsupported.append(cipher_name)
            continue
        if not context.get_ciphers():
            local_unsupported.append(cipher_name)
            continue
        try:
            context.maximum_version = ssl.TLSVersion.TLSv1_2  # weak suites are pre-1.3
        except (ValueError, ssl.SSLError):
            pass
        try:
            with socket.create_connection((ip or host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=sni or host):
                    accepted.append({"cipher": cipher_name, "severity": severity})
        except ssl.SSLError as exc:
            text = str(exc).lower()
            if "certificate required" in text or "peer did not return" in text:
                accepted.append({"cipher": cipher_name, "severity": severity})
            elif "no ciphers can be selected" in text or "no shared cipher" in text or "handshake failure" in text:
                refused.append(cipher_name)
            else:
                refused.append(cipher_name)
        except (TimeoutError, OSError):
            break  # endpoint went away; remaining candidates untestable
    return {
        "accepted": accepted,
        "refused": refused,
        "local_unsupported": local_unsupported,
        "disallowed_accepted": [row["cipher"] for row in accepted if row["severity"] == "DISALLOWED"],
        "cbc_accepted": [row["cipher"] for row in accepted if row["severity"] == "CBC"],
    }
