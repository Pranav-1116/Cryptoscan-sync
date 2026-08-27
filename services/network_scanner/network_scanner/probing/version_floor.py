"""TLS version floor probe — which protocol versions a server still accepts.

A normal handshake negotiates the *best* mutual version, which hides the
compliance question enterprises actually ask: *does this endpoint still
accept TLS 1.0?* This probe pins each version with
``minimum_version == maximum_version`` and records ACCEPTED / REFUSED /
LOCAL_UNSUPPORTED (the scanner's own OpenSSL may forbid old versions) /
UNREACHABLE per candidate.
"""

from __future__ import annotations

import socket
import ssl
from typing import Any

WEAK_VERSIONS = {"TLSv1.0", "TLSv1.1"}


def _target_versions() -> list[tuple[str, "ssl.TLSVersion"]]:
    candidates = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]
    return candidates


def probe_version_floor(
    host: str,
    port: int,
    *,
    ip: str | None = None,
    timeout: float = 4.0,
    sni: str | None = None,
) -> dict[str, Any]:
    """Handshake once per TLS version; report what the server accepts."""
    outcomes: dict[str, str] = {}
    for name, version in _target_versions():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
        except (ValueError, ssl.SSLError):
            outcomes[name] = "LOCAL_UNSUPPORTED"
            continue
        try:
            with socket.create_connection((ip or host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=sni or host):
                    outcomes[name] = "ACCEPTED"
        except ssl.SSLError as exc:
            outcomes[name] = _refused_or_local(exc)
        except TimeoutError:
            outcomes[name] = "TIMEOUT"
            break  # endpoint stopped answering mid-scan
        except OSError:
            outcomes[name] = "UNREACHABLE"
            break
    accepted = [name for name, verdict in outcomes.items() if verdict == "ACCEPTED"]
    weak_accepted = [name for name in accepted if name in WEAK_VERSIONS]
    return {
        "versions": outcomes,
        "accepted": accepted,
        "weakest_accepted": min(accepted) if accepted else None,  # lexicographic works for TLSv1.x
        "weak_accepted": weak_accepted,
        "strongest_accepted": max(accepted) if accepted else None,
        "untestable": sorted(name for name, verdict in outcomes.items() if verdict == "LOCAL_UNSUPPORTED"),
    }


def _refused_or_local(exc: ssl.SSLError) -> str:
    """Distinguish server refusal from the local OpenSSL forbidding a version."""
    text = str(exc).lower()
    if "no supported protocol" in text or "no ciphers can be selected" in text or "unsupported protocol" in text:
        # the CLIENT could not configure the version — nothing learned about the server
        return "LOCAL_UNSUPPORTED"
    if "certificate required" in text or "peer did not return" in text:
        return "ACCEPTED"  # version negotiated; server then demanded a client cert
    return "REFUSED"
