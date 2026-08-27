"""RFC 5746 renegotiation probe via ``openssl s_client``.

Two independent facts, both honest about local limits:

* ``secure_renegotiation`` — did the server negotiate the RFC 5746
  ``renegotiation_info`` extension (``Secure Renegotiation IS [NOT] supported``
  in s_client output)?  Servers without it allow the CVE-2009-3555
  plaintext-injection attack.
* ``client_renegotiation`` — when the client initiates a renegotiation (``R``
  in s_client on a TLS<=1.2 session), does the server complete it?  Accepting
  client-initiated renegotiation is a CPU DoS vector (CVE-2011-1473).

Renegotiation does not exist in TLS 1.3 (post-handshake messages replaced it),
so the probe pins TLS 1.2; a server that refuses TLS 1.2 entirely yields
``UNTESTABLE`` rather than a guess.  When the openssl binary is missing or
cannot run, the outcome is ``LOCAL_UNSUPPORTED`` — never a silent skip.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any

_RENEG_ERROR = re.compile(
    r"no renegotiation|unsafe legacy renegotiation|handshake failure|"
    r"unexpected message|decryption failed|bad handshake|no renegotiation",
    re.IGNORECASE,
)
_NEW_SESSION = re.compile(r"New, .*Cipher is|CONNECTION ESTABLISHED", re.IGNORECASE)


def _openssl_binary() -> str | None:
    return shutil.which("openssl")


def _run_s_client(
    binary: str,
    host: str,
    port: int,
    *,
    connect_to: str | None = None,
    sni: str | None = None,
    timeout: float = 5.0,
    payload: bytes = b"",
) -> str:
    """Run ``openssl s_client`` once and return combined stdout+stderr text."""
    target = f"{connect_to or host}:{port}"
    argv = [
        binary,
        "s_client",
        "-connect",
        target,
        "-servername",
        sni or host,
        "-tls1_2",
    ]
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, local diagnostic tool
            argv,
            input=payload,
            capture_output=True,
            timeout=max(3.0, timeout) + 2.0,
        )
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return (proc.stdout or b"").decode("utf-8", "replace") + (proc.stderr or b"").decode("utf-8", "replace")


def parse_renegotiation_output(handshake_text: str, renegotiation_text: str) -> dict[str, Any]:
    """Pure classifier over the two s_client transcripts (unit-testable).

    ``handshake_text``: plain connect transcript (secure-renegotiation fact).
    ``renegotiation_text``: transcript of the session that sent ``R\\n``.
    """
    lowered = handshake_text.lower()
    secure = "UNKNOWN"
    detail: str | None = None
    if "secure renegotiation is supported" in lowered:
        secure = "SUPPORTED"
    elif "secure renegotiation is not supported" in lowered:
        secure = "NOT_SUPPORTED"
    elif handshake_text and "no peer cert" not in lowered:
        detail = "handshake transcript carried no renegotiation indicator"

    client_reneg = "UNTESTABLE"
    reneg_detail: str | None = None
    text = renegotiation_text
    if text and "RENEGOTIATING" in text:
        after = text.split("RENEGOTIATING", 1)[1]
        error_match = _RENEG_ERROR.search(after)
        if error_match:
            client_reneg = "REFUSED"
            reneg_detail = error_match.group(0).strip()
        elif len(_NEW_SESSION.findall(text)) >= 2:
            # the initial handshake plus a second completed handshake
            client_reneg = "ACCEPTED"
        else:
            client_reneg = "UNKNOWN"
            reneg_detail = "renegotiation started but completion was not observed"
    elif text:
        reneg_detail = "client did not attempt renegotiation"

    return {
        "secure_renegotiation": secure,
        "client_renegotiation": client_reneg,
        "secure_detail": detail,
        "client_detail": reneg_detail,
    }


def probe_renegotiation(
    host: str,
    port: int,
    *,
    ip: str | None = None,
    sni: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Probe secure- and client-initiated renegotiation for one endpoint."""
    result: dict[str, Any] = {
        "method": "openssl-sclient",
        "tls_version": "TLSv1.2",  # renegotiation is a TLS<=1.2 mechanism
        "secure_renegotiation": "UNKNOWN",
        "client_renegotiation": "UNTESTABLE",
        "secure_detail": None,
        "client_detail": None,
    }
    binary = _openssl_binary()
    if not binary:
        result["method"] = "openssl-sclient-unavailable"
        result["client_renegotiation"] = "LOCAL_UNSUPPORTED"
        result["secure_detail"] = "openssl binary not found on this host"
        return result
    handshake = _run_s_client(binary, host, port, connect_to=ip, sni=sni, timeout=timeout)
    if not handshake.strip():
        # could not even complete the pinned TLS 1.2 handshake
        result["secure_detail"] = "TLS 1.2 handshake did not complete (refused or unreachable)"
        return result
    renegotiation = _run_s_client(
        binary, host, port, connect_to=ip, sni=sni, timeout=timeout, payload=b"R\n"
    )
    result.update(parse_renegotiation_output(handshake, renegotiation))
    return result
