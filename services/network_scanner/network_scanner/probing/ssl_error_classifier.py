"""Classify stdlib ssl.SSLError strings into probe error types."""

from __future__ import annotations


def classify_ssl_error(exc: BaseException | str) -> str:
    text = str(exc).lower()
    if "version" in text or "protocol" in text or "wrong version number" in text:
        return "PROTOCOL_VERSION_MISMATCH"
    if "cipher" in text:
        return "CIPHER_SUITE_MISMATCH"
    if "certificate" in text or "verify" in text or "hostname" in text:
        return "CERTIFICATE_VERIFY_FAILED"
    if "handshake" in text:
        return "HANDSHAKE_FAILURE"
    return "TLS_ERROR"
