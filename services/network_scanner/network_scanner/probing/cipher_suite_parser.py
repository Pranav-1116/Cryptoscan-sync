"""Parse OpenSSL / IANA TLS 1.2 and TLS 1.3 cipher suite names."""

from __future__ import annotations

from typing import Any


def parse_cipher_suite(name: str | None, *, tls_version: str | None = None, bits: int | None = None) -> dict[str, Any]:
    raw = (name or "").strip()
    result: dict[str, Any] = {
        "cipher_suite": raw or None,
        "tls_version": tls_version,
        "key_exchange": None,
        "authentication": None,
        "encryption": None,
        "mode": None,
        "mac": None,
        "key_size": bits,
        "algorithm": "TLS",
    }
    if not raw:
        return result

    if raw.startswith("TLS_"):
        # TLS 1.3: TLS_AES_256_GCM_SHA384 / TLS_CHACHA20_POLY1305_SHA256
        parts = [p for p in raw.split("_") if p and p != "TLS"]
        result["key_exchange"] = "ECDHE"
        result["tls_version"] = result["tls_version"] or "TLSv1.3"
        if parts and parts[0] == "AES" and len(parts) >= 2 and parts[1].isdigit():
            result["encryption"] = f"AES-{parts[1]}"
            result["algorithm"] = "AES"
            result["key_size"] = result["key_size"] or int(parts[1])
            result["mode"] = parts[2] if len(parts) > 2 else None
            result["mac"] = parts[3] if len(parts) > 3 else None
        elif "CHACHA20" in parts:
            result["encryption"] = "ChaCha20-Poly1305"
            result["algorithm"] = "ChaCha20-Poly1305"
            result["mode"] = "AEAD"
            result["mac"] = "POLY1305"
        return result

    # OpenSSL TLS 1.2: ECDHE-RSA-AES256-GCM-SHA384
    tokens = [t for t in raw.replace("_", "-").split("-") if t]
    if not tokens:
        return result
    kx = tokens[0]
    if kx in {"ECDHE", "DHE", "ECDH", "DH", "RSA"}:
        result["key_exchange"] = kx
        tokens = tokens[1:]
    if tokens and tokens[0] in {"RSA", "ECDSA", "DSS", "PSK", "Ed25519"}:
        result["authentication"] = tokens[0]
        tokens = tokens[1:]
    if tokens:
        enc = tokens[0]
        if enc.upper().startswith("AES") and enc[3:].isdigit():
            result["encryption"] = f"AES-{enc[3:]}"
            result["algorithm"] = "AES"
            result["key_size"] = result["key_size"] or int(enc[3:])
        elif enc.upper() in {"CHACHA20", "CHACHA20POLY1305"}:
            result["encryption"] = "ChaCha20-Poly1305"
            result["algorithm"] = "ChaCha20-Poly1305"
        elif enc.upper() in {"3DES", "DES", "RC4", "CAMELLIA"}:
            result["encryption"] = enc.upper()
            result["algorithm"] = "3DES" if enc.upper() == "3DES" else enc.upper()
        else:
            result["encryption"] = enc
    if len(tokens) > 1 and tokens[1] in {"GCM", "CCM", "CBC", "CHACHA20"}:
        result["mode"] = "AEAD" if tokens[1] == "CHACHA20" else tokens[1]
    if tokens:
        result["mac"] = tokens[-1] if tokens[-1].upper().startswith("SHA") else result["mac"]
    return result


def tls_algorithm(version: str | None) -> str:
    raw = (version or "").upper().replace(" ", "")
    if raw in {"SSLV3", "SSL3", "SSLV3.0"}:
        return "SSLv3"
    if raw in {"TLSV1", "TLSV1.0", "TLS1.0", "TLS1"}:
        return "TLS1.0"
    if raw in {"TLSV1.1", "TLS1.1"}:
        return "TLS1.1"
    if raw in {"TLSV1.2", "TLS1.2"}:
        return "TLS1.2"
    if raw in {"TLSV1.3", "TLS1.3"}:
        return "TLS1.3"
    return "TLS"
