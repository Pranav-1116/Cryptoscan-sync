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

    if raw.startswith("TLS_") and "_WITH_" in raw:
        # IANA TLS 1.2 name: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.
        # Passive sensors, the IANA registry and CBOM exports use this form,
        # while the OpenSSL form (ECDHE-RSA-AES256-GCM-SHA384) uses dashes.
        # Normalise to the OpenSSL spelling so both parse identically, rather
        # than reporting an observed suite as unparsed.
        import re

        converted = raw[4:].replace("_WITH_", "_")
        # IANA writes "AES_256_GCM"; OpenSSL (which the tokenizer below
        # understands) writes "AES256-GCM". Collapse the key size first so the
        # bulk cipher is not split into its own tokens.
        converted = re.sub(r"(AES|CAMELLIA|ARIA|CHACHA20)_(\d+)", r"\1\2", converted)
        converted = re.sub(r"3DES_EDE_CBC", "3DES-EDE-CBC", converted)
        raw = converted.replace("_", "-")
        result["cipher_suite"] = name

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


# --------------------------------------------------------------------------- #
# shared-registry verdicts + policy issues
# --------------------------------------------------------------------------- #

DEPRECATED_TLS_VERSIONS = {"SSLv3", "TLS1.0", "TLS1.1"}
DISALLOWED_BULK_CIPHERS = {"3DES", "DES", "RC4", "NULL", "RC2", "IDEA", "EXPORT"}

#: issue severity order (first match wins as the headline compliance_issue)
_ISSUE_ORDER = {
    "DISALLOWED_CIPHER": 0,
    "WEAK_TLS_VERSION": 1,
    "WEAK_CIPHER_SUITE": 2,
    "CBC_MODE": 3,
    "NO_HSTS": 4,
    "WEAK_TLS_VERSION_ACCEPTED": 1,
    "DISALLOWED_CIPHER_ACCEPTED": 0,
    "CBC_ACCEPTED": 3,
    "CERT_REVOKED": 0,
    "INSECURE_RENEGOTIATION_ENABLED": 5,
    "CLIENT_RENEGOTIATION_ACCEPTED": 5,
    "CHAIN_LINK_BROKEN": 6,
    "CHAIN_ORDER_BROKEN": 6,
    "CHAIN_WEAK_INTERMEDIATE": 7,
    "CHAIN_INCOMPLETE": 8,
    "DUPLICATE_CERT_IN_CHAIN": 9,
    "ROOT_CERT_SENT": 10,
    "SSH_HOST_KEY_CHANGED": 0,
    "SSH_DSS_HOST_KEY": 1,
    "SSH_WEAK_HOST_KEY": 2,
    "SSH_RSA_HOST_KEY": 4,
    "SSH_WEAK_CIPHER_OFFERED": 2,
    "SSH_WEAK_MAC_OFFERED": 2,
    "SSH_WEAK_KEX_OFFERED": 3,
    "SSH_LEGACY_ALGORITHM_OFFERED": 4,
}


def registry_verdict(cipher_suite: str | None) -> dict[str, Any]:
    """Algorithm-registry verdict for a negotiated suite (tolerant import)."""
    try:
        from shared_models.algorithm_registry import parse_algorithm

        info = parse_algorithm(str(cipher_suite or "TLS"))
        bulk = next((c for c in info.components if c.get("role") == "bulk_cipher"), None)
        return {
            "status": info.status,
            "key_size": info.key_size,
            "quantum_impact": info.quantum_impact,
            "algorithm": (bulk or info.to_dict()).get("algorithm") or info.canonical,
        }
    except Exception:  # noqa: BLE001 — degrade to UNKNOWN, never crash a probe
        return {"status": "UNKNOWN", "key_size": None, "quantum_impact": None, "algorithm": None}


def policy_issues(crypto: dict[str, Any] | None, *, hsts: dict[str, Any] | None = None) -> list[str]:
    """Compliance issues for a negotiated TLS session.

    ``crypto`` is the finding's crypto block (tls_version, cipher_suite,
    encryption, mode, status...); ``hsts`` the optional header facts.
    """
    crypto = crypto or {}
    issues: list[str] = []
    version = str(crypto.get("tls_version") or "").replace("TLSv", "TLS").replace("SSLv", "SSL")
    if version in {"TLS1.0", "TLS1.1", "SSL3.0", "SSL3", "SSL2.0"} or version in DEPRECATED_TLS_VERSIONS:
        issues.append("WEAK_TLS_VERSION")
    encryption = str(crypto.get("encryption_algorithm") or "").upper()
    if any(bad in encryption for bad in DISALLOWED_BULK_CIPHERS):
        issues.append("DISALLOWED_CIPHER")
    status = str(crypto.get("status") or "")
    if status in {"DISALLOWED", "DEPRECATED"} and "DISALLOWED_CIPHER" not in issues:
        issues.append("WEAK_CIPHER_SUITE")
    if str(crypto.get("encryption_mode") or "").upper() == "CBC" and "CHACHA" not in encryption:
        issues.append("CBC_MODE")
    if hsts is not None and not (hsts.get("hsts") or {}).get("present", False):
        issues.append("NO_HSTS")
    return sorted(set(issues), key=lambda issue: _ISSUE_ORDER.get(issue, 99))


def headline_issue(issues: list[str]) -> str | None:
    """Most severe issue for the finding's compliance_issue field."""
    if not issues:
        return None
    return sorted(issues, key=lambda issue: _ISSUE_ORDER.get(issue, 99))[0]
