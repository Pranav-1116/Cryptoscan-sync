"""Deterministic TLS protocol-version and cipher-suite classification.

Pure functions — no I/O — so the policy verdicts are unit-testable and stable.
The live engine (tls_audit) feeds observed negotiated values in and the
classifier maps them to severity classes per a fixed, conservative policy.
"""

from __future__ import annotations

from dataclasses import dataclass

# Protocol policy. TLS 1.0/1.1 are deprecated (RFC 8996); SSLv2/v3 dead.
PROTOCOL_POLICY: dict[str, dict] = {
    "SSLv2":  {"allowed": False, "severity": "CRITICAL", "reason": "SSLv2 is broken and prohibited"},
    "SSLv3":  {"allowed": False, "severity": "CRITICAL", "reason": "SSLv3 (POODLE) is prohibited"},
    "TLSv1":  {"allowed": False, "severity": "HIGH",     "reason": "TLS 1.0 deprecated (RFC 8996); downgrade risk"},
    "TLSv1.1":{"allowed": False, "severity": "HIGH",     "reason": "TLS 1.1 deprecated (RFC 8996); downgrade risk"},
    "TLSv1.2":{"allowed": True,  "severity": "INFO",     "reason": "TLS 1.2 acceptable with modern suites"},
    "TLSv1.3":{"allowed": True,  "severity": "INFO",     "reason": "TLS 1.3 current"},
}

# Cipher-suite keyword classifications (matched against the OpenSSL/IANA name).
# Order matters: most specific / strongest disqualifiers first.
_DISALLOWED_TOKENS = (
    ("NULL",    "NULL encryption — no confidentiality", "CRITICAL"),
    ("ANON",    "anonymous key exchange — no authentication (MITM)", "CRITICAL"),
    ("EXPORT",  "export-grade — trivially breakable", "CRITICAL"),
    ("RC4",     "RC4 stream cipher — biased, prohibited", "CRITICAL"),
    ("DES-",    "single DES — 56-bit, broken", "CRITICAL"),
    ("3DES",    "3DES / DES-CBC3 — Sweet32 birthday bound", "HIGH"),
    ("MD5",     "MD5 MAC/PRF — collision-prone", "HIGH"),
)
_WEAK_TOKENS = (
    ("CBC",     "CBC mode in TLS 1.2 — padding-oracle (Lucky13) exposure", "MEDIUM"),
    ("RSA",     "RSA key exchange — no forward secrecy", "MEDIUM"),
    ("KX-RSA",  "RSA key exchange — no forward secrecy", "MEDIUM"),
)
# TLS 1.3 suites are AEAD-only and strong by construction.
_TLS13_STRONG_PREFIXES = ("TLS_AES_256_GCM", "TLS_CHACHA20_POLY1305", "TLS_AES_128_GCM")
_STRONG_TOKENS = ("GCM", "CHACHA20", "POLY1305", "ECDHE", "DHE")


@dataclass
class CipherVerdict:
    name: str
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    allowed: bool
    forward_secrecy: bool
    aead: bool
    reasons: list[str]


def classify_protocol(version: str | None) -> dict:
    if not version:
        return {"version": None, "allowed": False, "severity": "HIGH",
                "reason": "no protocol version negotiated"}
    key = _normalize_version(version)
    pol = PROTOCOL_POLICY.get(key)
    if pol is None:
        return {"version": key, "allowed": False, "severity": "MEDIUM",
                "reason": f"unknown protocol version {version!r}"}
    return {"version": key, "allowed": pol["allowed"], "severity": pol["severity"],
            "reason": pol["reason"]}


def _normalize_version(version: str) -> str:
    v = version.strip().replace(" ", "")
    aliases = {
        "TLS1.0": "TLSv1", "TLSv1.0": "TLSv1", "TLS1": "TLSv1",
        "TLS1.1": "TLSv1.1", "TLSv1.1": "TLSv1.1",
        "TLS1.2": "TLSv1.2", "TLSv1.2": "TLSv1.2",
        "TLS1.3": "TLSv1.3", "TLSv1.3": "TLSv1.3",
        "SSL2": "SSLv2", "SSLv2": "SSLv2", "SSL3": "SSLv3", "SSLv3": "SSLv3",
    }
    return aliases.get(v, v)


def classify_cipher(cipher_name: str | None, *, protocol: str | None = None) -> CipherVerdict:
    name = (cipher_name or "").upper()
    reasons: list[str] = []
    severity = "INFO"
    allowed = True

    if not name:
        return CipherVerdict(name="", severity="HIGH", allowed=False,
                             forward_secrecy=False, aead=False,
                             reasons=["no cipher negotiated"])

    is_tls13 = name.startswith("TLS_") and any(name.startswith(p) for p in _TLS13_STRONG_PREFIXES)

    for token, reason, sev in _DISALLOWED_TOKENS:
        if token in name:
            reasons.append(reason)
            allowed = False
            severity = _max_sev(severity, sev)

    if not is_tls13:
        for token, reason, sev in _WEAK_TOKENS:
            # "RSA" as a bare KX token shouldn't fire on ECDHE-RSA (auth); only
            # flag static-RSA key exchange (no ECDHE/DHE prefix).
            if token == "RSA" and ("ECDHE" in name or "DHE" in name):
                continue
            if token in name:
                reasons.append(reason)
                severity = _max_sev(severity, sev)
                if token == "RSA" or token == "KX-RSA":
                    pass  # allowed but weak

    fs = ("ECDHE" in name) or ("DHE" in name and "EXPORT" not in name)
    aead = ("GCM" in name) or ("CHACHA20" in name) or ("CCM" in name)
    if not fs and allowed:
        reasons.append("no forward secrecy")
        severity = _max_sev(severity, "MEDIUM")
    if aead and allowed and not reasons:
        reasons.append("AEAD + forward secrecy")
    elif not aead and allowed and severity == "INFO":
        reasons.append("non-AEAD cipher")
        severity = _max_sev(severity, "LOW")

    if is_tls13 and allowed:
        severity = "INFO"
        reasons = ["TLS 1.3 AEAD suite — strong"]
    return CipherVerdict(name=cipher_name or "", severity=severity, allowed=allowed,
                         forward_secrecy=fs, aead=aead, reasons=reasons)


_SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _max_sev(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b


def overall_grade(findings: list[dict]) -> dict:
    """Roll protocol + cipher findings up into an A–F grade."""
    worst = "INFO"
    n_crit = n_high = 0
    for f in findings:
        sev = f.get("severity", "INFO")
        worst = _max_sev(worst, sev)
        n_crit += sev == "CRITICAL"
        n_high += sev == "HIGH"
    grade = {"INFO": "A", "LOW": "B", "MEDIUM": "C", "HIGH": "D", "CRITICAL": "F"}[worst]
    return {"grade": grade, "worst_severity": worst,
            "critical_findings": n_crit, "high_findings": n_high}
