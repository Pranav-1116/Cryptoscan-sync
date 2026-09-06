"""Active TLS/cipher enumeration (SSLyze-style) engine.

Performs real outbound TLS handshakes against a host:port and deterministically
audits:
- protocol support (TLS 1.0/1.1 downgrade acceptance vs 1.2/1.3)
- negotiated / accepted cipher suites (weak/disallowed suites)
- certificate chain (leaf → intermediates), signature/key strength
- certificate expiry and hostname (SAN) mismatch

All network work is isolated in ``_handshake``; the classification is pure
(see cipher_policy). Fail-closed: a connect/handshake failure is reported, not
silently treated as "secure". No AI.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
from dataclasses import asdict, dataclass, field
from typing import Any

from keyassure.cipher_policy import classify_cipher, classify_protocol, overall_grade

# Protocol versions we explicitly probe. OpenSSL 3 may not be able to
# negotiate 1.0/1.1 at all — we report that as LOCAL_UNSUPPORTED, not "secure".
_PROBE_VERSIONS = [
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1_0", None)),
]


class TlsAuditError(ValueError):
    pass


@dataclass
class ProtocolResult:
    version: str
    status: str            # NEGOTIATED / REFUSED / LOCAL_UNSUPPORTED / ERROR
    cipher: str | None = None
    severity: str = "INFO"
    reason: str = ""


@dataclass
class CertResult:
    subject: str | None = None
    issuer: str | None = None
    serial: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    san: list[str] = field(default_factory=list)
    key_type: str | None = None
    key_bits: int | None = None
    sig_algorithm: str | None = None
    sha256_fingerprint: str | None = None
    chain_length: int = 0
    issues: list[dict] = field(default_factory=list)


def _handshake(host: str, port: int, *, sni: str | None, timeout: float,
               min_ver=None, max_ver=None, ciphers: str | None = None):
    """Open one TLS connection; return (ssl_sock, version, cipher, peer_chain)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if min_ver is not None:
        ctx.minimum_version = min_ver
    if max_ver is not None:
        ctx.maximum_version = max_ver
    if ciphers:
        ctx.set_ciphers(ciphers)
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        tls = ctx.wrap_socket(raw, server_hostname=sni or host)
        try:
            chain = tls.get_unverified_chain()  # OpenSSL 1.7+ / py3.13
        except Exception:
            chain = None
        der_leaf = tls.getpeercert(binary_form=True)
        version = tls.version()
        cipher = tls.cipher()[0] if tls.cipher() else None
        return tls, version, cipher, (chain, der_leaf)
    except Exception:
        raw.close()
        raise


def _probe_protocols(host: str, port: int, sni: str | None, timeout: float) -> list[ProtocolResult]:
    results: list[ProtocolResult] = []
    for label, ver in _PROBE_VERSIONS:
        if ver is None:
            results.append(ProtocolResult(label, "LOCAL_UNSUPPORTED",
                                          reason="scanner OpenSSL cannot offer this version"))
            continue
        try:
            _tls, negotiated, cipher, _ = _handshake(
                host, port, sni=sni, timeout=timeout, min_ver=ver, max_ver=ver)
            pol = classify_protocol(negotiated)
            results.append(ProtocolResult(
                version=negotiated or label, status="NEGOTIATED", cipher=cipher,
                severity=pol["severity"], reason=pol["reason"]))
            try:
                _tls.close()
            except Exception:
                pass
        except (ssl.SSLError, OSError) as exc:
            text = str(exc).lower()
            if "unsupported" in text and "protocol" in text:
                results.append(ProtocolResult(label, "REFUSED",
                                              reason="server refused this protocol version"))
            elif "no protocols" in text or "unsupported" in text:
                results.append(ProtocolResult(label, "LOCAL_UNSUPPORTED",
                                              reason="scanner cannot offer this version"))
            else:
                results.append(ProtocolResult(label, "REFUSED", reason=str(exc)[:160]))
    return results


def _analyze_chain(chain, der_leaf, hostname: str, now: dt.datetime) -> CertResult:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID, ExtensionOID

    res = CertResult()
    certs: list[x509.Certificate] = []
    if chain:
        for c in chain:
            try:
                certs.append(x509.load_der_x509_certificate(c.public_bytes()))
            except Exception:
                pass
    if not certs and der_leaf:
        try:
            certs.append(x509.load_der_x509_certificate(der_leaf))
        except Exception:
            pass
    if not certs:
        return res
    res.chain_length = len(certs)
    leaf = certs[0]

    def _dn(name):
        try:
            return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            try:
                return name.rfc4514_string()
            except Exception:
                return None

    res.subject = _dn(leaf.subject)
    res.issuer = _dn(leaf.issuer)
    try:
        res.serial = format(leaf.serial_number, "x")
    except Exception:
        res.serial = None
    res.not_before = leaf.not_valid_before_utc.isoformat()
    res.not_after = leaf.not_valid_after_utc.isoformat()
    res.days_until_expiry = (leaf.not_valid_after_utc - now).days

    try:
        san_ext = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        res.san = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        res.san = []

    pk = leaf.public_key()
    res.key_type = type(pk).__name__.replace("PublicKey", "").replace("EllipticCurve", "EC")
    try:
        res.key_bits = pk.key_size
    except Exception:
        res.key_bits = None
    try:
        res.sig_algorithm = leaf.signature_hash_algorithm.name + "/" + (
            leaf.signature_algorithm_oid._name or "sig")
    except Exception:
        res.sig_algorithm = None
    res.sha256_fingerprint = leaf.fingerprint(hashes.SHA256()).hex()

    # ---- deterministic issues ----
    if res.days_until_expiry is not None and res.days_until_expiry < 0:
        res.issues.append({"severity": "CRITICAL", "code": "CERT_EXPIRED",
                           "detail": f"certificate expired {-res.days_until_expiry} days ago"})
    elif res.days_until_expiry is not None and res.days_until_expiry <= 30:
        res.issues.append({"severity": "HIGH", "code": "CERT_EXPIRING",
                           "detail": f"certificate expires in {res.days_until_expiry} days"})

    # key strength
    kt = (res.key_type or "").upper()
    if "RSA" in kt and (res.key_bits or 0) < 2048:
        res.issues.append({"severity": "CRITICAL", "code": "WEAK_KEY",
                           "detail": f"RSA {res.key_bits}-bit < 2048"})
    if "EC" in kt and (res.key_bits or 0) < 224:
        res.issues.append({"severity": "HIGH", "code": "WEAK_KEY",
                           "detail": f"EC {res.key_bits}-bit curve is weak"})
    if res.sig_algorithm and ("md5" in res.sig_algorithm.lower() or "sha1" in res.sig_algorithm.lower()):
        res.issues.append({"severity": "HIGH", "code": "WEAK_SIGNATURE",
                           "detail": f"signature uses {res.sig_algorithm}"})

    # hostname / SAN mismatch
    if hostname:
        names = list(res.san) + ([res.subject] if res.subject else [])
        if not any(_hostname_matches(hostname, n) for n in names):
            res.issues.append({"severity": "HIGH", "code": "SAN_MISMATCH",
                               "detail": f"hostname {hostname!r} not in SAN/CN {names[:6]}"})
    # self-signed leaf presented on a public name
    if len(certs) == 1 and leaf.issuer == leaf.subject:
        res.issues.append({"severity": "MEDIUM", "code": "SELF_SIGNED",
                           "detail": "leaf is self-signed (no chain to a CA)"})
    return res


def _hostname_matches(hostname: str, pattern: str | None) -> bool:
    if not pattern:
        return False
    h = hostname.strip(".").lower()
    p = pattern.strip(".").lower()
    if h == p:
        return True
    if p.startswith("*."):
        base = p[2:]
        # wildcard matches exactly one left-most label
        return h.endswith("." + base) and h.count(".") == base.count(".") + 1
    return False


def _probe_weak_ciphers(host: str, port: int, sni: str | None, timeout: float) -> list[dict]:
    """Reuse a small fixed candidate set and report acceptance honestly."""
    candidates = [
        ("RC4-SHA", "CRITICAL"), ("DES-CBC3-SHA", "HIGH"), ("NULL-SHA256", "CRITICAL"),
        ("AES128-SHA", "MEDIUM"), ("ECDHE-RSA-AES256-GCM-SHA384", "INFO"),
    ]
    out = []
    for name, sev in candidates:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers(name)
        except ssl.SSLError:
            out.append({"cipher": name, "status": "LOCAL_UNSUPPORTED", "severity": sev})
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni or host):
                    verdict = classify_cipher(name, protocol="TLSv1.2")
                    out.append({"cipher": name, "status": "ACCEPTED",
                                "severity": sev if sev in ("CRITICAL", "HIGH") else verdict.severity,
                                "forward_secrecy": verdict.forward_secrecy,
                                "aead": verdict.aead})
        except ssl.SSLError:
            out.append({"cipher": name, "status": "REFUSED", "severity": sev})
        except OSError:
            out.append({"cipher": name, "status": "ERROR", "severity": sev})
    return out


def audit_tls_endpoint(host: str, port: int = 443, *, sni: str | None = None,
                       timeout: float = 6.0, now: dt.datetime | None = None) -> dict[str, Any]:
    """Run a full active TLS audit. Returns a deterministic result dict."""
    reference = now or dt.datetime.now(dt.timezone.utc)
    if not host:
        raise TlsAuditError("host is required")
    try:
        socket.getaddrinfo(host, port)
    except OSError as exc:
        raise TlsAuditError(f"cannot resolve/connect {host}:{port}: {exc}") from exc

    protocols = _probe_protocols(host, port, sni or host, timeout)
    cipher_findings = _probe_weak_ciphers(host, port, sni or host, timeout)

    # Certificate chain from a default (best) handshake.
    cert_result = CertResult()
    best_error = None
    try:
        _tls, _ver, _ciph, (chain, der) = _handshake(host, port, sni=sni or host, timeout=timeout)
        cert_result = _analyze_chain(chain, der, sni or host, reference)
        try:
            _tls.close()
        except Exception:
            pass
    except (ssl.SSLError, OSError) as exc:
        best_error = str(exc)[:200]

    findings: list[dict] = []
    for p in protocols:
        if p.status == "NEGOTIATED" and p.severity in ("HIGH", "CRITICAL"):
            findings.append({"kind": "protocol", "code": f"DEPRECATED_{p.version}",
                             "severity": p.severity, "detail": p.reason})
    for c in cipher_findings:
        if c["status"] == "ACCEPTED" and c["severity"] in ("HIGH", "CRITICAL", "MEDIUM"):
            findings.append({"kind": "cipher", "code": f"WEAK_CIPHER_{c['cipher']}",
                             "severity": c["severity"], "detail": f"server negotiates {c['cipher']}"})
    for issue in cert_result.issues:
        findings.append({"kind": "certificate", **issue})

    grade = overall_grade(findings)
    return {
        "target": {"host": host, "port": port, "sni": sni or host},
        "reachable": best_error is None or bool(cert_result.subject),
        "handshake_error": best_error,
        "protocols": [asdict(p) for p in protocols],
        "cipher_probes": cipher_findings,
        "certificate": asdict(cert_result),
        "findings": findings,
        "grade": grade["grade"],
        "worst_severity": grade["worst_severity"],
        "summary": {
            "supports_tls13": any(p.version == "TLSv1.3" and p.status == "NEGOTIATED" for p in protocols),
            "supports_tls12": any(p.version == "TLSv1.2" and p.status == "NEGOTIATED" for p in protocols),
            "downgrade_accepted": any(p.status == "NEGOTIATED" and p.version in ("TLSv1.0", "TLSv1.1") for p in protocols),
            "weak_cipher_accepted": any(c["status"] == "ACCEPTED" and c["severity"] in ("CRITICAL", "HIGH") for c in cipher_findings),
        },
    }
