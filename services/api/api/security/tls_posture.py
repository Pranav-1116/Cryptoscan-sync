"""Serving-TLS posture inspection (deployment set, round 36).

The mTLS/Vault/TDE items are infrastructure decisions — but the part
that can be *verified in code* is whether the deployment's TLS
configuration is coherent *before* it takes traffic: the certificate
parses, the private key matches it, it is not expired or about to be,
the key is not weak, and the trust bundle is a real certificate
collection. An unconfigured app boundary is reported honestly as such
(termination at a reverse proxy is a legitimate deployment shape we
cannot see from inside the process).

Production boot rule: when TLS is configured at the app boundary it
must be VALID at boot — a deployment with a broken or expired serving
certificate fails fast instead of serving.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: expiry buckets (days)
WARN_DAYS = 30
NOTICE_DAYS = 90


def _check(checks: list[dict[str, str]], name: str, status: str, detail: str) -> None:
    checks.append({"check": name, "status": status, "detail": detail})


def _days_left(not_after: datetime, now: datetime) -> int:
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    return int((not_after - now).total_seconds() // 86400)


def inspect_tls_posture(
    cert_file: str = "",
    key_file: str = "",
    ca_bundle: str = "",
    *,
    min_version: str = "1.2",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Inspect the configured serving-TLS material. Pure; raises nothing."""
    now = now or datetime.now(timezone.utc)
    checks: list[dict[str, str]] = []
    cert_summary: dict[str, Any] | None = None

    cert_path = Path(cert_file) if (cert_file or "").strip() else None
    key_path = Path(key_file) if (key_file or "").strip() else None

    if cert_path is None and key_path is None:
        _check(checks, "app-boundary TLS", "INFO",
               "no serving certificate configured at the app boundary — "
               "termination at a reverse proxy / load balancer is a "
               "deployment decision this surface cannot see")
        return {
            "model": "tls-posture/inspection-v1",
            "configured": False,
            "checks": checks,
            "certificate": None,
            "min_tls_version": min_version,
            "status": "UNCONFIGURED",
            "note": "mTLS client-certificate enforcement and TDE remain "
                    "deployment-scoped; this inspection covers the serving "
                    "certificate and trust bundle only",
        }

    if cert_path is None or key_path is None:
        _check(checks, "cert/key pairing", "FAIL",
               "TLS_CERT_FILE and TLS_KEY_FILE must be configured together")
        return {
            "model": "tls-posture/inspection-v1", "configured": True,
            "checks": checks, "certificate": None,
            "min_tls_version": min_version, "status": "FAIL",
            "note": "incomplete TLS configuration",
        }

    certificate = None
    try:
        from cryptography import x509

        cert_bytes = cert_path.read_bytes()
        certificate = x509.load_pem_x509_certificate(cert_bytes)
        cert_summary = {
            "subject": certificate.subject.rfc4514_string(),
            "issuer": certificate.issuer.rfc4514_string(),
            "not_before": certificate.not_valid_before_utc.isoformat(),
            "not_after": certificate.not_valid_after_utc.isoformat(),
            "serial": format(certificate.serial_number, "x"),
        }
        _check(checks, "certificate parses", "PASS",
               f"{cert_path} is a valid X.509 certificate")
    except FileNotFoundError:
        _check(checks, "certificate readable", "FAIL",
               f"certificate file not found: {cert_path}")
    except Exception as exc:
        _check(checks, "certificate parses", "FAIL",
               f"{cert_path} is not a parseable PEM certificate: "
               f"{type(exc).__name__}")

    # expiry + key material only when the certificate parsed
    if certificate is not None:
        days = _days_left(certificate.not_valid_after_utc, now)
        cert_summary["days_until_expiry"] = days
        if days < 0:
            _check(checks, "expiry", "FAIL",
                   f"certificate EXPIRED {-days} days ago")
        elif days <= WARN_DAYS:
            _check(checks, "expiry", "WARN",
                   f"certificate expires in {days} days")
        else:
            _check(checks, "expiry", "PASS",
                   f"certificate valid for {days} days")

        try:
            public = certificate.public_key()
            size = getattr(public, "key_size", 0)
            cert_summary["public_key"] = {
                "type": type(public).__name__.replace("_", " "),
                "size": size,
            }
            weak = (size and (
                ("RSA" in type(public).__name__ and size < 2048)
                or ("EllipticCurve" in type(public).__name__ and size < 256)
            ))
            _check(checks, "key strength", "WARN" if weak else "PASS",
                   f"{type(public).__name__} {size} bits"
                   + (" — below the floor for new deployments" if weak else ""))
        except Exception as exc:  # pragma: no cover - parser-dependent
            _check(checks, "key strength", "INFO",
                   f"public key not inspectable: {type(exc).__name__}")

        sig = certificate.signature_algorithm_oid._name
        if sig.lower() in ("sha1_with_rsa_encryption", "md5_with_rsa_encryption"):
            _check(checks, "signature algorithm", "FAIL",
                   f"broken signature algorithm: {sig}")
        else:
            _check(checks, "signature algorithm", "PASS", sig)

        try:
            from cryptography.x509.oid import ExtensionOID

            sans = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            cert_summary["subject_alternative_names"] = [
                s.value for s in sans]
        except Exception:
            cert_summary["subject_alternative_names"] = []
        if certificate.issuer == certificate.subject:
            _check(checks, "self-signed", "WARN",
                   "certificate is self-signed — fine for internal mTLS "
                   "bootstrap, must come from the site CA for serving")

    # private key: exists, parses, matches the certificate
    try:
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_private_key(key_path.read_bytes(),
                                                 password=None)
        if certificate is not None:
            cert_public = certificate.public_key().public_numbers()
            key_public = key.public_key().public_numbers()
            _check(checks, "cert/key pairing", "PASS" if cert_public == key_public else "FAIL",
                   "private key matches the serving certificate"
                   if cert_public == key_public else
                   "private key does NOT match the serving certificate")
    except FileNotFoundError:
        _check(checks, "private key readable", "FAIL",
               f"private key file not found: {key_path}")
    except Exception as exc:
        _check(checks, "private key parses", "FAIL",
               f"{key_path} is not a parseable unencrypted PEM key: "
               f"{type(exc).__name__}")

    # trust bundle
    if (ca_bundle or "").strip():
        try:
            from cryptography.x509 import load_pem_x509_certificates

            certs = load_pem_x509_certificates(Path(ca_bundle).read_bytes())
            _check(checks, "trust bundle", "PASS",
                   f"{ca_bundle}: {len(certs)} certificates load")
        except FileNotFoundError:
            _check(checks, "trust bundle", "FAIL",
                   f"trust bundle not found: {ca_bundle}")
        except Exception as exc:
            _check(checks, "trust bundle", "FAIL",
                   f"{ca_bundle} does not contain PEM certificates: "
                   f"{type(exc).__name__}")
    else:
        _check(checks, "trust bundle", "INFO",
               "no TLS_CA_BUNDLE configured — outbound verification uses "
               "the system store (a deployment choice)")

    statuses = [c["status"] for c in checks]
    overall = ("FAIL" if "FAIL" in statuses
               else "WARN" if "WARN" in statuses else "PASS")
    return {
        "model": "tls-posture/inspection-v1",
        "configured": True,
        "checks": checks,
        "certificate": cert_summary,
        "min_tls_version": min_version,
        "status": overall,
        "note": "mTLS client-certificate enforcement and TDE remain "
                "deployment-scoped; this inspection covers the serving "
                "certificate and trust bundle only",
    }


def production_tls_gate(posture: dict[str, Any] | None = None) -> str | None:
    """Boot-time rule: configured TLS must be valid in production.

    Returns an error message when the deployment must not come up, None
    when fine (including legitimately-unconfigured — a reverse proxy
    may terminate TLS where we cannot see it).
    """
    if posture is None:
        from api.config.settings import get_settings

        settings = get_settings()
        posture = inspect_tls_posture(settings.TLS_CERT_FILE,
                                      settings.TLS_KEY_FILE,
                                      settings.TLS_CA_BUNDLE,
                                      min_version=settings.TLS_MIN_VERSION)
    if not posture.get("configured"):
        return None
    if posture.get("status") == "FAIL":
        failures = "; ".join(c["detail"] for c in posture.get("checks", [])
                             if c["status"] == "FAIL")
        return ("TLS_CERT_FILE/TLS_KEY_FILE are configured but invalid — "
                "refusing to start with broken serving TLS: " + failures)
    return None
