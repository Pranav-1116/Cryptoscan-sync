"""Certificates as CBOM entries — shared by the network plane (served certificates)
and the crypto plane (certificates on disk)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cryptava.collectors import Context
from cryptava.util import slug
from cryptava.x509 import CertificateError, parse_der

WEAK_SIGNATURES = {"md5WithRSAEncryption", "sha1WithRSAEncryption", "ecdsa-with-SHA1", "dsa-with-sha1"}


def _signature_label(name: str) -> str:
    mapping = {
        "sha256WithRSAEncryption": "SHA256withRSA", "sha384WithRSAEncryption": "SHA384withRSA",
        "sha512WithRSAEncryption": "SHA512withRSA", "sha1WithRSAEncryption": "SHA1withRSA",
        "md5WithRSAEncryption": "MD5withRSA", "sha224WithRSAEncryption": "SHA224withRSA",
        "ecdsa-with-SHA256": "SHA256withECDSA", "ecdsa-with-SHA384": "SHA384withECDSA",
        "ecdsa-with-SHA512": "SHA512withECDSA", "ecdsa-with-SHA1": "SHA1withECDSA",
        "dsa-with-sha1": "SHA1withDSA", "dsa-with-sha256": "SHA256withDSA",
    }
    return mapping.get(name, name)


def register(ctx: Context, der: bytes, *, layer: str, source: str, where: str,
             evidence_type: str = "CERTIFICATE_OBSERVED") -> tuple[str, str, dict[str, Any]] | None:
    """Declare (or re-observe) one certificate. Returns ``(ref, evidence_label, facts)``."""
    try:
        cert = parse_der(der)
    except CertificateError:
        return None
    obs = ctx.obs
    fingerprint = cert["fingerprint_sha256"]
    ref = ctx.certificates.get(fingerprint)
    label = cert.get("subject_cn") or cert.get("subject") or fingerprint[:16]
    if ref is None:
        ref = obs.asset(f"cert:{fingerprint[:24]}", "CERTIFICATE", label,
                        identity={"fingerprint_sha256": fingerprint},
                        attributes={k: cert[k] for k in ("subject", "issuer", "serial_number", "not_before",
                                                          "not_after", "public_key_algorithm", "public_key_bits",
                                                          "curve", "signature_algorithm", "san", "is_ca",
                                                          "self_signed")},
                        source=source)
        ctx.certificates[fingerprint] = ref
    try:
        expires = datetime.fromisoformat(cert["not_after"])
        expired = expires < datetime.now(timezone.utc)
    except ValueError:
        expired = None
    key_facts = {
        "algorithm": cert["public_key_algorithm"],
        "key_size": cert["public_key_bits"],
        "curve": cert["curve"],
        "role": "certificate-public-key",
        "subject": cert["subject"],
        "issuer": cert["issuer"],
        "serial_number": cert["serial_number"],
        "not_before": cert["not_before"],
        "not_after": cert["not_after"],
        "expired": expired,
        "self_signed": cert["self_signed"],
        "is_ca": cert["is_ca"],
        "observed_at_location": where,
        "host": ctx.fqdn,
    }
    ev = obs.observe(ref, evidence_type, key_facts, layer=layer, source=source)
    obs.observe(ref, evidence_type, {
        "algorithm": _signature_label(cert["signature_algorithm"]),
        "role": "certificate-signature",
        "weak_signature": cert["signature_algorithm"] in WEAK_SIGNATURES,
        "observed_at_location": where,
        "host": ctx.fqdn,
    }, layer=layer, source=source)

    # issuer: a CA node (identity = issuer DN) and, if it names an organisation, a vendor
    if not cert["self_signed"] and cert.get("issuer"):
        ca_ref = ctx.cas.get(cert["issuer"])
        if ca_ref is None:
            ca_ref = obs.asset(f"ca:{slug(cert['issuer'], limit=80)}", "CA",
                               cert.get("issuer_cn") or cert["issuer"],
                               identity={"subject": cert["issuer"]},
                               attributes={"organisation": cert.get("issuer_o")}, source=source)
            ctx.cas[cert["issuer"]] = ca_ref
        ca_ev = obs.observe(ca_ref, "CERTIFICATE_OBSERVED", {
            "issued_certificate": fingerprint, "issuer": cert["issuer"], "host": ctx.fqdn,
        }, layer=layer, source=source)
        obs.relate(ref, "issued_by", ca_ref, basis="RUNTIME_OBSERVATION" if "handshake" in source else "CONFIGURATION",
                   evidence=[ev, ca_ev])
        if cert.get("issuer_o"):
            ctx.vendor_links.append((ca_ref, cert["issuer_o"], "certificate authority", None, "certificate issuer O="))
    elif cert["self_signed"] and cert.get("subject_o"):
        ctx.vendor_links.append((ref, cert["subject_o"], "self-signed certificate", None, "certificate subject O="))
    return ref, ev, cert
