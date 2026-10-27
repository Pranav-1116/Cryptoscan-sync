"""§13/§14/§15 Certificate intelligence, key metadata, trust store analysis.

Certificate discovery sources: filesystem, TLS endpoints, trust stores, Java
keystores, Windows stores, Linux stores, containers, Kubernetes secrets
*metadata*, load balancers, firewalls, HSM-backed services, cloud
certificate services. Analysis covers subject/issuer/validity/public-key
algorithm/key size/signature algorithm/chain/usage/SAN/EKU/trust.

**Never collect private keys.** ``analyze_certificate`` accepts only
certificates; ``analyze_key_metadata`` accepts metadata dicts and rejects
any payload containing secret material fields.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from cryptography import x509  # noqa: F401  (module-wide: SAN formatting)

#: fields that would make a key record secret material (§14 — never stored)
_SECRET_FIELDS = frozenset({
    "private_key", "private", "secret", "password", "passphrase", "seed",
    "d", "p", "q", "dp", "dq", "qinv", "k", "r", "s", "key_material",
    "secret_material", "pin", "wrapped_key",
})

#: signature algorithm -> (algorithm, hash)
_SIG_ALGORITHMS = {
    "sha256WithRSAEncryption": ("RSA-PSS", "SHA-256"),
    "sha384WithRSAEncryption": ("RSA-PSS", "SHA-384"),
    "sha512WithRSAEncryption": ("RSA-PSS", "SHA-512"),
    "sha1WithRSAEncryption": ("RSA", "SHA-1"),
    "md5WithRSAEncryption": ("RSA", "MD5"),
    "ecdsa-with-SHA256": ("ECDSA", "SHA-256"),
    "ecdsa-with-SHA384": ("ECDSA", "SHA-384"),
    "ecdsa-with-SHA512": ("ECDSA", "SHA-512"),
    "ecdsa-with-SHA1": ("ECDSA", "SHA-1"),
    "ed25519": ("Ed25519", ""),
    "ed448": ("Ed448", ""),
    "dsaWithSHA1": ("DSA", "SHA-1"),
    "dsa_with_SHA256": ("DSA", "SHA-256"),
}

#: curve name normalization
_CURVES = {
    "secp256r1": "P-256", "prime256v1": "P-256", "P-256": "P-256",
    "secp384r1": "P-384", "P-384": "P-384", "secp521r1": "P-521", "P-521": "P-521",
    "secp256k1": "secp256k1", "X25519": "X25519", "Ed25519": "Ed25519",
    "Curve25519": "Curve25519", "X448": "X448", "Ed448": "Ed448",
    "brainpoolP256r1": "BrainpoolP256r1", "brainpoolP384r1": "BrainpoolP384r1",
}


class CertificateIntelligence:
    """§13 certificate + §14 key metadata + §15 trust store analysis."""

    # -- §13 ---------------------------------------------------------------

    def analyze_certificate(
        self,
        *,
        der: bytes,
        location: str = "",
        asset_id: str = "default",
        trust_anchor: bool = False,
    ) -> dict[str, Any]:
        """Deep certificate analysis (cryptography.x509)."""
        cert = x509.load_der_x509_certificate(der)
        now = datetime.now(timezone.utc)
        public_key = cert.public_key()
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa, dsa
        key_algorithm = "UNKNOWN"
        key_size = None
        curve = None
        if isinstance(public_key, rsa.RSAPublicKey):
            key_algorithm, key_size = "RSA", public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_algorithm, key_size = "ECDSA", public_key.curve.key_size
            curve = _CURVES.get(public_key.curve.name, public_key.curve.name)
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            key_algorithm, key_size = "Ed25519", 256
        elif isinstance(public_key, ed448.Ed448PublicKey):
            key_algorithm, key_size = "Ed448", 448
        elif isinstance(public_key, dsa.DSAPublicKey):
            key_algorithm, key_size = "DSA", public_key.key_size
        sig_alg = _SIG_ALGORITHMS.get(cert.signature_algorithm_oid._name, "UNKNOWN")
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            san_entries = [_format_san(entry) for entry in san]
        except Exception:
            san_entries = []
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            eku_entries = [str(usage) for usage in eku]
        except Exception:
            eku_entries = []
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        usage = {"digital_signature": None, "key_encipherment": None,
                 "key_agreement": None}
        if _has_extension(cert, x509.KeyUsage):
            key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            usage = {
                "digital_signature": key_usage.digital_signature,
                "key_encipherment": key_usage.key_encipherment,
                "key_agreement": key_usage.key_agreement,
            }
        return {
            "location": location,
            "asset_id": asset_id,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial": cert.serial_number,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "expired": not_after < now,
            "not_yet_valid": not_before > now,
            "days_remaining": max(0, (not_after - now).days),
            "public_key_algorithm": key_algorithm,
            "key_size": key_size,
            "curve": curve,
            "signature_algorithm": sig_alg[0] if sig_alg != "UNKNOWN" else "UNKNOWN",
            "signature_hash": sig_alg[1] if sig_alg != "UNKNOWN" else "",
            "is_ca": bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
                     if _has_extension(cert, x509.BasicConstraints) else False,
            "san": san_entries,
            "eku": eku_entries,
            "trust_anchor": trust_anchor,
            "self_signed": cert.subject == cert.issuer,
            "usage": usage,
        }

    def analyze_pem(self, pem: bytes, **kwargs: Any) -> dict[str, Any]:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(pem)
        return self.analyze_certificate(der=cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER), **kwargs)

    def discover_sources(self, sources: dict[str, Any]) -> list[dict[str, Any]]:
        """§13 discovery from every certificate source type (metadata in)."""
        out: list[dict[str, Any]] = []
        for source, items in (sources or {}).items():
            if source not in ("filesystem", "tls_endpoints", "trust_stores",
                              "java_keystores", "windows_stores", "linux_stores",
                              "containers", "kubernetes_secrets", "load_balancers",
                              "firewalls", "hsm_backed", "cloud_certificates"):
                continue
            for item in items or []:
                row = dict(item)
                row["source"] = source
                out.append(row)
        return out

    # -- §14 ---------------------------------------------------------------

    def analyze_key_metadata(self, record: dict[str, Any]) -> dict[str, Any]:
        """Key *metadata* only — rejects any secret material outright."""
        present_secrets = [f for f in _SECRET_FIELDS if f in record
                           or f.lower() in {k.lower() for k in record}]
        if present_secrets:
            return {"error": "secret material rejected",
                    "fields": present_secrets[:5]}
        return {
            "key_type": record.get("key_type"),
            "algorithm": record.get("algorithm"),
            "size": record.get("size"),
            "curve": record.get("curve"),
            "usage": record.get("usage"),
            "location": record.get("location"),
            "owner": record.get("owner"),
            "lifecycle": record.get("lifecycle"),
            "certificate_relationship": record.get("certificate_relationship"),
            "hardware_backed": bool(record.get("hardware_backed", False)),
            "hsm_slot": record.get("hsm_slot"),
            "generated_at": record.get("generated_at"),
            "rotated_at": record.get("rotated_at"),
            "expires_at": record.get("expires_at"),
            "revoked_at": record.get("revoked_at"),
            "destroyed_at": record.get("destroyed_at"),
            "backed_up": bool(record.get("backed_up", False)),
        }

    # -- §15 ---------------------------------------------------------------

    def analyze_trust_store(
        self,
        *,
        store_name: str,
        anchors: Iterable[dict[str, Any]],
        expected_roots: Optional[Iterable[str]] = None,
    ) -> dict[str, Any]:
        """Trust store → CA → certificate → application → protocol mapping.

        Detects: expired CA, weak signature, deprecated algorithm, unexpected
        CA, untrusted chain, duplicate trust anchor, legacy trust dependency.
        ``expected_roots`` (subject CNs the organization intends to trust)
        enables the ``unexpected_ca`` finding.
        """
        anchors = list(anchors)
        expected = {str(r).strip() for r in (expected_roots or [])}
        findings: list[dict[str, str]] = []
        seen_subjects: dict[str, int] = {}
        for anchor in anchors:
            subject = str(anchor.get("subject") or anchor.get("common_name") or "?")
            seen_subjects[subject] = seen_subjects.get(subject, 0) + 1
            if anchor.get("expired"):
                findings.append({"store": store_name, "subject": subject,
                                 "type": "expired_ca"})
            # untrusted chain: the anchor is explicitly marked untrusted or
            # its chain failed verification
            if anchor.get("trusted") is False or str(
                    anchor.get("status") or "").upper() in ("UNTRUSTED", "UNVERIFIED"):
                findings.append({"store": store_name, "subject": subject,
                                 "type": "untrusted_chain",
                                 "detail": str(anchor.get("status") or "not trusted")})
            # unexpected CA: the org supplied its expected roots and this
            # anchor is not among them (subject or CN match)
            if expected and not any(
                    r in subject or subject.endswith(r) or r.endswith(subject)
                    for r in expected):
                findings.append({"store": store_name, "subject": subject,
                                 "type": "unexpected_ca"})
            sig = str(anchor.get("signature_algorithm") or "")
            sig_norm = sig.upper().replace("-", "").replace("_", "")
            if sig_norm.startswith("MD5"):
                findings.append({"store": store_name, "subject": subject,
                                 "type": "weak_signature", "detail": sig})
            elif sig_norm.startswith("SHA1"):
                findings.append({"store": store_name, "subject": subject,
                                 "type": "deprecated_algorithm", "detail": sig})
            key_alg = str(anchor.get("public_key_algorithm") or "")
            if key_alg == "RSA" and (anchor.get("key_size") or 0) < 2048:
                findings.append({"store": store_name, "subject": subject,
                                 "type": "weak_key", "detail": f"RSA {anchor.get('key_size')}"})
            # legacy trust dependency: applications/protocols still depend on
            # a CA that is expired or uses deprecated algorithms
            depends_on = str(anchor.get("application") or "") or str(
                anchor.get("protocol") or "")
            if depends_on and (anchor.get("expired") or sig_norm.startswith("MD5")
                               or sig_norm.startswith("SHA1")
                               or (key_alg == "RSA" and (anchor.get("key_size") or 0) < 2048)):
                findings.append({"store": store_name, "subject": subject,
                                 "type": "legacy_trust_dependency",
                                 "detail": f"{depends_on} depends on {subject}"})
        for subject, count in seen_subjects.items():
            if count > 1:
                findings.append({"store": store_name, "subject": subject,
                                 "type": "duplicate_trust_anchor", "detail": f"{count}x"})
        return {
            "store": store_name,
            "anchor_count": len(anchors),
            "findings": findings,
            "map": [{"store": store_name,
                     "ca": str(a.get("subject") or a.get("common_name") or "?"),
                     "certificate": str(a.get("certificate_id") or ""),
                     "application": str(a.get("application") or ""),
                     "protocol": str(a.get("protocol") or "")}
                    for a in anchors],
        }


def _format_san(entry: Any) -> str:
    """x509 SAN entries → deterministic 'TYPE:value' strings."""
    if isinstance(entry, x509.DNSName):
        return f"DNS:{entry.value}"
    if isinstance(entry, x509.IPAddress):
        return f"IP:{entry.value}"
    if isinstance(entry, x509.UniformResourceIdentifier):
        return f"URI:{entry.value}"
    if isinstance(entry, x509.RFC822Name):
        return f"email:{entry.value}"
    if isinstance(entry, x509.DirectoryName):
        return f"dir:{entry.value.rfc4514_string()}"
    return str(entry)


def _has_extension(cert: Any, ext_type: Any) -> bool:
    try:
        cert.extensions.get_extension_for_class(ext_type)
        return True
    except Exception:
        return False
