"""SPIFFE-style workload identity for service-to-service (scanner↔API) auth.

Deterministic, no AI. The trust domain issues short-lived X.509 SVIDs
(Service Verifiable Identity Documents) where the certificate's SPIFFE URI SAN
carries the workload identity ``spiffe://<trust-domain>/<workload>``.

- ``issue_svid``     mint a short-lived leaf cert + private key for a workload,
                     signed by the domain CA.
- ``verify_peer``    validate a presented client/peer certificate against the
                     CA bundle, check it is in its validity window and that its
                     SPIFFE id matches one of the allowed workloads.

This supports mTLS at the edge; the API validates the peer cert. The CA bundle
can be generated deterministically (``generate_ca``) for the deployment.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

DEFAULT_TRUST_DOMAIN = "cryptoscan.internal"
DEFAULT_SVID_TTL_MINUTES = 60
SPIFFE_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.8.15")  # uniformResourceIdentifier SAN


class WorkloadIdentityError(ValueError):
    pass


@dataclass
class CaBundle:
    trust_domain: str
    cert_pem: str
    private_key_pem: str

    @property
    def cert(self) -> x509.Certificate:
        return x509.load_pem_x509_certificate(self.cert_pem.encode())

    @property
    def private_key(self):
        return serialization.load_pem_private_key(self.private_key_pem.encode(), password=None)


def spiffe_id(workload: str, trust_domain: str = DEFAULT_TRUST_DOMAIN) -> str:
    workload = workload.strip().strip("/")
    if not workload or any(c.isspace() for c in workload):
        raise WorkloadIdentityError("workload path is required")
    return f"spiffe://{trust_domain}/{workload}"


def generate_ca(*, trust_domain: str = DEFAULT_TRUST_DOMAIN,
                common_name: str | None = None) -> CaBundle:
    """Generate a deterministic-enough self-signed domain CA (ECDSA P-256)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name or f"{trust_domain} CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoScan Workload CA"),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                          content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return CaBundle(
        trust_domain=trust_domain,
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        private_key_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def issue_svid(
    ca: CaBundle,
    workload: str,
    *,
    ttl_minutes: int = DEFAULT_SVID_TTL_MINUTES,
    now: dt.datetime | None = None,
) -> dict[str, str]:
    """Mint a leaf SVID cert + key for ``workload``, signed by the CA."""
    sid = spiffe_id(workload, ca.trust_domain)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ref = now or dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sid)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ref - dt.timedelta(minutes=1))
        .not_valid_after(ref + dt.timedelta(minutes=ttl_minutes))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(sid)]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False,
                          key_encipherment=False, data_encipherment=False,
                          key_agreement=False, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        .sign(ca.private_key, hashes.SHA256())
    )
    return {
        "spiffe_id": sid,
        "cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "key_pem": leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        "ca_cert_pem": ca.cert_pem,
        "not_after": (ref + dt.timedelta(minutes=ttl_minutes)).isoformat(),
    }


def extract_spiffe_id(cert: x509.Certificate) -> str | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return None
    for uri in ext.value.get_values_for_type(x509.UniformResourceIdentifier):
        if uri.startswith("spiffe://"):
            return uri
    return None


def verify_peer(
    peer_cert_pem: str,
    ca: CaBundle,
    *,
    allowed_workloads: Iterable[str] | None = None,
    now: dt.datetime | None = None,
) -> dict:
    """Verify a peer SVID: chain to CA, validity window, SPIFFE id/allowlist.

    Returns {"spiffe_id": ..., "workload": ...} on success; raises
    WorkloadIdentityError on any failure (fail-closed).
    """
    ref = now or dt.datetime.now(dt.timezone.utc)
    try:
        peer = x509.load_pem_x509_certificate(peer_cert_pem.encode())
    except ValueError as exc:
        raise WorkloadIdentityError("peer certificate is not valid PEM/X.509") from exc

    # chain + signature: peer must be signed by the CA key
    ca_pub = ca.cert.public_key()
    try:
        if isinstance(ca_pub, ec.EllipticCurvePublicKey):
            ca_pub.verify(
                peer.signature,
                peer.tbs_certificate_bytes,
                ec.ECDSA(peer.signature_hash_algorithm),
            )
        elif isinstance(ca_pub, rsa.RSAPublicKey):
            from cryptography.hazmat.primitives.asymmetric import padding

            ca_pub.verify(
                peer.signature, peer.tbs_certificate_bytes,
                padding.PKCS1v15(), peer.signature_hash_algorithm,
            )
        else:
            raise WorkloadIdentityError("unsupported CA key type")
    except Exception as exc:  # noqa: BLE001
        raise WorkloadIdentityError("SVID is not signed by the trusted CA") from exc

    if peer.not_valid_before_utc > ref or peer.not_valid_after_utc <= ref:
        raise WorkloadIdentityError("SVID is outside its validity window (expired/not yet valid)")

    sid = extract_spiffe_id(peer)
    if not sid:
        raise WorkloadIdentityError("peer certificate carries no SPIFFE id")
    prefix = f"spiffe://{ca.trust_domain}/"
    if not sid.startswith(prefix):
        raise WorkloadIdentityError(f"SPIFFE id {sid} is not in trust domain {ca.trust_domain}")
    workload = sid[len(prefix):]

    if allowed_workloads is not None:
        allowed = {spiffe_id(w, ca.trust_domain) for w in allowed_workloads}
        if sid not in allowed:
            raise WorkloadIdentityError(
                f"workload {workload!r} is not in the allowlist {sorted(allowed)}")
    return {"spiffe_id": sid, "workload": workload}
