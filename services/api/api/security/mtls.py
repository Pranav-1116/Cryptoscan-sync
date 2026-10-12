"""mTLS serving-context construction (advanced/82, round 38).

The enforcement half of mutual TLS at the app boundary: build the
server ``SSLContext`` that REQUIRES client certificates —
``verify_mode = CERT_REQUIRED`` with the site CA as the trust anchor —
and hand it to uvicorn. Deployment still owns the certificates; this
module owns the policy: the context it returns cannot be built without
a valid certificate pair and a trust bundle, and it refuses weaker
client verification modes (optional/none) by construction.

Used by ``scripts/serve_mtls.py`` (``uvicorn api.main:app --ssl via
this builder``) and pinned by tests that perform a REAL TLS handshake:
a client without a certificate is rejected by the kernel TLS layer, a
client with a site-CA-signed certificate is accepted.
"""

from __future__ import annotations

import ssl
from pathlib import Path


class MtlsError(Exception):
    """mTLS context construction failed — never serve without it."""


def build_mtls_context(
    cert_file: str,
    key_file: str,
    ca_bundle: str,
    *,
    min_version: str = "1.2",
) -> ssl.SSLContext:
    """One server context enforcing client certificates.

    Raises :class:`MtlsError` with an operator-readable reason when the
    material is missing or unloadable — a deployment must not come up
    serving plaintext or optional-verification TLS by accident.
    """
    for name, path in (("TLS_CERT_FILE", cert_file),
                       ("TLS_KEY_FILE", key_file),
                       ("TLS_CA_BUNDLE", ca_bundle)):
        if not (path or "").strip():
            raise MtlsError(f"{name} is required for mTLS serving")
        if not Path(path).is_file():
            raise MtlsError(f"{name} does not exist: {path}")

    floors = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}
    floor = floors.get(str(min_version or "1.2").strip())
    if floor is None:
        raise MtlsError(f"unsupported TLS_MIN_VERSION {min_version!r} "
                        "(use 1.2 or 1.3)")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(cert_file, key_file)
    except ssl.SSLError as exc:
        raise MtlsError(f"certificate/key pair rejected: {exc}") from exc
    try:
        context.load_verify_locations(ca_bundle)
    except ssl.SSLError as exc:
        raise MtlsError(f"trust bundle rejected: {exc}") from exc

    # the policy, by construction:
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = floor
    context.options |= ssl.OP_NO_COMPRESSION  # CRIME-style leaks
    return context


def client_context(cert_file: str = "", key_file: str = "",
                   ca_bundle: str = "") -> ssl.SSLContext:
    """A matching CLIENT context for tests and internal callers.

    Verifies the server against the same site CA; sends a client
    certificate when given one.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    if (ca_bundle or "").strip():
        context.load_verify_locations(ca_bundle)
    else:  # test convenience only — production callers pass the bundle
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if cert_file and key_file:
        context.load_cert_chain(cert_file, key_file)
    return context
