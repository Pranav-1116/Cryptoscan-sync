"""CycloneDX-spec standard enveloped signatures (JSON Signature Format).

The JWS path (`jws_signer`) stores its signature in a
``metadata.properties`` entry — valid JWS, but not the field the
CycloneDX spec defines for enveloped signatures. CycloneDX >= 1.4
defines a top-level ``signature`` object in JSON Signature Format
(JSF, https://cyberphone.github.io/doc/security/jsf.html):

    "signature": {
      "algorithm": "ES256",
      "publicKey": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."},
      "value": "<base64url signature bytes>"
    }

JSF signing rule (single-signature form): the signed data is the JSON
serialization of the *entire document* where ``signature`` holds every
property except ``value`` — i.e. ``{...bom, "signature": {algorithm,
publicKey?, keyId?}}`` — canonicalized with sorted keys and compact
separators (JCS-compatible for the ASCII/integer data a BOM carries).
Remove ``value``, serialize, sign; verification reconstructs exactly
those bytes.

Signature encodings follow JSF: ES256 = raw IEEE P-1363 ``r || s``
(64 bytes), RS256 = PKCS#1 v1.5, HS256 = HMAC-SHA256 — the same
primitives the JWS path already uses, so both paths stay verifiable by
the same key material.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )
    _CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - dependency not installed
    _CRYPTOGRAPHY = False

SUPPORTED_ALGS = {"RS256", "ES256", "HS256"}

# property names that never take part in the signed body (legacy paths)
_SIGNATURE_PROPERTY_NAMES = {"cryptoscan:jws", "cryptoscan:signature", "cryptoscan:signatureAlg"}


def canonical_json(value: Any) -> bytes:
    """JCS-compatible canonical bytes: sorted keys, compact separators."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _strip_legacy_signature_properties(bom: dict[str, Any]) -> dict[str, Any]:
    """The signed body excludes the legacy property-style signatures so a
    document re-signed into the standard field does not drag stale JWS
    bytes into the signed set."""
    cleaned = dict(bom)
    metadata = dict(cleaned.get("metadata") or {})
    props = [
        item
        for item in list(metadata.get("properties") or [])
        if isinstance(item, dict) and item.get("name") not in _SIGNATURE_PROPERTY_NAMES
    ]
    if props:
        metadata["properties"] = props
        cleaned["metadata"] = metadata
    elif "metadata" in cleaned:
        metadata.pop("properties", None)
        cleaned["metadata"] = metadata
    return cleaned


def _jsf_signing_input(bom: dict[str, Any], signature_header: dict[str, Any]) -> bytes:
    """The exact bytes JSF signs: the document with the ``signature``
    object present but ``value`` absent."""
    body = _strip_legacy_signature_properties(bom)
    body.pop("signature", None)
    body["signature"] = {k: v for k, v in signature_header.items() if v is not None}
    return canonical_json(body)


def _public_jwk(public_key) -> dict[str, str] | None:
    """JWK for the embedded ``publicKey`` (EC/RSA). None when unavailable —
    HS256 carries ``keyId`` instead (shared secrets are never embedded)."""
    if not _CRYPTOGRAPHY:
        return None
    try:
        numbers = public_key.public_numbers()
    except Exception as exc:
        # not an EC/RSA public key (e.g. Ed25519): no JWK to embed — the
        # signer falls back to keyId-only and the verifier needs the key
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(exc).__name__},
        )
        return None
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        size = (public_key.curve.key_size + 7) // 8
        return {
            "kty": "EC",
            "crv": {256: "P-256", 384: "P-384", 521: "P-521"}.get(public_key.curve.key_size, str(public_key.curve.key_size)),
            "x": b64url(numbers.x.to_bytes(size, "big")),
            "y": b64url(numbers.y.to_bytes(size, "big")),
        }
    from cryptography.hazmat.primitives.asymmetric import rsa

    if isinstance(public_key, rsa.RSAPublicKey):
        n, e = numbers.n, numbers.e
        size = (n.bit_length() + 7) // 8
        return {
            "kty": "RSA",
            "n": b64url(n.to_bytes(size, "big")),
            "e": b64url(e.to_bytes(max(1, (e.bit_length() + 7) // 8), "big")),
        }
    return None


def _jwk_to_public_key(jwk: dict[str, Any]):
    if not _CRYPTOGRAPHY:
        return None
    kty = str(jwk.get("kty") or "").upper()
    try:
        if kty == "EC":
            curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}.get(str(jwk.get("crv")))
            if curve is None:
                return None
            x = int.from_bytes(b64url_decode(str(jwk.get("x") or "")), "big")
            y = int.from_bytes(b64url_decode(str(jwk.get("y") or "")), "big")
            return ec.EllipticCurvePublicNumbers(y=y, x=x, curve=curve).public_key()
        if kty == "RSA":
            from cryptography.hazmat.primitives.asymmetric import rsa

            n = int.from_bytes(b64url_decode(str(jwk.get("n") or "")), "big")
            e = int.from_bytes(b64url_decode(str(jwk.get("e") or "")), "big")
            return rsa.RSAPublicNumbers(e=e, n=n).public_key()
    except Exception as exc:
        logger.warning("jsf_jwk_decode_failed", extra={"error_type": type(exc).__name__})
        return None
    return None


def _sign_bytes(signing_input: bytes, key, alg: str) -> bytes:
    if alg == "HS256":
        secret = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        return hmac.new(secret, signing_input, hashlib.sha256).digest()
    if not _CRYPTOGRAPHY:  # pragma: no cover
        raise RuntimeError("cryptography package is required for JSF asymmetric signing")
    if alg == "RS256":
        return key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    if alg == "ES256":
        der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    raise ValueError(f"Unsupported JSF alg {alg!r}; supported: {sorted(SUPPORTED_ALGS)}")


def _verify_bytes(signing_input: bytes, signature: bytes, key, alg: str) -> None:
    """Raise on mismatch (InvalidSignature / ValueError)."""
    if alg == "HS256":
        secret = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            raise InvalidSignature("HS256 MAC mismatch")
        return
    if alg == "RS256":
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        return
    if alg == "ES256":
        if len(signature) != 64:
            raise InvalidSignature("ES256 signature must be 64 bytes")
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
        return
    raise ValueError(f"Unsupported JSF alg {alg!r}")


def _load_public_key(pem: bytes | str):
    if not _CRYPTOGRAPHY:  # pragma: no cover
        raise RuntimeError("cryptography package is required for JSF verification")
    if hasattr(pem, "verify"):
        return pem
    data = pem.encode("utf-8") if isinstance(pem, str) else bytes(pem)
    return serialization.load_pem_public_key(data)


def _load_private_key(pem: bytes | str):
    if not _CRYPTOGRAPHY:  # pragma: no cover
        raise RuntimeError("cryptography package is required for JSF signing")
    data = pem.encode("utf-8") if isinstance(pem, str) else pem
    return serialization.load_pem_private_key(data, password=None)


def sign_jsf(
    bom: dict[str, Any],
    key: Any,
    alg: str = "ES256",
    *,
    key_id: str | None = None,
) -> dict[str, Any]:
    """Return the BOM with the spec-standard top-level ``signature`` field.

    ``key``: PEM private key (RS256/ES256) or a shared secret string
    (HS256, which records ``keyId`` instead of an embedded public key).
    The legacy ``cryptoscan:jws`` property, when present, is excluded
    from the signed body so re-signing stays deterministic.
    """
    alg = str(alg).upper()
    if alg not in SUPPORTED_ALGS:
        raise ValueError(f"Unsupported JSF alg {alg!r}; supported: {sorted(SUPPORTED_ALGS)}")

    header: dict[str, Any] = {"algorithm": alg}
    if alg == "HS256":
        if key_id:
            header["keyId"] = str(key_id)
    else:
        private_key = _load_private_key(key)
        jwk = _public_jwk(private_key.public_key())
        if jwk is None:
            raise ValueError("JSF asymmetric signing needs an EC or RSA key")
        if key_id:
            header["keyId"] = str(key_id)
        header["publicKey"] = jwk
        signing_key = private_key
    if alg == "HS256":
        signing_key = key

    signing_input = _jsf_signing_input(bom, header)
    signature = _sign_bytes(signing_input, signing_key, alg)

    signed = _strip_legacy_signature_properties(bom)
    signed.pop("signature", None)
    signed["signature"] = dict(header)
    signed["signature"]["value"] = b64url(signature)
    return signed


def verify_jsf(bom: dict[str, Any], key: Any = None) -> tuple[bool, str | None]:
    """Verify a standard-form JSF signature.

    ``key``: trusted public key (PEM or key object) or shared secret.
    When ``key`` is None the embedded ``publicKey`` JWK is used — useful
    for integrity checks; pass an explicit key for authenticity.
    Returns (ok, error).
    """
    signature_block = bom.get("signature")
    if not isinstance(signature_block, dict) or not signature_block.get("value"):
        return False, "no standard signature field"
    alg = str(signature_block.get("algorithm") or "").upper()
    if alg not in SUPPORTED_ALGS:
        return False, f"unsupported algorithm {alg!r}"

    if key is None:
        if alg == "HS256":
            return False, "HS256 verification needs the shared secret"
        embedded = _jwk_to_public_key(signature_block.get("publicKey") or {})
        if embedded is None:
            return False, "signature carries no usable embedded publicKey"
        verify_key = embedded
    elif alg == "HS256":
        verify_key = key
    else:
        verify_key = _load_public_key(key)

    try:
        raw = b64url_decode(str(signature_block["value"]))
        signing_input = _jsf_signing_input(bom, {k: v for k, v in signature_block.items() if k != "value"})
        _verify_bytes(signing_input, raw, verify_key, alg)
        return True, None
    except InvalidSignature:
        return False, "signature mismatch"
    except Exception as exc:
        return False, f"verification failed: {type(exc).__name__}"
