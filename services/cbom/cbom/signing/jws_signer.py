"""RFC 7515 JSON Web Signature (JWS) — compact serialization for CBOM signing.

The CBOM spec (logic-2 §23–24) calls for JWS signing. This module implements
the full asymmetric story the HMAC path could not:

- RS256 (RSA PKCS#1 v1.5 / SHA-256) and ES256 (ECDSA P-256 / SHA-256)
  signatures with PEM keys, plus HS256 for backward compatibility with the
  existing shared-secret deployments.
- Canonical CycloneDX payload: the BOM JSON without signature properties,
  serialized with the same canonical form the HMAC path uses, so a JWS
  produced here can be verified independently by any RFC 7515 verifier.
- The JWS is stored as the ``cryptoscan:jws`` metadata property and the
  algorithm is recorded in ``cryptoscan:signatureAlg`` (``JWS-RS256`` etc.),
  matching the HMAC path's property layout.

Keys are passed as PEM bytes/strings (private for signing, public for
verification) — loaded with ``cryptography``; no key material is ever logged
or embedded in the BOM.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import base64
import hashlib
import hmac
import json
from typing import Any, Callable

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

# Canonical JSON: compact separators, sorted keys — deterministic bytes.
def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _canonical_payload(bom: dict[str, Any]) -> bytes:
    """The exact bytes that are signed: BOM minus signature properties."""
    unsigned = dict(bom)
    metadata = dict(unsigned.get("metadata") or {})
    props = [
        item
        for item in list(metadata.get("properties") or [])
        if item.get("name") not in {"cryptoscan:jws", "cryptoscan:signature", "cryptoscan:signatureAlg"}
    ]
    if props:
        metadata["properties"] = props
        unsigned["metadata"] = metadata
    elif "metadata" in unsigned:
        unsigned["metadata"] = metadata
    return canonical_json(unsigned)


def _rs256_sign(signing_input: bytes, private_key) -> bytes:
    return private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def _rs256_verify(signing_input: bytes, signature: bytes, public_key) -> None:
    public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())


def _es256_sign(signing_input: bytes, private_key) -> bytes:
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    # JWS uses fixed 32-byte big-endian r || s (raw), not DER.
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _es256_verify(signing_input: bytes, signature: bytes, public_key) -> None:
    if len(signature) != 64:
        raise InvalidSignature("ES256 signature must be 64 bytes")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))


def _hs256_sign(signing_input: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, signing_input, hashlib.sha256).digest()


def _hs256_verify(signing_input: bytes, signature: bytes, secret: bytes) -> None:
    expected = _hs256_sign(signing_input, secret)
    if not hmac.compare_digest(expected, signature):
        raise InvalidSignature("HS256 MAC mismatch")


_SIGNERS: dict[str, tuple[Callable, Callable]] = {
    "RS256": (_rs256_sign, _rs256_verify),
    "ES256": (_es256_sign, _es256_verify),
    "HS256": (_hs256_sign, _hs256_verify),
}


def _header_alg(header_b64: str) -> str | None:
    """Read the ``alg`` claim without fully decoding (safe for bad input)."""
    try:
        header = json.loads(b64url_decode(header_b64))
        return header.get("alg") if isinstance(header, dict) else None
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None


def _load_private_key(pem: bytes | str, password: bytes | None = None):
    if not _CRYPTOGRAPHY:  # pragma: no cover
        raise RuntimeError("cryptography package is required for JWS signing")
    data = pem.encode("utf-8") if isinstance(pem, str) else pem
    return serialization.load_pem_private_key(data, password=password)


def _load_public_key(pem: bytes | str):
    if not _CRYPTOGRAPHY:  # pragma: no cover
        raise RuntimeError("cryptography package is required for JWS verification")
    data = pem.encode("utf-8") if isinstance(pem, str) else pem
    return serialization.load_pem_public_key(data)


def sign_compact(payload: bytes, key, alg: str, *, key_id: str | None = None) -> str:
    """Produce a compact JWS over ``payload`` with the given key/alg."""
    if alg not in SUPPORTED_ALGS:
        raise ValueError(f"Unsupported JWS alg {alg!r}; supported: {sorted(SUPPORTED_ALGS)}")
    header: dict[str, Any] = {"alg": alg, "typ": "JWT"}
    if key_id:
        header["kid"] = key_id
    signing_input = f"{b64url(canonical_json(header))}.{b64url(payload)}".encode("ascii")
    signer, _ = _SIGNERS[alg]
    if alg == "HS256":
        if not isinstance(key, (bytes, str)):
            raise TypeError("HS256 requires a shared secret (bytes/str)")
        signature = signer(signing_input, key.encode("utf-8") if isinstance(key, str) else key)
    else:
        private_key = _load_private_key(key) if not hasattr(key, "sign") else key
        signature = signer(signing_input, private_key)
    return signing_input.decode("ascii") + "." + b64url(signature)


def verify_compact(jws: str, key, alg: str | None = None) -> tuple[bool, str]:
    """Verify a compact JWS. Returns (ok, error-or-empty)."""
    try:
        parts = jws.split(".")
        if len(parts) != 3:
            return False, "not a compact JWS"
        header_b64, payload_b64, sig_b64 = parts
        alg = alg or _header_alg(header_b64)
        if alg not in SUPPORTED_ALGS:
            return False, f"unsupported alg {alg!r}"
        json.loads(b64url_decode(header_b64))
        _, verifier = _SIGNERS[alg]
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = b64url_decode(sig_b64)
        if alg == "HS256":
            if not isinstance(key, (bytes, str)):
                return False, "HS256 requires a shared secret"
            verifier(signing_input, signature, key.encode("utf-8") if isinstance(key, str) else key)
        else:
            public_key = _load_public_key(key) if not hasattr(key, "verify") else key
            verifier(signing_input, signature, public_key)
        return True, ""
    except InvalidSignature:
        return False, "signature does not match"
    except Exception as exc:
        return False, str(exc)


# --------------------------------------------------------------- CBOM API


def sign_cbom_jws(
    bom: dict[str, Any],
    key,
    alg: str = "RS256",
    *,
    key_id: str | None = None,
) -> dict[str, Any]:
    """Return a copy of ``bom`` carrying a compact JWS over its canonical body."""
    if alg not in SUPPORTED_ALGS:
        raise ValueError(f"Unsupported JWS alg {alg!r}")
    payload = _canonical_payload(bom)
    jws = sign_compact(payload, key, alg, key_id=key_id)
    signed = dict(bom)
    metadata = dict(signed.get("metadata") or {})
    properties = [
        item
        for item in list(metadata.get("properties") or [])
        if item.get("name") not in {"cryptoscan:jws", "cryptoscan:signature", "cryptoscan:signatureAlg"}
    ]
    properties.append({"name": "cryptoscan:jws", "value": jws})
    properties.append({"name": "cryptoscan:signatureAlg", "value": f"JWS-{alg}"})
    metadata["properties"] = properties
    signed["metadata"] = metadata
    return signed


def verify_cbom_jws(bom: dict[str, Any], key, alg: str | None = None) -> tuple[bool, str]:
    """Verify a JWS-signed BOM against a public key (or secret for HS256)."""
    props = {
        item.get("name"): item.get("value")
        for item in ((bom.get("metadata") or {}).get("properties") or [])
    }
    jws = props.get("cryptoscan:jws")
    if not jws:
        return False, "BOM carries no cryptoscan:jws property"
    declared = (props.get("cryptoscan:signatureAlg") or "JWS-HS256").removeprefix("JWS-")
    payload = _canonical_payload(bom)
    ok, err = verify_compact(jws, key, alg or declared)
    if not ok:
        return False, err
    # The signed payload must be the canonical BOM body (tamper check).
    header_b64 = jws.split(".")[0]
    try:
        json.loads(b64url_decode(header_b64))
    except Exception:
        return False, "malformed JWS header"
    payload_b64 = jws.split(".")[1]
    if b64url_decode(payload_b64) != payload:
        return False, "JWS payload does not match the BOM body"
    return True, ""
