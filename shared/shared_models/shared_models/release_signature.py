"""Ed25519 signatures over a document, with the trust question kept separate.

Two artefacts in this product claim to describe a deployment: the **release manifest**
(what shipped, sha256 per file) and the **air-gap bundle** (what was carried across the
network gap). Both were unsigned, and both said so. An unsigned manifest proves the files
match a list — not who wrote the list — so `verify-installation` could only ever report
`MANIFEST_UNSIGNED`, and a bundle could be edited in transit with its own hashes rewritten
to match.

This module supplies the missing half, and it is deliberately small enough to audit:

* **What is signed.** The document with its ``signature`` member removed, serialised as
  canonical JSON (sorted keys, no whitespace, UTF-8). A verifier that re-serialises
  differently will disagree, so both sides call :func:`canonical_bytes` and never
  re-implement it. ``covers`` names the exclusion in the signature block so a reader does
  not have to guess which fields were in scope.
* **What a valid signature proves.** That whoever held the private key for ``key_id``
  signed exactly these bytes. It does **not** prove the key belongs to the vendor: that is
  a trust decision, and :func:`verify_document` takes the trusted key explicitly. A
  signature that verifies against a key you were handed by the same attacker who edited the
  manifest is still worthless, and the API makes that visible rather than hiding it behind
  a boolean.
* **What is never invented.** No key, no verdict: a signed document checked without a
  trusted key reports ``SIGNED_UNVERIFIED`` — not ``VALID``. An unsigned document reports
  ``UNSIGNED`` even if a stray ``signature`` field is present but malformed.

The signature block is a plain JSON object, so both the manifest and the bundle carry the
same shape::

    {"schema": "cryptoscan.signature/1", "alg": "Ed25519", "key_id": "ed25519:…",
     "public_key": "<base64 raw 32 bytes>", "signature": "<base64 64 bytes>",
     "covers": "the document minus its `signature` member, canonical JSON"}

Private keys are handled only as PEM files on the operator's own disk, are never logged,
never written into a document and never accepted from an environment variable in this
module. Key distribution is a release-process problem and is stated as one.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "cryptoscan.signature/1"
ALGORITHM = "Ed25519"

#: reported by :func:`verify_document`; the first two are the only ones that mean "proven"
VALID = "VALID"
INVALID = "INVALID"
UNSIGNED = "UNSIGNED"
SIGNED_UNVERIFIED = "SIGNED_UNVERIFIED"
KEY_MISMATCH = "SIGNATURE_KEY_MISMATCH"
MALFORMED = "SIGNATURE_MALFORMED"

LIMITS = [
    "a valid signature proves the holder of the private key signed these exact bytes; it "
    "does not prove the key belongs to the vendor — that is a trust decision made outside "
    "this code",
    "the signing key is a file on the operator's disk; this module does not manage, rotate "
    "or revoke keys, and no key material is ever written into a document",
    "signature verification does not check a certificate chain, a timestamp authority or "
    "revocation: a signed document has no proven signing time",
]


def canonical_bytes(document: Mapping[str, Any], *, exclude: str = "signature") -> bytes:
    """The exact bytes a signature covers: the document minus ``exclude``.

    Canonical JSON: sorted keys, no insignificant whitespace, UTF-8. The same function is
    used to sign and to verify, because two implementations of "canonical" is one too many.
    """
    body = {key: value for key, value in document.items() if key != exclude}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _raw_public_key(public_key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def key_id(public_key_b64: str) -> str:
    """Stable name for a key: the hash of the raw public bytes, not a comment in a file."""
    raw = base64.b64decode(public_key_b64)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def load_private_key(path: str | Path):
    """Read an Ed25519 private key from a PEM file. Unencrypted PEM only, on purpose."""
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not hasattr(key, "private_bytes"):
        raise ValueError(f"{path} is not a private key")
    return key


def load_public_key(source: str | Path):
    """A public key from a PEM file, a raw-base64 ``.pub`` file, or a base64 string.

    Raw 32-byte Ed25519 keys are accepted because that is what the signature block carries;
    a PEM file is accepted because that is what an operator is likely to have been given.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    text = str(source).strip()
    candidate = Path(text) if len(text) < 512 else None
    if candidate is not None and candidate.exists():
        data = candidate.read_bytes()
        if b"BEGIN PUBLIC KEY" in data:
            return serialization.load_pem_public_key(data)
        text = data.decode("utf-8").strip()
    raw = base64.b64decode(text)
    if len(raw) != 32:
        raise ValueError(f"expected a 32-byte Ed25519 public key, got {len(raw)} bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def public_key_b64(public_key: Any) -> str:
    return base64.b64encode(_raw_public_key(public_key)).decode("ascii")


def sign_document(document: Mapping[str, Any], private_key: Any) -> dict[str, Any]:
    """Return the ``signature`` block for ``document`` (which must not include one)."""
    body = {key: value for key, value in document.items() if key != "signature"}
    signature = private_key.sign(canonical_bytes(body))
    public_b64 = public_key_b64(private_key.public_key())
    return {
        "schema": SCHEMA,
        "alg": ALGORITHM,
        "key_id": key_id(public_b64),
        "public_key": public_b64,
        "signature": base64.b64encode(signature).decode("ascii"),
        "covers": "every member except `signature`, as canonical JSON (sorted keys, no whitespace)",
    }


def sign_file_in_place(path: str | Path, private_key_path: str | Path) -> dict[str, Any]:
    """Sign a JSON document on disk and write it back with its ``signature`` block."""
    key = load_private_key(private_key_path)
    document = json.loads(Path(path).read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a JSON object")
    document.pop("signature", None)
    document["signature"] = sign_document(document, key)
    Path(path).write_text(json.dumps(document, indent=2) + "\n")
    return document["signature"]


def verify_document(
    document: Mapping[str, Any],
    *,
    trusted_key: Any = None,
    trusted_key_id: str | None = None,
) -> dict[str, Any]:
    """Check a document's signature against a **trusted** key and say exactly what it proves.

    The distinction that matters: without ``trusted_key`` this returns
    ``SIGNED_UNVERIFIED`` — the signature's own public key is not evidence, because whoever
    edited the document could have replaced it.
    """
    block = document.get("signature") if isinstance(document, Mapping) else None
    if not block:
        return {
            "status": UNSIGNED,
            "proves": "nothing — the document carries no signature",
            "meaning": (
                "an unsigned document can still match its own hashes; it cannot say who "
                "produced it"
            ),
            "limits": LIMITS,
        }
    if not isinstance(block, Mapping):
        return {"status": MALFORMED, "proves": "nothing", "reason": "signature is not an object",
                "limits": LIMITS}
    from cryptography.exceptions import InvalidSignature

    try:
        raw_signature = base64.b64decode(str(block.get("signature") or ""))
        embedded = str(block.get("public_key") or "")
        if not embedded or not raw_signature:
            raise ValueError("signature block is missing `public_key` or `signature`")
        embedded_key = load_public_key(embedded)
    except Exception as exc:  # noqa: BLE001 — a malformed block is a verdict, not a crash
        return {"status": MALFORMED, "proves": "nothing", "reason": str(exc), "limits": LIMITS}

    body = {key: value for key, value in document.items() if key != "signature"}
    embedded_id = key_id(public_key_b64(embedded_key))

    if trusted_key is None:
        return {
            "status": SIGNED_UNVERIFIED,
            "key_id": embedded_id,
            "reason": (
                "no trusted key was supplied, so the signature was not checked against "
                "anything an attacker could not also have written"
            ),
            "meaning": (
                "the document carries a signature; this run cannot say whether it is valid"
            ),
            "limits": LIMITS,
        }

    trusted_id = key_id(public_key_b64(trusted_key))
    if trusted_key_id and trusted_key_id != trusted_id:
        return {"status": KEY_MISMATCH, "reason": "the supplied key is not the one named",
                "expected_key_id": trusted_key_id, "actual_key_id": trusted_id, "limits": LIMITS}
    if embedded_id != trusted_id:
        return {
            "status": KEY_MISMATCH,
            "reason": "the document was signed by a different key than the trusted one",
            "signed_by": embedded_id,
            "trusted": trusted_id,
            "proves": "nothing about authenticity",
            "limits": LIMITS,
        }
    try:
        trusted_key.verify(raw_signature, canonical_bytes(body))
    except InvalidSignature:
        return {
            "status": INVALID,
            "key_id": trusted_id,
            "reason": "the bytes do not match the signature",
            "proves": "the document was altered after signing",
            "limits": LIMITS,
        }
    return {
        "status": VALID,
        "key_id": trusted_id,
        "proves": (
            "the holder of this key signed exactly these bytes; the document has not been "
            "altered since"
        ),
        "meaning": (
            "authenticity follows only if this key is the one you intended to trust — the "
            "signature is not a certificate and proves no signing time"
        ),
        "limits": LIMITS,
    }


def generate_keypair(directory: str | Path, *, name: str = "cryptoscan-release") -> dict[str, str]:
    """Create an Ed25519 key pair on disk, with the private key mode 0600.

    This exists so a deployment can sign its own manifests. It is not a key ceremony: a
    release key that matters should live in an HSM or a signing service, and this function
    says so in its own output rather than implying otherwise.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_path = target / f"{name}.key"
    public_path = target / f"{name}.pub"
    private_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(private_path, 0o600)
    public_path.write_text(public_key_b64(key.public_key()) + "\n")
    return {
        "private_key": str(private_path),
        "public_key": str(public_path),
        "key_id": key_id(public_key_b64(key.public_key())),
        "note": (
            "this is a local key pair, not a ceremony: a release key that matters belongs in "
            "an HSM or a signing service, and the public key still has to reach the verifier "
            "over a channel the attacker does not control"
        ),
    }


__all__ = [
    "ALGORITHM",
    "INVALID",
    "KEY_MISMATCH",
    "LIMITS",
    "MALFORMED",
    "SCHEMA",
    "SIGNED_UNVERIFIED",
    "UNSIGNED",
    "VALID",
    "canonical_bytes",
    "generate_keypair",
    "key_id",
    "load_private_key",
    "load_public_key",
    "public_key_b64",
    "sign_document",
    "sign_file_in_place",
    "verify_document",
]
