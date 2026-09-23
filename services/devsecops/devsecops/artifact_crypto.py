"""Encryption at rest for stored scan artifacts, keyed per tenant.

A binary artifact is the most sensitive thing this platform writes down: the SBOM
lists every component and path in a shipped image, the CBOM names the algorithms
in use, and the manifest counts private keys and test vectors. It sits on a disk
that gets backed up, replicated and handed to auditors, so it is worth encrypting
with a key that is *not* on that disk — and worth separating by tenant, because
two organizations' inventories living under one key means one leaked key reads
both.

The design is deliberately small and dependency-light (stdlib + the
``cryptography`` package the platform already ships):

* one key per tenant, derived ``HKDF-SHA256`` from a master secret — the key is
  never stored, only its id is, so a database dump carries no key material;
* AES-256-GCM per object with a random nonce, so identical payloads do not
  produce identical bytes and tampering is detected rather than decrypted;
* an envelope that names its version and key id, so a blob can be checked against
  a tenant before decryption and a key rotation can be seen coming;
* plaintext fallback for objects written before this existed, reported as
  ``alg: none`` rather than silently treated as encrypted.

Nothing here is a second opinion about *what* an artifact says: the platform's own
sha256 and HMAC signatures are computed over the plaintext, so verification,
gating and diffing are unchanged by encryption.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any

ENVELOPE_MAGIC = b"CSENC1"
KEY_ID_PREFIX = "cs1-"
HKDF_SALT = b"cryptoscan-artifact-at-rest-v1"
KEY_BYTES = 32
NONCE_BYTES = 12
PLATFORM_TENANT = "platform"
TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ArtifactCryptoError(RuntimeError):
    """An encryption or decryption that could not be done, with a reason code.

    The reason is a machine-readable code (``no_key``, ``wrong_key``,
    ``tampered``, ``malformed``, ``invalid_tenant``) so an API can answer with
    something better than "decryption failed" — the difference between a rotated
    key and an edited blob matters to whoever has to fix it.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
        self.message = message

    def as_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "message": self.message}


def normalize_tenant(tenant_id: Any) -> str:
    """A tenant id that is safe in a path, an envelope and a log line.

    An artifact written with no tenant context belongs to the platform estate —
    it is not "shared", it is the bucket a single-organization install uses.
    """
    value = str(tenant_id or "").strip()
    if not value:
        return PLATFORM_TENANT
    if not TENANT_RE.match(value):
        raise ArtifactCryptoError("invalid_tenant", f"tenant id is not usable as a scope: {value!r}")
    return value


def resolve_master_secret(explicit: str | None = None) -> tuple[str | None, str]:
    """(secret, source) for artifact encryption.

    ``CRYPTOSCAN_ARTIFACT_KEY`` wins because at-rest encryption should be able to
    use a key of its own; ``SECRET_KEY`` follows, so an install that already has
    a platform master gets encryption without another knob; a host with neither
    stores plaintext and says so.
    """
    if explicit:
        return explicit, "explicit"
    for env, source in (("CRYPTOSCAN_ARTIFACT_KEY", "env:CRYPTOSCAN_ARTIFACT_KEY"),
                        ("SECRET_KEY", "env:SECRET_KEY")):
        value = os.environ.get(env)
        if value:
            return value, source
    return None, "none"


def tenant_key(tenant_id: Any, secret: str) -> bytes:
    """The 32-byte key for one tenant, derived from the master secret."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    scope = normalize_tenant(tenant_id)
    derived = HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=HKDF_SALT,
                   info=f"artifact-at-rest:{scope}".encode("utf-8")).derive(secret.encode("utf-8"))
    return derived


def key_id(tenant_id: Any, secret: str) -> str:
    """A short, stable public name for a tenant key (never the key itself)."""
    scope = normalize_tenant(tenant_id)
    digest = hmac.new(tenant_key(scope, secret), b"key-id", hashlib.sha256).hexdigest()
    return f"{KEY_ID_PREFIX}{digest[:16]}"


def is_envelope(blob: bytes) -> bool:
    return isinstance(blob, (bytes, bytearray)) and bytes(blob[:len(ENVELOPE_MAGIC)]) == ENVELOPE_MAGIC


def envelope_key_id(blob: bytes) -> str | None:
    """The key id an envelope was written with, or ``None`` for a plain object."""
    if not is_envelope(blob):
        return None
    rest = bytes(blob[len(ENVELOPE_MAGIC):])
    head = rest.split(b"\n", 1)
    if len(head) != 2:
        return None
    return head[0].decode("utf-8", "replace") or None


def at_rest_report(tenant_id: Any, secret: str | None) -> dict[str, Any]:
    """What a store *would* do for this tenant, for a status endpoint."""
    resolved, source = resolve_master_secret(secret)
    report: dict[str, Any] = {"tenant": normalize_tenant(tenant_id),
                              "algorithm": "AES-256-GCM" if resolved else "none",
                              "key_source": source,
                              "encrypted": bool(resolved)}
    if resolved:
        report["key_id"] = key_id(tenant_id, resolved)
    else:
        report["note"] = ("no artifact encryption key configured; artifacts are stored in "
                          "plaintext (set CRYPTOSCAN_ARTIFACT_KEY or SECRET_KEY)")
    return report


def encrypt_blob(data: bytes, *, tenant_id: Any, secret: str | None = None) -> tuple[bytes, dict[str, Any]]:
    """Encrypt one object. Returns ``(blob, at_rest)``.

    With no key material configured the object is returned unchanged and the
    report says ``algorithm: none`` — a caller that must not write plaintext can
    check the report and refuse, but the platform never pretends it encrypted
    something it did not.
    """
    resolved, source = resolve_master_secret(secret)
    if not resolved:
        return data, {"tenant": normalize_tenant(tenant_id), "algorithm": "none",
                      "key_source": "none", "encrypted": False,
                      "note": "stored unencrypted: no CRYPTOSCAN_ARTIFACT_KEY/SECRET_KEY configured"}
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    scope = normalize_tenant(tenant_id)
    kid = key_id(scope, resolved)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(tenant_key(scope, resolved)).encrypt(nonce, data, kid.encode("utf-8"))
    blob = b"".join([ENVELOPE_MAGIC, kid.encode("utf-8"), b"\n", nonce, ciphertext])
    return blob, {"tenant": scope, "algorithm": "AES-256-GCM", "key_id": kid,
                  "key_source": source, "encrypted": True, "bytes": len(blob)}


def decrypt_blob(blob: bytes, *, tenant_id: Any, secret: str | None = None,
                 label: str = "artifact") -> tuple[bytes, dict[str, Any]]:
    """Decrypt one object written by :func:`encrypt_blob`.

    A plain (unversioned) object is returned as-is and reported as unencrypted:
    artifacts written before this module existed are still readable, and the
    answer says which of the two happened. An object that *is* encrypted but
    cannot be opened with this tenant's key is an error with a reason — never a
    silently-empty document, which would read as "the artifact has no content".
    """
    if not is_envelope(blob):
        return blob, {"algorithm": "none", "encrypted": False,
                      "note": f"{label} was stored before encryption-at-rest; it is plaintext on disk"}
    rest = bytes(blob[len(ENVELOPE_MAGIC):])
    parts = rest.split(b"\n", 1)
    if len(parts) != 2 or len(parts[1]) <= NONCE_BYTES:
        raise ArtifactCryptoError("malformed", f"{label} has an incomplete encryption envelope")
    blob_key_id = parts[0].decode("utf-8", "replace")
    nonce, ciphertext = parts[1][:NONCE_BYTES], parts[1][NONCE_BYTES:]
    resolved, source = resolve_master_secret(secret)
    if not resolved:
        raise ArtifactCryptoError("no_key",
                                  f"{label} is encrypted with {blob_key_id} but no artifact key is "
                                  "configured on this host (set CRYPTOSCAN_ARTIFACT_KEY or SECRET_KEY)")
    scope = normalize_tenant(tenant_id)
    expected = key_id(scope, resolved)
    if blob_key_id != expected:
        raise ArtifactCryptoError("wrong_key",
                                  f"{label} was encrypted for key {blob_key_id}, not this tenant's "
                                  f"key {expected} — a tenant reads its own artifacts only")
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        plaintext = AESGCM(tenant_key(scope, resolved)).decrypt(nonce, ciphertext, blob_key_id.encode("utf-8"))
    except InvalidTag as exc:  # tampered ciphertext, or a key that is not this key's master
        raise ArtifactCryptoError("tampered",
                                  f"{label} failed authentication with {blob_key_id}: it was modified "
                                  "after it was written, or the master secret changed") from exc
    return plaintext, {"tenant": scope, "algorithm": "AES-256-GCM", "key_id": blob_key_id,
                       "key_source": source, "encrypted": True}


def seal_reference(tenant_id: Any, secret: str | None = None) -> dict[str, Any]:
    """A public, non-secret summary of the key an artifact would be sealed with."""
    return at_rest_report(tenant_id, secret)
