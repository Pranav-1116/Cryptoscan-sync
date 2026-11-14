"""Envelope encryption for stored evidence bytes.

One column in this platform stores raw uploaded content:
``binary_scan_jobs.artifact_bytes``. Everything else stores derived facts
and hashes. This module encrypts that one column at the application layer
— AES-256-GCM envelope with a key ring — so the database holds ciphertext
and the keys live where the bank keeps keys.

Design, and what each choice refuses:

* **Tenant-bound ciphertext.** The tenant id is the AEAD's additional
  authenticated data: ciphertext copied to another tenant fails to
  decrypt. Tenancy here is structural, the same rule the shard map and
  the read cache follow — never a convention.
* **Key ring with rotation.** Ciphertext carries its key id
  (``v1:<kid>:<nonce>:<ct>``). Adding a new primary key never breaks old
  rows; rotation is add-and-rewrap, never re-encrypt-everything-at-once.
* **Fail-closed in production.** With no keys configured, ``protect``
  passes bytes through UNCRYPTED in development and REFUSES in
  production. A silent plaintext downgrade in a bank deployment is the
  exact failure this module exists to make impossible; the queue's
  ``as_dict`` always names the state in words operators can read.
* **Honest scope.** This is application-layer encryption of one column.
  Full-disk TDE, pgcrypto on other columns and backup encryption are the
  deployment's (``postgresql.conf`` and the backup volume are documented
  for exactly that handoff). The module never claims to be what it is not.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import threading
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

PREFIX = "v1"
KEY_BYTES = 32  # AES-256
NONCE_BYTES = 12

_lock = threading.Lock()
_ring: Optional[dict[str, bytes]] = None


class DecryptionError(ValueError):
    """The bytes are not ours — wrong key, wrong tenant, or tampered."""


def _load_ring() -> dict[str, bytes]:
    """Parse EVIDENCE_ENCRYPTION_KEYS (``kid:base64,kid:base64,...``);
    the FIRST entry is the primary (encrypt-with) key."""
    raw = os.environ.get("EVIDENCE_ENCRYPTION_KEYS", "").strip()
    if not raw:
        return {}
    ring: dict[str, bytes] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            kid, material = entry.split(":", 1)
            key = base64.b64decode(material, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError(
                "EVIDENCE_ENCRYPTION_KEYS entries are 'kid:base64-32-bytes' "
                f"— unparsable entry {entry!r}") from exc
        if len(key) != KEY_BYTES:
            raise ValueError(
                f"EVIDENCE_ENCRYPTION_KEYS key {kid!r} must be "
                f"{KEY_BYTES} bytes (AES-256), got {len(key)}")
        ring[kid] = key
    return ring


def get_ring() -> dict[str, bytes]:
    global _ring
    with _lock:
        if _ring is None:
            _ring = _load_ring()
        return _ring


def reset_ring() -> None:
    """Forget the cached ring (key changes in tests / rotation reloads)."""
    global _ring
    with _lock:
        _ring = None


def encryption_status(*, is_production: bool = False) -> dict:
    """The honest state, in words an operator can act on."""
    ring = get_ring()
    return {
        "configured": bool(ring),
        "key_ids": sorted(ring),
        "algorithm": "AES-256-GCM",
        "aad": "tenant_id (ciphertext is tenant-bound)",
        "note": (
            "envelope encryption of binary_scan_jobs.artifact_bytes"
            + (" — keys loaded, rows are ciphertext"
               if ring else
               " — NO KEYS CONFIGURED: artifact bytes are stored "
               "UNENCRYPTED"
               + (" and production refuses to store them (fail-closed)"
                  if is_production else
                  " (development posture; configure "
                  "EVIDENCE_ENCRYPTION_KEYS before production)"))),
    }


def _env_is_production() -> bool:
    return os.environ.get("ENVIRONMENT", "").strip().lower() == "production"


def protect(plain: bytes, *, tenant_id: Optional[str],
            is_production: Optional[bool] = None) -> bytes:
    """Encrypt for storage. Returns ``enc1:<hex envelope>`` — or the bytes
    unchanged when no key ring exists in development. ``is_production``
    defaults to the ENVIRONMENT the deployment runs under: production
    refuses plaintext storage outright."""
    if is_production is None:
        is_production = _env_is_production()
    ring = get_ring()
    if not ring:
        if is_production:
            raise ValueError(
                "refusing to store artifact bytes UNENCRYPTED in production: "
                "configure EVIDENCE_ENCRYPTION_KEYS")
        return plain
    kid = next(iter(ring))
    nonce = os.urandom(NONCE_BYTES)
    aad = (tenant_id or "platform").encode("utf-8")
    ct = AESGCM(ring[kid]).encrypt(nonce, plain, aad)
    envelope = ":".join((PREFIX, kid, nonce.hex(), ct.hex()))
    # ASCII marker so stored rows are self-describing: ciphertext starts
    # with b"enc1:", development plaintext never does.
    return b"enc1:" + envelope.encode("ascii")


def unprotect(stored: bytes, *, tenant_id: Optional[str]) -> bytes:
    """Decrypt one stored value. Anything that fails authentication —
    wrong key, wrong tenant, tampered bytes — raises DecryptionError and
    the bytes never reach a scan pipeline."""
    ring = get_ring()
    if not stored.startswith(b"enc1:"):
        return stored  # development plaintext (encryption_status names it)
    try:
        text = stored[len(b"enc1:"):].decode("ascii")
        _prefix, kid, nonce_hex, ct_hex = text.split(":", 3)
        key = ring[kid]
        nonce = bytes.fromhex(nonce_hex)
        ct = bytes.fromhex(ct_hex)
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise DecryptionError(
            "stored bytes are not decryptable with the configured key ring"
        ) from exc
    aad = (tenant_id or "platform").encode("utf-8")
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "decryption failed: wrong tenant, wrong key, or tampered bytes"
        ) from exc
