#!/usr/bin/env python3
"""Encryption helpers for evidence backups (round 17 — audits 15/16).

Backups leave the machine, so plaintext DB snapshots are a data-exfiltration
path that bypasses every in-product control. This module gives
backup_evidence.py / restore_evidence.py one shared implementation:

* AES-256-GCM (authenticated — tampering fails the restore, not silently
  restores corrupted evidence);
* scrypt KDF (memory-hard) derives the 256-bit key from the operator's
  passphrase in ``BACKUP_ENCRYPTION_KEY``;
* a small binary header carries the version tag, salt, and nonce so the
  file is self-describing: ``CSBC1 | salt(16) | nonce(12) | ciphertext``.

The manifest beside the backup stays JSON and records the **plaintext**
SHA-256 plus the KDF parameters, so an encrypted backup is fully
verifiable after decryption without trusting the ciphertext's integrity
alone (GCM tag) or the manifest alone.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

MAGIC = b"CSBC1"  # CryptoScan Backup Crypto, format 1
_SALT_LEN = 16
_NONCE_LEN = 12
_HEADER_LEN = len(MAGIC) + _SALT_LEN + _NONCE_LEN

KDF_NAME = "scrypt"
KDF_PARAMS = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}

ENV_KEY = "BACKUP_ENCRYPTION_KEY"
MIN_KEY_LEN = 16


class BackupKeyError(SystemExit):
    """Raised when the encryption key is missing or too weak to accept."""


def load_key(env: dict[str, str] | None = None) -> bytes:
    """Read and validate the backup key (min 16 chars — honest floor, not strength)."""
    source = os.environ if env is None else env
    raw = source.get(ENV_KEY, "")
    if not raw:
        raise BackupKeyError(
            f"{ENV_KEY} is not set — generate one with, for example:\n"
            f"  python3 -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    if len(raw) < MIN_KEY_LEN:
        raise BackupKeyError(
            f"{ENV_KEY} is too short ({len(raw)} chars, minimum {MIN_KEY_LEN}) — "
            "use a 32+ char random secret"
        )
    return raw.encode("utf-8")


def derive_key(passphrase: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase, salt=salt, **KDF_PARAMS)


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with a fresh random salt+nonce; returns header+ciphertext."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag  # noqa: F401 — re-exported semantics

    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    aes = AESGCM(derive_key(key, salt))
    return MAGIC + salt + nonce + aes.encrypt(nonce, plaintext, None)


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    """Verify + decrypt; raises InvalidTag on tamper/corruption, ValueError on bad header."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(blob) < _HEADER_LEN or blob[: len(MAGIC)] != MAGIC:
        raise ValueError("not a CryptoScan encrypted backup (bad header)")
    salt = blob[len(MAGIC): len(MAGIC) + _SALT_LEN]
    nonce = blob[len(MAGIC) + _SALT_LEN: _HEADER_LEN]
    aes = AESGCM(derive_key(key, salt))
    try:
        return aes.decrypt(nonce, blob[_HEADER_LEN:], None)
    except InvalidTag:
        # wrong key or tampered ciphertext — never restore silently-corrupt evidence
        raise


def is_encrypted_file(path: Path) -> bool:
    """Cheap sniff: magic header at the start of the file."""
    try:
        with path.open("rb") as fh:
            return fh.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def encrypt_file(src: Path, dst: Path, key: bytes) -> None:
    blob = encrypt_bytes(src.read_bytes(), key)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    tmp.write_bytes(blob)
    tmp.replace(dst)
    # remove the plaintext as soon as the ciphertext is in place
    src.unlink(missing_ok=True)


def decrypt_file(src: Path, dst: Path, key: bytes) -> None:
    plaintext = decrypt_bytes(src.read_bytes(), key)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    tmp.write_bytes(plaintext)
    tmp.replace(dst)
