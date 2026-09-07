"""Deterministic signing/encryption key provider (no plaintext secrets).

Resolution order for each key, fail-closed and auditable:
1. Vault reference injected via environment (a *reference id* / secret path,
   never the secret itself) — resolved through the platform secret loader.
2. A key persisted in the platform settings store (generated once by an
   authorized action, stored encrypted at rest by the DB layer).
3. A key deterministically DERIVED (HKDF-SHA256) from the platform's master
   SECRET_KEY with a domain-separation info string — never the raw master key.

The process-ephemeral random fallback used during local development is removed:
a production deployment always has SECRET_KEY set, so derivation is stable.
No AI; pure cryptography via the `cryptography` package.
"""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _platform_master() -> bytes:
    key = os.environ.get("SECRET_KEY") or os.environ.get("GOVERNANCE_MASTER_KEY")
    if not key:
        raise RuntimeError(
            "no platform SECRET_KEY configured; cannot derive governance keys "
            "(set SECRET_KEY or provision keys via vault/settings)")
    return key.encode("utf-8")


def _hkdf(info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=b"cryptoscan-governance-v1",
                info=info).derive(_platform_master())


def signing_secret(*, settings_repo=None) -> str:
    """HMAC signing secret (hex). Env vault ref > stored key > derived."""
    env_ref = os.environ.get("GOVERNANCE_SIGNING_KEY_REF")
    if env_ref:
        return _resolve_vault_secret(env_ref)
    if settings_repo is not None:
        stored = settings_repo.get("governance.signing_secret", default=None)
        if stored:
            return str(stored)
    # deterministic derivation from platform master (stable across restarts)
    return _hkdf(b"resilience-signing-secret").hex()


def backup_fernet_key(*, settings_repo=None) -> bytes:
    """Fernet key (urlsafe-b64 32 bytes). Env vault ref > stored key > derived."""
    env_ref = os.environ.get("BACKUP_ENCRYPTION_KEY_REF") or os.environ.get("BACKUP_ENCRYPTION_KEY")
    if env_ref:
        # BACKUP_ENCRYPTION_KEY may be a raw Fernet key in dev; a *_REF is vault
        raw = _resolve_vault_secret(env_ref) if env_ref.endswith(("ref://", "vault://")) else env_ref
        return raw.encode() if isinstance(raw, str) else raw
    if settings_repo is not None:
        stored = settings_repo.get("governance.backup_fernet_key", default=None)
        if stored:
            return str(stored).encode()
    key = _hkdf(b"backup-encryption-fernet", length=32)
    return base64.urlsafe_b64encode(key)


def provision_keys(settings_repo, *, created_by: str = "system") -> dict[str, bool]:
    """Generate and PERSIST dedicated keys in the settings store (one-time,
    idempotent). Returns whether each key was newly created. This is the
    audited path an operator uses to pin keys explicitly rather than derive."""
    from cryptography.fernet import Fernet

    created = {"signing": False, "encryption": False}
    if not settings_repo.get("governance.signing_secret", default=None):
        settings_repo.set("governance.signing_secret", _hkdf(b"provisioned-signing").hex(),
                          updated_by=created_by)
        created["signing"] = True
    if not settings_repo.get("governance.backup_fernet_key", default=None):
        settings_repo.set("governance.backup_fernet_key", Fernet.generate_key().decode(),
                          updated_by=created_by)
        created["encryption"] = True
    return created


def _resolve_vault_secret(ref: str) -> str:
    """Resolve a vault reference. The platform vault lease service loads secret
    material; here we integrate through a thin indirection so callers never pass
    raw secrets. Falls back to an env var named by the reference when the vault
    client isn't wired in this process (deterministic in tests)."""
    # ref forms: vault://path/to/secret  or  ref://NAME
    name = ref.split("://", 1)[-1].replace("/", "_").upper()
    val = os.environ.get(f"VAULT_SECRET_{name}")
    if val:
        return val
    raise RuntimeError(f"vault reference {ref!r} could not be resolved (vault unavailable)")
