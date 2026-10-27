"""Secure Credential Architecture (24/7 spec §23).

Vendor credentials are NEVER stored inside scanner plugins. Plugins only ever
hold a *credential reference*; the reference resolves through a credential
vault to short-lived, scoped, read-only access. Credential management is
separated from vendor discovery; least privilege is the default.

The isolation worker also scrubs known secret keys from any context handed to
a plugin, so even a broken plugin cannot leak credentials.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from universal_vendor.plugin import scrub_secrets

_SECRET_KEYS = ("password", "secret", "token", "apikey", "api_key",
                "private_key", "preshared", "passphrase", "credential",
                "access_key", "client_secret")


@dataclass
class CredentialReference:
    """What a plugin is allowed to see: a reference, never the secret."""
    reference_id: str
    vault_path: str
    scoped_to: list[str] = field(default_factory=list)   # resource scopes
    read_only: bool = True
    expires_at: Optional[str] = None
    mechanism: str = "short-lived"  # short-lived | scoped | mfa | vault-ref

    def to_dict(self) -> dict[str, Any]:
        return {"reference_id": self.reference_id, "vault_path": self.vault_path,
                "scoped_to": list(self.scoped_to), "read_only": self.read_only,
                "expires_at": self.expires_at, "mechanism": self.mechanism}


class CredentialVault:
    """Vault facade. In production this wraps the operator's vault (e.g.
    Vault/Secrets Manager/KMS). Here it issues scoped references and leases —
    the actual secret values never cross this boundary into plugins."""

    def __init__(self) -> None:
        self._refs: dict[str, CredentialReference] = {}
        self._leases: dict[str, dict[str, Any]] = {}

    def issue_reference(
        self,
        *,
        vault_path: str,
        scoped_to: Optional[list[str]] = None,
        read_only: bool = True,
        ttl_seconds: int = 900,
    ) -> CredentialReference:
        reference_id = f"ref-{len(self._refs) + 1}"
        reference = CredentialReference(
            reference_id=reference_id,
            vault_path=vault_path,
            scoped_to=list(scoped_to or []),
            read_only=read_only,
            expires_at=(datetime.now(timezone.utc)
                        + timedelta(seconds=ttl_seconds)).isoformat(),
        )
        self._refs[reference_id] = reference
        return reference

    def lease(self, reference_id: str) -> dict[str, Any]:
        """Resolve a reference into a short-lived lease (never a raw secret
        string in plugin context — the plugin gets a token handle)."""
        reference = self._refs.get(reference_id)
        if reference is None:
            raise KeyError(f"unknown credential reference {reference_id}")
        if reference.expires_at and reference.expires_at < datetime.now(timezone.utc).isoformat():
            raise PermissionError(f"credential reference {reference_id} expired")
        lease = {
            "reference_id": reference_id,
            "vault_path": reference.vault_path,
            "scoped_to": list(reference.scoped_to),
            "read_only": reference.read_only,
            "lease_id": f"lease-{reference_id}",
            "expires_at": reference.expires_at,
        }
        self._leases[reference_id] = lease
        return lease

    def references(self) -> list[CredentialReference]:
        return list(self._refs.values())


def strip_credentials(context: dict[str, Any]) -> dict[str, Any]:
    """Remove known secret-bearing keys from a context handed to a plugin."""
    out: dict[str, Any] = {}
    for key, value in context.items():
        lowered = str(key).lower()
        if any(token in lowered for token in _SECRET_KEYS):
            continue
        out[key] = value
    return out


def context_with_credential_reference(context: dict[str, Any],
                                      reference: CredentialReference) -> dict[str, Any]:
    """Hand a plugin a context carrying only the credential reference."""
    clean = strip_credentials(context)
    clean["credential_reference"] = reference.to_dict()
    return clean
