"""Secrets-vault abstraction (adapter pattern).

The platform never persists key material. At scan time a scanner *leases* a
short-lived credential through this adapter, which delegates to the
customer's enterprise/cloud secret store:

    Credential Manager -> Vault adapter -> short-lived token -> scanner

Adapters are deterministic and side-effect-safe in tests/offline/air-gapped
mode: an unknown/unreachable provider fails closed (returns no secret) rather
than fabricating one. ``OutOfBandVault`` models the air-gapped case where the
operator injects the credential into the scanner's environment directly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol


class VaultError(RuntimeError):
    """Raised when a credential cannot be obtained — callers fail closed."""


@dataclass
class LeasedCredential:
    """A short-lived credential handed to a scanner. Never logged/persisted."""

    kind: str
    provider: str
    secret_ref: str
    value: str | None
    expires_in_seconds: int | None = None
    read_only: bool = True

    def redacted(self) -> dict:
        return {"kind": self.kind, "provider": self.provider,
                "secret_ref": self.secret_ref, "value": "<redacted>",
                "expires_in_seconds": self.expires_in_seconds, "read_only": self.read_only}


class VaultAdapter(Protocol):
    name: str

    def fetch(self, secret_ref: str, *, least_privilege_scope: str | None = None) -> LeasedCredential: ...


class OutOfBandVault:
    """Air-gapped / on-prem: the operator injects the secret via an env var the
    scanner reads. We only record that a reference exists; we never hold it."""

    name = "manual_out_of_band"

    def fetch(self, secret_ref: str, *, least_privilege_scope: str | None = None) -> LeasedCredential:
        # Env var name is derived deterministically from the ref; the value
        # lives only in the scanner process environment.
        env_key = "ZELNX_CRED_" + "".join(c if c.isalnum() else "_" for c in secret_ref).upper()[:48]
        value = os.environ.get(env_key)
        return LeasedCredential(kind="credential", provider=self.name, secret_ref=secret_ref,
                                value=value, expires_in_seconds=None, read_only=True)


class EnvSecretsManagerVault:
    """AWS Secrets Manager / Azure Key Vault / GCP Secret Manager / HashiCorp
    Vault. In this deterministic build we resolve via well-known env vars that
    a sidecar/CSI driver populates; real SDK calls are injected by the adapter
    in the deployed image. Resolution failure fails closed."""

    PROVIDERS = ("aws_secrets_manager", "azure_key_vault", "gcp_secret_manager", "hashicorp_vault")

    def __init__(self, provider: str):
        if provider not in self.PROVIDERS:
            raise VaultError(f"unsupported vault provider: {provider}")
        self.name = provider

    def fetch(self, secret_ref: str, *, least_privilege_scope: str | None = None) -> LeasedCredential:
        # A secrets-operator/CSI sidecar mounts each secret to an env var in
        # production; here we look that up deterministically.
        suffix = "".join(c if c.isalnum() else "_" for c in secret_ref).upper()[-40:]
        env_key = f"ZELNX_VAULT_{self.name.upper()}_{suffix}"
        value = os.environ.get(env_key)
        if value is None:
            # Fail closed: never return a guessed credential.
            raise VaultError(f"secret {secret_ref!r} not resolvable via {self.name} "
                             "(sidecar/CSI env not present)")
        read_only = bool(least_privilege_scope) and "read" in least_privilege_scope.lower()
        return LeasedCredential(kind="credential", provider=self.name, secret_ref=secret_ref,
                                value=value, expires_in_seconds=900, read_only=read_only)


def get_adapter(vault_provider: str) -> VaultAdapter:
    if vault_provider in EnvSecretsManagerVault.PROVIDERS:
        return EnvSecretsManagerVault(vault_provider)
    if vault_provider in ("manual_out_of_band", "kms_onprem"):
        return OutOfBandVault()
    raise VaultError(f"unknown vault provider: {vault_provider}")


def lease_credential(credential: dict, *, require_value: bool = False) -> LeasedCredential:
    """Resolve a CredentialRef (to_dict) into a short-lived lease.

    Honors least-privilege (the lease is flagged read-only) and never returns
    secret material to API code — callers pass the lease straight to a
    scanner process boundary.
    """
    if credential.get("status") in {"revoked", "expired", "error"}:
        raise VaultError(f"credential not usable: status={credential.get('status')}")
    adapter = get_adapter(credential.get("vault_provider", "manual_out_of_band"))
    lease = adapter.fetch(credential.get("secret_ref", ""),
                          least_privilege_scope=credential.get("least_privilege_scope"))
    lease.kind = credential.get("kind", "credential")
    if require_value and not lease.value:
        raise VaultError("credential material unavailable in this environment")
    return lease
