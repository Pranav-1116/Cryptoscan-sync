"""ZELNX Cloud Discovery Engine — secret & key reference discovery (spec §11).

**Never scans secret values.**  Discovers only the *relationship*:

    Application ── REFERENCES ── Key / Secret Store ── Crypto Key

- AWS Secrets Manager, AWS Parameter Store
- Azure Key Vault
- Google Secret Manager

Supported: secret metadata (name, version count, key references, KMS
encryption key, rotation config, tags) and which applications reference
them.  Values are never read, listed or echoed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import EvidenceSource

SecretEnumerator = Callable[[], list[dict[str, Any]]]


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


@dataclass
class SecretReference:
    """One secret store entry (metadata + references only)."""

    secret_id: str
    provider: str = ""
    account: str = ""
    region: str = ""
    store: str = ""  # secrets_manager | parameter_store | key_vault | secret_manager
    name: str = ""
    referenced_by: list[str] = field(default_factory=list)
    encryption_key_reference: str = ""
    rotation_enabled: bool | None = None
    version_count: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret_id": self.secret_id,
            "provider": self.provider,
            "account": self.account,
            "region": self.region,
            "store": self.store,
            "name": self.name,
            "referenced_by": list(self.referenced_by),
            "encryption_key_reference": self.encryption_key_reference,
            "rotation_enabled": self.rotation_enabled,
            "version_count": self.version_count,
            "metadata": dict(self.metadata),
            "evidence": self.evidence.to_dict(),
            "note": "secret values are never collected",
        }


@dataclass
class SecretInventory:
    """All secret/key store references across clouds."""

    secrets: list[SecretReference] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [secret.to_dict() for secret in self.secrets]

    def count(self, provider: str | None = None) -> int:
        if provider is None:
            return len(self.secrets)
        return sum(1 for s in self.secrets if s.provider == provider)

    def without_encryption(self) -> list[SecretReference]:
        return [s for s in self.secrets if not s.encryption_key_reference]

    def summary(self) -> dict[str, Any]:
        return {
            "secrets": len(self.secrets),
            "by_provider": {
                provider: self.count(provider) for provider in ("aws", "azure", "gcp")
            },
            "by_store": {
                store: sum(1 for s in self.secrets if s.store == store)
                for store in ("secrets_manager", "parameter_store", "key_vault", "secret_manager")
            },
            "referenced_by_apps": len({ref for s in self.secrets for ref in s.referenced_by}),
            "errors": self.errors,
        }


class SecretReferenceDiscovery:
    """Discover secret/key references from injected enumerators.

    Adapter shape: ``{"provider": "aws", "enumerate_secrets": fn}``.
    Rows must never contain values; if they do, they are stripped by the
    scrub contract (``values`` key removed).
    """

    def __init__(self, providers: list[dict[str, Any]]) -> None:
        self._providers = list(providers)

    def discover(self) -> SecretInventory:
        inventory = SecretInventory()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            enumerator = entry.get("enumerate_secrets")
            if enumerator is None:
                continue
            try:
                rows = enumerator() or []
            except Exception as exc:  # noqa: BLE001
                inventory.errors.append(
                    {"provider": provider, "kind": "enumerate", "detail": str(exc)[:300]}
                )
                continue
            for row in rows:
                if isinstance(row, dict):
                    row = {k: v for k, v in row.items() if str(k).lower() not in
                           ("value", "secretvalue", "plaintext", "secret_string", "secret_value")}
                    inventory.secrets.append(self._secret(row, provider=provider))
        return inventory

    @staticmethod
    def _secret(row: dict[str, Any], *, provider: str) -> SecretReference:
        return SecretReference(
            secret_id=str(_pick(row, "secret_id", "id", "arn", "resourceId", "name",
                                default="") or ""),
            provider=provider,
            account=str(_pick(row, "account", "subscription", "project", default="") or ""),
            region=str(_pick(row, "region", default="") or ""),
            store=str(_pick(row, "store", "service", default="") or ""),
            name=str(_pick(row, "name", "secret_name", "key_name", default="") or ""),
            referenced_by=[str(app) for app in (_pick(row, "referenced_by", "applications",
                                                      default=[]) or [])],
            encryption_key_reference=str(_pick(row, "encryption_key_reference", "kms_key_id",
                                               "encryption_key", "key_id", "keyvault_key",
                                               default="") or ""),
            rotation_enabled=_pick(row, "rotation_enabled", "automatic_rotation", default=None),
            version_count=_pick(row, "version_count", "versions", "version", default=None),
            metadata=dict(_pick(row, "metadata", "tags", default={}) or {}),
            evidence=EvidenceSource(
                source_provider=provider,
                account=str(_pick(row, "account", "subscription", "project", default="") or ""),
                api_source=str(_pick(row, "api_source", default="secret-reference-discovery") or ""),
            ),
        )
