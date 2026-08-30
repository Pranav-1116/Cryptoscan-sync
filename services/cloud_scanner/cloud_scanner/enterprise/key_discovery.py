"""ZELNX Cloud Discovery Engine — cloud cryptographic key discovery (spec §3).

Discovers **key metadata only** — never the private key material:

- AWS KMS:        customer-managed + AWS-managed keys, key spec, state,
                  usage, rotation config, multi-region, origin, aliases,
                  grants metadata, resource dependencies
- Azure:          Key Vault / Managed HSM keys, types, curves, operations,
                  enabled state, expiration, rotation policy, HSM-backed,
                  access-model metadata
- GCP:            Cloud KMS key rings, crypto keys, versions, algorithms,
                  purposes, protection levels, rotation schedules, HSM
                  protection, resource dependencies

The scrub contract is enforced in tests: no ``key_material`` / secret
value ever appears in ``to_dict()`` even when the raw row contains it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import CryptoKey, EvidenceSource

KeyEnumerator = Callable[[], list[dict[str, Any]]]

ALGORITHM_HINTS = {
    "SYMMETRIC_DEFAULT": ("AES", 256),
    "RSA_2048": ("RSA", 2048),
    "RSA_3072": ("RSA", 3072),
    "RSA_4096": ("RSA", 4096),
    "ECC_NIST_P256": ("ECDSA", 256),
    "ECC_NIST_P384": ("ECDSA", 384),
    "ECC_NIST_P521": ("ECDSA", 521),
    "ECC_SECG_P256K1": ("ECDSA", 256),
    "EC_P256": ("ECDSA", 256),
    "EC_P384": ("ECDSA", 384),
    "EC_P521": ("ECDSA", 521),
    "EC_ED25519": ("ED25519", 256),
    "HSM": ("AES", 256),
    "SOFTWARE": ("AES", 256),
    "GOOGLE_SYMMETRIC_ENCRYPTION": ("AES", 256),
    "RSA_SIGN_PSS_2048_SHA256": ("RSA", 2048),
    "RSA_SIGN_PSS_3072_SHA256": ("RSA", 3072),
    "RSA_SIGN_PSS_4096_SHA256": ("RSA", 4096),
    "RSA_SIGN_PKCS1_2048_SHA256": ("RSA", 2048),
    "RSA_DECRYPT_OAEP_2048_SHA256": ("RSA", 2048),
    "EC_SIGN_P256_SHA256": ("ECDSA", 256),
    "EC_SIGN_P384_SHA384": ("ECDSA", 384),
    "EC_SIGN_P521_SHA512": ("ECDSA", 521),
    "EC_SIGN_SECP256K1_SHA256": ("ECDSA", 256),
}


def algorithm_for_spec(spec: str, provider: str) -> tuple[str, int | None]:
    """Map a provider key spec/algorithm token to (algorithm, key_size)."""
    token = str(spec or "").upper()
    if token in ALGORITHM_HINTS:
        return ALGORITHM_HINTS[token]
    if provider == "aws" and token.startswith("SYMMETRIC"):
        return "AES", 256
    if provider == "azure" and "RSA" in token:
        bits = "".join(ch for ch in token if ch.isdigit())
        return "RSA", int(bits) if bits else None
    if token in {"RSA", "AES", "ECDSA", "ED25519", "EC", "OKP", "X25519"}:
        return token, None
    return "UNKNOWN", None


def normalize_key(row: dict[str, Any], *, provider: str, account: str = "",
                  region: str = "", evidence: EvidenceSource | None = None) -> CryptoKey:
    """Normalize one raw provider key row into the shared model."""
    spec = str(_pick(row, "key_spec", "spec", "algorithm", "key_algorithm", "keyType", default="") or "")
    algo, bits = algorithm_for_spec(spec, provider)
    curve = str(_pick(row, "curve", "curve_name", "curveName", default="") or "")
    if not curve:
        clean = spec.upper().replace("-", "").replace("_", "")
        for token, label in (("P256", "P-256"), ("P384", "P-384"), ("P521", "P-521"),
                             ("SECP256K1", "SECP256K1"), ("ED25519", "ED25519")):
            if token in clean:
                curve = label
                break
    hsm = _pick(row, "hsm_backed", "hsm", "protection_level", default=None)
    if isinstance(hsm, str):
        hsm = hsm.upper() in {"HSM", "TRUE", "YES", "HARDWARE"}
    return CryptoKey(
        provider=provider,
        account=str(_pick(row, "account", "subscription", "project", default=account) or account),
        region=str(_pick(row, "region", default=region) or region),
        key_id=str(_pick(row, "key_id", "id", "name", "keyIdentifier", "resourceId", default="") or ""),
        name=str(_pick(row, "name", "key_name", "displayName", default="") or ""),
        key_manager=str(_pick(row, "key_manager", "keyManager", "managed_by",
                              default="CUSTOMER_MANAGED") or "CUSTOMER_MANAGED"),
        key_spec=spec,
        algorithm=algo,
        key_size=_pick(row, "key_size", "size", "keySize", default=bits),
        curve=curve,
        key_state=str(_pick(row, "key_state", "state", "keyState", "status", "enabled_state",
                            default="") or ""),
        key_usage=str(_pick(row, "key_usage", "usage", "keyUsage", "operations", default="") or ""),
        purpose=str(_pick(row, "purpose", "key_purpose", default="") or ""),
        rotation_enabled=_pick(row, "rotation_enabled", "rotationEnabled", "automatic_rotation",
                               default=None),
        rotation_period_days=_pick(row, "rotation_period_days", "rotationPeriod",
                                   "rotation_schedule", default=None),
        multi_region=_pick(row, "multi_region", "multiRegion", "multi_region_key", default=None),
        origin=str(_pick(row, "origin", "keyOrigin", default="") or ""),
        aliases=[str(item) for item in (_pick(row, "aliases", default=[]) or [])],
        grants=[dict(item) for item in (_pick(row, "grants", default=[]) or [])],
        hsm_backed=hsm,
        protection_level=str(_pick(row, "protection_level", "protectionLevel", default="") or ""),
        expiration=str(_pick(row, "expiration", "expires", "expiry", default="") or ""),
        created_at=str(_pick(row, "created_at", "createdAt", "creation_time", default="") or ""),
        dependencies=[str(item) for item in (_pick(row, "dependencies", "resource_dependencies",
                                                   default=[]) or [])],
        metadata=dict(_pick(row, "metadata", default={}) or {}),
        evidence=evidence or EvidenceSource(source_provider=provider, account=account),
    )


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


@dataclass
class KeyInventory:
    """All discovered crypto keys across providers."""

    keys: list[CryptoKey] = field(default_factory=list)
    truncated: bool = False
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [key.to_dict() for key in self.keys]

    def by_provider(self, provider: str) -> list[CryptoKey]:
        return [key for key in self.keys if key.provider == provider]

    def customer_managed(self) -> list[CryptoKey]:
        return [key for key in self.keys
                if key.key_manager == "CUSTOMER_MANAGED"]

    def without_rotation(self) -> list[CryptoKey]:
        return [key for key in self.keys
                if key.rotation_enabled is False and key.key_manager == "CUSTOMER_MANAGED"]

    def count(self, provider: str | None = None) -> int:
        return len(self.by_provider(provider)) if provider else len(self.keys)

    def summary(self) -> dict[str, Any]:
        return {
            "keys": len(self.keys),
            "by_provider": {
                provider: len(self.by_provider(provider))
                for provider in ("aws", "azure", "gcp")
            },
            "customer_managed": len(self.customer_managed()),
            "provider_managed": len(self.keys) - len(self.customer_managed()),
            "non_rotating_customer_keys": len(self.without_rotation()),
            "hsm_backed": sum(1 for key in self.keys if key.hsm_backed),
            "truncated": self.truncated,
            "errors": self.errors,
        }


class KeyDiscovery:
    """Run key discovery for injected provider adapters.

    Adapter shape: ``{"provider": "aws", "enumerate_keys": fn}`` where
    ``enumerate_keys()`` returns raw key rows (metadata only).
    """

    def __init__(self, providers: list[dict[str, Any]], *, max_keys: int = 2000) -> None:
        self._providers = list(providers)
        self._max_keys = max_keys

    def discover(self, *, accounts: list[dict[str, Any]] | None = None) -> KeyInventory:
        inventory = KeyInventory()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            enumerator = entry.get("enumerate_keys")
            if enumerator is None:
                inventory.errors.append(
                    {"provider": provider, "kind": "no_enumerator",
                     "detail": "no enumerate_keys callable injected"}
                )
                continue
            try:
                rows = enumerator() or []
            except Exception as exc:  # noqa: BLE001
                inventory.errors.append(
                    {"provider": provider, "kind": "enumerate", "detail": str(exc)[:300]}
                )
                continue
            for row in rows:
                if len(inventory.keys) >= self._max_keys:
                    inventory.truncated = True
                    break
                if isinstance(row, dict):
                    inventory.keys.append(normalize_key(row, provider=provider))
        return inventory
