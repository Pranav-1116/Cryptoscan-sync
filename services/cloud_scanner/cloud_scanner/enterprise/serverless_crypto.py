"""ZELNX Cloud Discovery Engine — serverless crypto discovery (spec §10).

Supports AWS Lambda, Azure Functions, Google Cloud Functions, Cloud Run.

Discovers runtime, runtime version, dependencies, crypto libraries,
environment configuration metadata, KMS / Key Vault dependencies,
certificate dependencies and API TLS relationships — all metadata, no
secret values, no function code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import EvidenceSource

ServerlessEnumerator = Callable[[], list[dict[str, Any]]]


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


@dataclass
class ServerlessFunction:
    """One serverless function / service."""

    function_id: str
    provider: str = ""
    account: str = ""
    region: str = ""
    runtime: str = ""
    runtime_version: str = ""
    dependencies: list[str] = field(default_factory=list)
    crypto_libraries: list[str] = field(default_factory=list)
    environment_metadata: dict[str, Any] = field(default_factory=dict)
    key_references: list[str] = field(default_factory=list)
    certificate_references: list[str] = field(default_factory=list)
    api_tls: str = ""  # api gateway / trigger URL TLS version
    api_tls_weak: bool = False
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "provider": self.provider,
            "account": self.account,
            "region": self.region,
            "runtime": self.runtime,
            "runtime_version": self.runtime_version,
            "dependencies": list(self.dependencies),
            "crypto_libraries": list(self.crypto_libraries),
            "environment_metadata": dict(self.environment_metadata),
            "key_references": list(self.key_references),
            "certificate_references": list(self.certificate_references),
            "api_tls": self.api_tls,
            "api_tls_weak": self.api_tls_weak,
            "evidence": self.evidence.to_dict(),
        }


CRYPTO_LIBRARY_HINTS = (
    "openssl", "libsodium", "cryptography", "pyca", "bcrypt", "argon2",
    "bouncycastle", "opensslj", "nss", "gnutls", "mbedtls", "wolfssl", "forge",
)


def detect_crypto_libraries(dependencies: list[str] | None) -> list[str]:
    """Extract crypto libraries from a dependency list (name matching only)."""
    found: list[str] = []
    for dep in dependencies or []:
        name = str(dep).lower()
        for hint in CRYPTO_LIBRARY_HINTS:
            if hint in name and dep not in found:
                found.append(dep)
    return found


@dataclass
class ServerlessInventory:
    """All serverless functions across providers."""

    functions: list[ServerlessFunction] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [fn.to_dict() for fn in self.functions]

    def count(self, provider: str | None = None) -> int:
        if provider is None:
            return len(self.functions)
        return sum(1 for fn in self.functions if fn.provider == provider)

    def with_weak_tls(self) -> list[ServerlessFunction]:
        return [fn for fn in self.functions if fn.api_tls_weak]

    def crypto_library_usage(self) -> dict[str, int]:
        from collections import Counter

        counter: Counter[str] = Counter()
        for fn in self.functions:
            for lib in fn.crypto_libraries:
                counter[lib] += 1
        return dict(counter)

    def summary(self) -> dict[str, Any]:
        return {
            "functions": len(self.functions),
            "by_provider": {
                provider: self.count(provider) for provider in ("aws", "azure", "gcp")
            },
            "crypto_libraries": self.crypto_library_usage(),
            "weak_api_tls": len(self.with_weak_tls()),
            "errors": self.errors,
        }


class ServerlessCryptoDiscovery:
    """Discover serverless crypto surfaces from injected enumerators."""

    def __init__(self, providers: list[dict[str, Any]]) -> None:
        self._providers = list(providers)

    def discover(self) -> ServerlessInventory:
        inventory = ServerlessInventory()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            enumerator = entry.get("enumerate_serverless")
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
                    inventory.functions.append(self._function(row, provider=provider))
        return inventory

    @staticmethod
    def _function(row: dict[str, Any], *, provider: str) -> ServerlessFunction:
        dependencies = [str(d) for d in (_pick(row, "dependencies", default=[]) or [])]
        runtime = str(_pick(row, "runtime", "runtime_version", default="") or "")
        runtime_version = str(_pick(row, "runtime_version", default="") or "")
        if not runtime and runtime_version:
            runtime = runtime_version.split("-")[0]
        api_tls = str(_pick(row, "api_tls", "tls_version", "trigger_tls", default="") or "")
        api_weak = bool(_pick(row, "api_tls_weak", "weak_tls", default=False))
        if not api_weak and any(
            weak in api_tls.upper() for weak in ("TLS1.0", "TLS1.1", "TLSV1.0", "TLSV1.1", "SSLV3")
        ):
            api_weak = True
        env_meta = dict(_pick(row, "environment_metadata", "environment", "env", default={}) or {})
        return ServerlessFunction(
            function_id=str(_pick(row, "function_id", "id", "name", "arn", "service",
                                  default="") or ""),
            provider=provider,
            account=str(_pick(row, "account", "subscription", "project", default="") or ""),
            region=str(_pick(row, "region", default="") or ""),
            runtime=runtime,
            runtime_version=runtime_version,
            dependencies=dependencies,
            crypto_libraries=detect_crypto_libraries(dependencies),
            environment_metadata=env_meta,
            key_references=[str(k) for k in (_pick(row, "key_references", "kms_keys",
                                                   default=[]) or [])],
            certificate_references=[str(c) for c in (_pick(row, "certificate_references",
                                                           "certificates", default=[]) or [])],
            api_tls=api_tls,
            api_tls_weak=api_weak,
            evidence=EvidenceSource(
                source_provider=provider,
                account=str(_pick(row, "account", "subscription", "project", default="") or ""),
                api_source=str(_pick(row, "api_source", default="serverless-crypto") or ""),
            ),
        )
