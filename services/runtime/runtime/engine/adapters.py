"""Runtime crypto adapter registry (spec 92 §5, §24–§29).

One generic "runtime scanner" is not enough: what becomes visible depends on
the runtime the process actually uses. OpenSSL exposes `EVP_CipherInit_ex`, a
JVM exposes `Cipher.getInstance`, .NET exposes `AesGcm`, Go has no C symbol at
all, and an HSM exposes only an audit record.

Each adapter therefore declares, explicitly:

* the **source** string it reports (which maps to an observation level),
* the **frameworks**/libraries it covers,
* the **parameters it can report** — and, just as important, the ones it cannot.
  An adapter that cannot see a tag length must not be read as "tag is fine";
  the field stays `UNKNOWN`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: every field a runtime event may carry. Anything else is rejected, so an
#: agent cannot smuggle payload or key material through an extra key.
EVENT_FIELDS = (
    "event_type",
    "host",
    "application",
    "process",
    "pid",
    "executable",
    "executable_digest",
    "container_id",
    "container_digest",
    "image",
    "namespace",
    "pod",
    "deployment",
    "cluster",
    "crypto_provider",
    "provider_version",
    "library",
    "function",
    "algorithm",
    "key_size",
    "mode",
    "padding",
    "hash",
    "curve",
    "operation",
    "nonce_length",
    "tag_length",
    "iv_length",
    "digest_length",
    "output_length",
    "kdf",
    "salt_present",
    "info_present",
    "tls_version",
    "cipher_suite",
    "mutual_tls",
    "key_reference",
    "device",
    "caller_identity",
    "timestamp",
    "observation_count",
    "source",
    "attributes",
)


@dataclass(frozen=True)
class Adapter:
    """A declared runtime crypto observation adapter."""

    id: str
    source: str
    framework: str
    libraries: tuple[str, ...]
    reports: tuple[str, ...]
    cannot_report: tuple[str, ...]
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "framework": self.framework,
            "libraries": list(self.libraries),
            "reports": list(self.reports),
            "cannot_report": list(self.cannot_report),
            "notes": list(self.notes),
        }


_COMMON_CANNOT = (
    "plaintext, key bytes, IV/nonce values, salts or customer data",
    "an algorithm the instrumentation did not observe",
)

ADAPTERS: tuple[Adapter, ...] = (
    Adapter(
        id="openssl-trace",
        source="OPENSSL_TRACE",
        framework="OpenSSL / BoringSSL / LibreSSL",
        libraries=("libcrypto.so", "libssl.so"),
        reports=(
            "algorithm", "key_size", "mode", "operation", "cipher_suite",
            "tls_version", "provider_version",
        ),
        cannot_report=(
            "padding for raw EVP_PKEY calls unless the caller sets it explicitly",
            "tag length for AEAD suites chosen inside a TLS stack",
        )
        + _COMMON_CANNOT,
        notes=(
            "LD_PRELOAD shim records one line per EVP_* call; no kernel code, no privileges",
        ),
    ),
    Adapter(
        id="jvm-jce",
        source="JVM_JCE",
        framework="JVM / JCE / BouncyCastle",
        libraries=("java.security", "javax.crypto", "bcprov"),
        reports=("algorithm", "key_size", "mode", "padding", "operation", "crypto_provider"),
        cannot_report=(
            "parameters passed to a provider implemented in native code",
            "which provider serviced the call when multiple are registered",
        )
        + _COMMON_CANNOT,
        notes=("Cipher.getInstance('AES/GCM/NoPadding') gives the full transformation string",),
    ),
    Adapter(
        id="dotnet-cng",
        source="DOTNET_CNG",
        framework=".NET / System.Security.Cryptography",
        libraries=("System.Security.Cryptography", "bcrypt.dll", "ncrypt.dll"),
        reports=("algorithm", "key_size", "mode", "operation", "nonce_length", "tag_length"),
        cannot_report=("key storage backend unless the key handle is exposed",) + _COMMON_CANNOT,
    ),
    Adapter(
        id="go-crypto",
        source="GO_CRYPTO",
        framework="Go crypto/*",
        libraries=("crypto/aes", "crypto/cipher", "crypto/rsa", "crypto/ecdsa", "crypto/tls"),
        reports=("algorithm", "key_size", "mode", "operation"),
        cannot_report=(
            "symbol-level attribution without a Go-aware tracer (inlining removes frames)",
            "tag length for AEAD helpers that hide the nonce size",
        )
        + _COMMON_CANNOT,
    ),
    Adapter(
        id="rust-crypto",
        source="RUST_CRYPTO",
        framework="Rust crypto crates",
        libraries=("ring", "rustls", "openssl", "aes-gcm", "sha2"),
        reports=("algorithm", "key_size", "mode", "operation", "library"),
        cannot_report=("generic-monomorphised call identities in release builds",) + _COMMON_CANNOT,
    ),
    Adapter(
        id="pkcs11-hsm",
        source="HSM_AUDIT",
        framework="PKCS#11 / HSM audit log",
        libraries=("pkcs11",),
        reports=("operation", "algorithm", "hash", "key_reference", "device", "caller_identity"),
        cannot_report=(
            "key material (never collected)",
            "bulk data length when the audit record omits it",
        )
        + _COMMON_CANNOT,
        notes=("evidence type is HSM_OBSERVED; the key is referenced, never read",),
    ),
    Adapter(
        id="kms-audit",
        source="KMS_AUDIT",
        framework="Cloud KMS audit trail",
        libraries=("aws-kms", "azure-keyvault", "gcp-kms"),
        reports=("operation", "algorithm", "key_reference", "caller_identity", "timestamp"),
        cannot_report=(
            "what the caller did with the plaintext after the KMS call",
            "ciphertext/plaintext content (never collected)",
        )
        + _COMMON_CANNOT,
        notes=("correlates application identity → key → algorithm → operation",),
    ),
    Adapter(
        id="database-audit",
        source="DATABASE_AUDIT",
        framework="Database audit / TDE telemetry",
        libraries=("oracle-audit", "postgres-log", "sqlserver-audit", "mongo-audit"),
        reports=("operation", "algorithm", "key_reference", "tls_version", "cipher_suite"),
        cannot_report=(
            "table-level crypto when the engine does not log it",
            "key length when the platform reports only 'AES-256'",
        )
        + _COMMON_CANNOT,
    ),
    Adapter(
        id="vpn-telemetry",
        source="VPN_TELEMETRY",
        framework="VPN gateway / IKE telemetry",
        libraries=("strongswan", "libreswan", "ikev2", "anyconnect"),
        reports=("algorithm", "hash", "key_size", "operation", "tls_version", "cipher_suite"),
        cannot_report=("per-flow key material (never available)",) + _COMMON_CANNOT,
    ),
    Adapter(
        id="ssh-telemetry",
        source="SSH_TELEMETRY",
        framework="SSH session telemetry",
        libraries=("openssh", "dropbear", "libssh"),
        reports=("algorithm", "hash", "key_size", "operation", "cipher_suite"),
        cannot_report=("client-side key negotiation if the server log omits it",) + _COMMON_CANNOT,
    ),
    Adapter(
        id="tls-tap",
        source="TLS_TAP",
        framework="Network TLS observation",
        libraries=(),
        reports=("tls_version", "cipher_suite", "mutual_tls", "algorithm", "key_size"),
        cannot_report=(
            "application-layer crypto behind the TLS session",
            "key sizes for TLS 1.3 suites that hide key exchange details",
        )
        + _COMMON_CANNOT,
        notes=("Level 4: transport crypto only",),
    ),
    Adapter(
        id="binary-trace",
        source="BINARY_TRACE",
        framework="Approved binary/runtime instrumentation",
        libraries=(),
        reports=("algorithm", "operation", "function", "key_size", "mode"),
        cannot_report=("semantic purpose of the operation", "parameters held in registers only") + _COMMON_CANNOT,
        notes=("Level 5: used when no API-level observation exists, never assumed to be Level 1",),
    ),
)

_BY_ID = {adapter.id: adapter for adapter in ADAPTERS}
_BY_SOURCE = {adapter.source: adapter for adapter in ADAPTERS}


def get_adapter(identifier: str | None) -> Adapter | None:
    """Look an adapter up by id or by its source string."""
    if not identifier:
        return None
    key = str(identifier).strip().lower()
    if key in _BY_ID:
        return _BY_ID[key]
    return _BY_SOURCE.get(str(identifier).strip().upper())


def adapter_catalog() -> dict[str, Any]:
    """The registry as the API reports it — including what each cannot see."""
    return {
        "model": "cryptoscan.runtime-adapters/1",
        "adapter_count": len(ADAPTERS),
        "adapters": [adapter.to_dict() for adapter in ADAPTERS],
        "sources": sorted(_BY_SOURCE),
        "note": (
            "an adapter reports only what its instrumentation can see; every other field of an "
            "event stays UNKNOWN rather than being inferred"
        ),
    }
