"""Observation hierarchy — never promote a lower level (spec 92 §6, §29).

An observation's *level* states how it was obtained. This matters because the
same algorithm string can arrive three different ways and must not be presented
with the same authority:

    Level 1  a crypto API call observed directly   (EVP_EncryptInit_ex, Cipher.doFinal, AesGcm.Encrypt)
    Level 2  framework-level instrumentation       (request-scoped hooks, ORM/driver wrappers)
    Level 3  HSM / KMS / database audit telemetry  (operation logs, key references)
    Level 4  network observation                   (negotiated TLS/IPsec/SSH session)
    Level 5  approved binary/runtime instrumentation (assembly/trace-level evidence)
    Level 6  UNKNOWN                               (custom crypto, blind spot)

The engine never upgrades a level. A TLS 1.3 session proves *transport* crypto
(Level 4); it proves nothing about the application's own AES (Level 1), and a
report that merges the two is wrong even when both are correct facts.
"""

from __future__ import annotations

from typing import Any

LEVEL_NAMES: dict[int, str] = {
    1: "CRYPTO_API_OBSERVED",
    2: "FRAMEWORK_OBSERVED",
    3: "AUDIT_TELEMETRY_OBSERVED",
    4: "NETWORK_SESSION_OBSERVED",
    5: "BINARY_INSTRUMENTATION_OBSERVED",
    6: "UNKNOWN",
}

LEVEL_DESCRIPTIONS: dict[int, str] = {
    1: "a cryptographic API call this process made, observed by approved instrumentation",
    2: "a framework-level hook (driver, container runtime, messaging client) observed the operation",
    3: "HSM, KMS or database audit telemetry reported the operation and its key reference",
    4: "a negotiated network session proves transport crypto only — not application crypto",
    5: "approved binary/runtime instrumentation observed the operation below the API layer",
    6: "no approved observation covers this code path — the crypto is UNKNOWN, not absent",
}

#: adapter/source kinds mapped to the level they justify. Anything absent from
#: this table falls to 6 (UNKNOWN) rather than being guessed upwards.
_SOURCE_LEVELS: dict[str, int] = {
    # Level 1 — crypto API instrumentation
    "OPENSSL_TRACE": 1,
    "BORINGSSL_TRACE": 1,
    "JVM_JCE": 1,
    "DOTNET_CNG": 1,
    "GO_CRYPTO": 1,
    "RUST_CRYPTO": 1,
    "PKCS11_API": 1,
    # Level 2 — framework-level
    "FRAMEWORK_HOOK": 2,
    "MESSAGING_CLIENT": 2,
    "ORM_DRIVER": 2,
    "RUNTIME_SIDECAR": 2,
    # Level 3 — audit telemetry
    "HSM_AUDIT": 3,
    "KMS_AUDIT": 3,
    "DATABASE_AUDIT": 3,
    "VPN_TELEMETRY": 3,
    "SSH_TELEMETRY": 3,
    # Level 4 — network observation
    "NETWORK_SESSION": 4,
    "TLS_TAP": 4,
    # Level 5 — binary instrumentation
    "BINARY_TRACE": 5,
    "EBPF": 5,
}

#: evidence types this engine may emit, per §23-style taxonomy, runtime side
RUNTIME_EVIDENCE_TYPES = (
    "RUNTIME_OBSERVED",
    "HSM_OBSERVED",
    "KMS_OBSERVED",
    "NETWORK_OBSERVED",
    "CONFIGURED",
    "UNKNOWN",
)


def level_for_evidence(source: Any) -> int:
    """Return the observation level a source justifies (6 when unknown)."""
    return _SOURCE_LEVELS.get(str(source or "").upper(), 6)


def evidence_type_for_level(level: int) -> str:
    """Evidence type implied by the level — Level 4 is network, not runtime."""
    if level == 1 or level == 2 or level == 5:
        return "RUNTIME_OBSERVED"
    if level == 3:
        return "HSM_OBSERVED"
    if level == 4:
        return "NETWORK_OBSERVED"
    return "UNKNOWN"


def level_table() -> list[dict[str, Any]]:
    """The hierarchy as a reportable table (used by the catalog endpoint)."""
    return [
        {
            "level": level,
            "name": LEVEL_NAMES[level],
            "description": LEVEL_DESCRIPTIONS[level],
            "sources": sorted(source for source, value in _SOURCE_LEVELS.items() if value == level),
            "evidence_type": evidence_type_for_level(level),
        }
        for level in range(1, 7)
    ]
