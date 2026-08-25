"""Identify OS / language packages that ship cryptographic implementations."""

from __future__ import annotations

CRYPTO_NAMES = {
    "openssl",
    "libssl",
    "libcrypto",
    "libssl3",
    "libssl1.1",
    "libcrypto3",
    "libsodium",
    "libgcrypt",
    "gnutls",
    "nss",
    "mbedtls",
    "wolfssl",
    "bouncycastle",
    "bcprov",
    "bcpkix",
    "cryptography",
    "pycryptodome",
    "pycrypto",
    "pyopenssl",
    "crypto-js",
    "node-forge",
    "jsonwebtoken",
    "bcrypt",
    "argon2",
}

CRYPTO_TOKENS = (
    "ssl",
    "crypto",
    "tls",
    "bcprov",
    "bcpkix",
    "sodium",
    "gnutls",
    "mbedtls",
    "wolfssl",
    "nss",
    "gcrypt",
)


def is_crypto_package(name: str | None) -> bool:
    raw = (name or "").lower()
    if not raw:
        return False
    if raw in CRYPTO_NAMES:
        return True
    return any(token in raw for token in CRYPTO_TOKENS)


def filter_crypto(packages: list[dict]) -> list[dict]:
    return [pkg for pkg in packages if is_crypto_package(pkg.get("name") or pkg.get("original_name"))]
