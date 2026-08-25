"""TLSConfig dataclass."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class TLSConfig:
    tls_version: str | None = None
    cipher_suite: str | None = None
    key_exchange: str | None = None
    algorithm: str | None = None
    mode: str | None = None
    key_size: int | None = None

    @classmethod
    def from_crypto(cls, crypto: dict[str, Any] | None) -> "TLSConfig":
        crypto = crypto or {}
        return cls(
            tls_version=crypto.get("tls_version"),
            cipher_suite=crypto.get("cipher_suite"),
            key_exchange=crypto.get("key_exchange_algorithm") or crypto.get("key_exchange"),
            algorithm=crypto.get("algorithm") or crypto.get("encryption_algorithm"),
            mode=crypto.get("mode") or crypto.get("encryption_mode"),
            key_size=crypto.get("key_size"),
        )
