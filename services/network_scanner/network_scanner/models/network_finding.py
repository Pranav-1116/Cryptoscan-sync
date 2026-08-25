"""NetworkFinding dataclass."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class NetworkFinding:
    endpoint: str
    status: str = "OK"
    algorithm: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    certificates: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkFinding":
        crypto = data.get("crypto") or {}
        return cls(
            endpoint=str(data.get("endpoint") or ""),
            status=str(data.get("status") or "OK"),
            algorithm=data.get("algorithm") or crypto.get("algorithm"),
            tls_version=crypto.get("tls_version"),
            cipher_suite=crypto.get("cipher_suite"),
            certificates=list(data.get("certificates") or []),
            extra=dict(data.get("metadata") or {}),
        )
