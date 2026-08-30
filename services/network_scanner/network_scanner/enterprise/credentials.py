"""Credentialed discovery — vault references, never secret material.

The architecture requirement: scan records must never contain router
passwords, SNMP secrets, API tokens or private keys. This module enforces
that: credentials exist only as *references* into a vault; resolution happens
at call time inside the vendor plugin, and every resolved secret is scrubbed
from any record produced downstream (see :func:`scrub_secrets`).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable

CREDENTIAL_TYPES = (
    "SSH", "SNMPV3", "REST_API", "NETCONF", "RESTCONF", "GNMI",
    "VENDOR_CONTROLLER", "CLOUD_API",
)

_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|community|authkey|privkey)\s*[=:]\s*\S+"),
    # Cisco-style config lines: "password 0 <cleartext>", "password 7 <type7>",
    # "secret 5 <hash>", "enable secret 9 <hash>" — value is secret material.
    re.compile(r"(?i)(password|secret)\s+(\d+)\s+\S+"),
    re.compile(r"(?i)(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)"),
)


@dataclass(frozen=True)
class CredentialRef:
    """A reference to a secret held in a vault — the only thing stored."""

    type: str
    ref: str  # vault path / key name, e.g. 'vault:secret/network/edge-routers'
    username: str | None = None
    credential_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in CREDENTIAL_TYPES:
            raise ValueError(f"unsupported credential type '{self.type}' (choose from {CREDENTIAL_TYPES})")

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "ref": self.ref, "username": self.username,
                "credential_id": self.credential_id, "extra": dict(self.extra)}


class CredentialVault:
    """Minimal vault interface. Plugins only ever resolve through this."""

    def resolve(self, ref: CredentialRef) -> dict[str, Any]:
        """Return the runtime credential. Default implementation reads
        environment variables named by the ref (e.g. ``CRYPTOSCAN_NETCONF_PW``);
        production deployments replace this with a real vault client."""
        key = ref.ref.replace(":", "_").replace("/", "_").upper().lstrip("_")
        env = os.environ.get(f"CRYPTOSCAN_{key}")
        if env is None:
            raise CredentialUnavailable(f"credential ref '{ref.ref}' not resolvable")
        return {"username": ref.username, "secret": env}


class CredentialUnavailable(Exception):
    """A credential ref could not be resolved — recorded, never fatal."""


def scrub_secrets(record: dict[str, Any], *, deep: bool = True) -> dict[str, Any]:
    """Remove any accidental secret material from a scan record.

    Walks nested dicts/lists; keys whose names look secret are dropped, and
    values that match secret patterns (PEM blocks, ``key=value`` secrets) are
    redacted. Unit tests assert scan outputs contain no secret material.
    """
    if isinstance(record, list):
        return [scrub_secrets(item, deep=deep) for item in record]
    if not isinstance(record, dict):
        return record
    out: dict[str, Any] = {}
    for key, value in record.items():
        if _looks_secret_key(key):
            continue
        if isinstance(value, dict):
            out[key] = scrub_secrets(value, deep=deep)
        elif isinstance(value, list):
            out[key] = [scrub_secrets(item, deep=deep) for item in value]
        elif isinstance(value, str):
            if _SECRET_PATTERNS[0].search(value) and "ref" not in key:
                out[key] = _SECRET_PATTERNS[0].sub(r"\1=***REDACTED***", value)
            elif _SECRET_PATTERNS[1].search(value):
                out[key] = _SECRET_PATTERNS[1].sub(r"\1 \2 ***REDACTED***", value)
            elif _SECRET_PATTERNS[2].search(value):
                out[key] = "***REDACTED-PRIVATE-KEY***"
            else:
                out[key] = value
        else:
            out[key] = value
    return out


def _looks_secret_key(key: str) -> bool:
    lowered = str(key).lower()
    if lowered in {"password", "passwd", "secret", "token", "api_key", "apikey",
                   "private_key", "privatekey", "community", "auth_key",
                   "authkey", "priv_key", "privkey", "psk", "presharedkey"}:
        return True
    return False


def scrub_all(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [scrub_secrets(record) for record in records]
