"""Credentials cross a transport boundary and must not survive it.

Three transports now read network hardware — SNMPv2c, NETCONF over SSH, and
RESTCONF over HTTPS — and each one carries a credential to the device: a
community string, a password, a bearer token. None of them may put it in the
payload that reaches the estate, because the estate is exported to a BOM, to a
report, and to whoever holds the auditor role.

The rule is the same for all three, so it lives in one place: pass the
credential in, use it, check the finished payload, and refuse rather than
redact. Redaction hides the fact that a device echoed a credential; refusal
makes somebody look at the device.
"""

from __future__ import annotations

import json
from typing import Any

#: Substrings that must never appear in a fact record, whatever a device says.
_SECRET_SHAPES = ("private_key", "private key", "password", "passwd", "key_material",
                  "authorization: bearer", "bearer ")


class CredentialLeakRefused(RuntimeError):
    """A transport was about to return a payload containing its own credential."""

    def __init__(self, host: str, kind: str = "credential") -> None:
        self.host = host
        self.kind = kind
        super().__init__(
            f"refusing to return hardware facts for {host}: the {kind} appears in the "
            "payload. A credential is not inventory data")


def refuse_credential_echo(payload: Any, credential: str | None, *, host: str,
                           kind: str = "credential") -> None:
    """Raise if ``credential`` appears anywhere in ``payload``.

    An empty or very short credential is not checked: matching the letter "a"
    against a device's sysDescr would refuse every honest device. A credential
    that short is a finding in itself, and the transport records it as one.
    """
    if not credential or len(credential) < 4:
        return
    rendered = json.dumps(payload, default=str)
    if credential in rendered:
        raise CredentialLeakRefused(host, kind)


def refuse_secret_shapes(payload: Any, *, host: str) -> None:
    """Refuse a payload that carries a secret-looking field, whatever its source.

    A device may return ``password`` in a configuration subtree, or a REST
    payload may include an ``Authorization`` header echoed back. This is the
    second belt, after the credential echo check.
    """
    rendered = json.dumps(payload, default=str).lower()
    for shape in _SECRET_SHAPES:
        if shape in rendered:
            raise CredentialLeakRefused(host, f"secret-shaped field ({shape.strip()})")
