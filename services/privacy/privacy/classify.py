"""Data classifier — which sensitivity class does a value belong to?

NIST: traffic inspection/logging creates privacy risk, so identify and mitigate
it. Every observation value is classified as ``public`` / ``sensitive`` /
``restricted`` BEFORE it is retained, and the privacy engine's data-minimization
allowlist decides the field set that survives.

Deterministic + testable. Classification is based on field names and value shape,
NOT on guessing content semantics, so a scanner can never accidentally
self-certify data as "public".
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any


class DataClass(str, Enum):
    PUBLIC = "public"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


#: field name signals (any token -> restrictive).
_RESTRICTED_FIELD = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|"
    r"authorization|cookie|credential|pem|rsa[_-]?private|dnssec[_-]?key|bearer)", re.I)
_SENSITIVE_FIELD = re.compile(
    r"(pii|person|email|phone|ssn|dob|address|health|patient|mrn|account[_-]?no|"
    r"iban|card|pan|cvv|name|owner|username|national[_-]?id|passport|certificate|"
    r"subject|key[_-]?size|public[_-]?key|firmware|serial|mac|hostname)", re.I)


def classify_value(field: str, value: Any) -> DataClass:
    """Classify ``value`` (named by ``field``) into a sensitivity class.

    A field name match is authoritative; if the name is neutral the value's own
    shape is examined (an embedded PEM block or a long base64/hex blob with a
    private-key marker is RESTRICTED, a bare number/algorithm is low risk).
    """
    name = (field or "").lower()
    if _RESTRICTED_FIELD.search(name):
        return DataClass.RESTRICTED
    if name in ("private", "priv", "key", "secret_data"):
        return DataClass.RESTRICTED
    if _SENSITIVE_FIELD.search(name):
        return DataClass.SENSITIVE
    if isinstance(value, str):
        if _looks_like_private_key(value):
            return DataClass.RESTRICTED
        if _looks_like_long_blob(value):
            return DataClass.SENSITIVE
    if isinstance(value, dict):
        # a nested dict containing any restricted field is restricted
        nested = [classify_value(k, v) for k, v in value.items()]
        if any(c is DataClass.RESTRICTED for c in nested):
            return DataClass.RESTRICTED
        if any(c is DataClass.SENSITIVE for c in nested):
            return DataClass.SENSITIVE
    return DataClass.PUBLIC


_PRIVATE_KEY_HEADERS = (
    "-----BEGIN", "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PGP PRIVATE KEY", "BEGIN ENCRYPTED PRIVATE KEY",
)
_BLOB_RE = re.compile(r"^[A-Za-z0-9+/=]{64,}$")


def _looks_like_private_key(value: str) -> bool:
    if any(h in value for h in _PRIVATE_KEY_HEADERS):
        return True
    return bool(re.search(r"(PRIVATE KEY|ssh-rsa|ssh-ed25519|BEGIN.*PRIVATE)", value, re.I))


def _looks_like_long_blob(value: str) -> bool:
    return bool(_BLOB_RE.match(value.strip())) or len(value.strip()) > 256
