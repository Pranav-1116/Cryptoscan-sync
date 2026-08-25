"""Algorithm → OID mapping used by CycloneDX CBOM generation."""

from __future__ import annotations

import json
from pathlib import Path

_TABLE = Path(__file__).with_name("oid_table.json")
_LOADED: dict[str, str] = {}
if _TABLE.is_file():
    try:
        data = json.loads(_TABLE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            _LOADED = {str(k): str(v) for k, v in data.items()}
    except Exception:
        _LOADED = {}

ALGORITHM_OIDS = _LOADED or {
    "AES": "2.16.840.1.101.3.4.1",
    "AES-128": "2.16.840.1.101.3.4.1.2",
    "AES-192": "2.16.840.1.101.3.4.1.22",
    "AES-256": "2.16.840.1.101.3.4.1.42",
    "SHA-1": "1.3.14.3.2.26",
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3",
    "SHA3-256": "2.16.840.1.101.3.4.2.8",
    "MD5": "1.2.840.113549.2.5",
    "RSA": "1.2.840.113549.1.1.1",
    "ECDSA": "1.2.840.10045.2.1",
    "DSA": "1.2.840.10040.4.1",
    "3DES": "1.2.840.113549.3.7",
    "DES": "1.3.14.3.2.7",
    "HMAC-SHA256": "1.2.840.113549.2.9",
    "HMAC-SHA1": "1.2.840.113549.2.7",
    "HMAC-SHA384": "1.2.840.113549.2.10",
    "HMAC-SHA512": "1.2.840.113549.2.11",
    "PBKDF2": "1.2.840.113549.1.5.12",
}


def lookup_oid(algorithm: str | None) -> str | None:
    if not algorithm:
        return None
    key = str(algorithm).upper()
    return ALGORITHM_OIDS.get(key) or ALGORITHM_OIDS.get(algorithm)
