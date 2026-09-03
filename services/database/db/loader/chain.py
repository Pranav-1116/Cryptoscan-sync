"""Tamper-evident evidence hash chain.

The chain is a blockchain-style linked list of evidence records. Each record's
``content_hash`` commits to the finding payload; its ``chain_hash`` links it to
the previous record:

* genesis record (position 0): ``chain_hash = sha256(content_hash + scan_session_id)``
* subsequent records:        ``chain_hash = sha256(content_hash + previous_hash)``

Canonical JSON serialization (sorted keys, no whitespace) makes hashes stable
across processes and languages.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_SENTINEL = ""


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def content_hash(finding: dict[str, Any]) -> str:
    """Commitment hash over a finding payload."""
    return hashlib.sha256(canonical_json(finding).encode("utf-8")).hexdigest()


def chain_hash(content_hash_hex: str, previous_hash: str) -> str:
    """Link a record to its predecessor (or the scan-session genesis anchor)."""
    return hashlib.sha256((content_hash_hex + (previous_hash or "")).encode("utf-8")).hexdigest()


def expected_previous(position: int, scan_session_id: str | None) -> str:
    """The anchor value a record at ``position`` must chain off."""
    return scan_session_id or GENESIS_SENTINEL if position == 0 else ""
