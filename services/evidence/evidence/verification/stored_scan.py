"""Verify the committed contents, order and manifest of a persisted scan."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from evidence.hashing.chain_hasher import ChainHasher
from evidence.hashing.content_hasher import ContentHasher

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_EMPTY_MANIFEST = hashlib.sha256(b"").hexdigest()


def verify_stored_scan(scan: Any, rows: list[Any]) -> dict[str, Any]:
    """Return an honest verdict; never use stored hashes as their own proof."""
    ordered = sorted(rows, key=lambda row: row.chain_position)
    errors: list[str] = []
    content_ok = True
    chain_ok = True
    format_ok = True
    previous = None

    for position, row in enumerate(ordered):
        if row.chain_position != position or row.previous_hash != previous:
            chain_ok = False
            errors.append(f"chain position or predecessor mismatch at {position}")
        if not all(_HEX64.fullmatch(str(value or "")) for value in (row.content_hash, row.chain_hash)):
            format_ok = False
            errors.append(f"invalid hash format at {position}")
        try:
            if ContentHasher.compute_hash(row.finding_data) != row.content_hash:
                content_ok = False
                errors.append(f"content hash mismatch at {position}")
        except (TypeError, ValueError):
            content_ok = False
            errors.append(f"finding content unavailable at {position}")
        expected = ChainHasher.compute_chain_hash(
            content_hash=row.content_hash or "",
            previous_chain_hash=previous,
            scan_session_id=scan.id if position == 0 else None,
        )
        if row.chain_hash != expected:
            chain_ok = False
            errors.append(f"chain hash mismatch at {position}")
        previous = row.chain_hash

    recorded_manifest = scan.manifest_hash
    actual_manifest = hashlib.sha256(
        "".join(sorted(str(row.id) for row in ordered)).encode("utf-8")
    ).hexdigest()
    manifest_ok = bool(recorded_manifest) and recorded_manifest == actual_manifest
    if recorded_manifest and not manifest_ok:
        errors.append("manifest does not match stored evidence IDs")

    if errors:
        result = "FAIL"
    elif not recorded_manifest or str(scan.status).upper() != "COMPLETED":
        result = "UNVERIFIABLE"
    elif not ordered:
        result = "EMPTY" if recorded_manifest == _EMPTY_MANIFEST else "FAIL"
    else:
        result = "PASS"

    return {
        "scan_id": scan.id,
        "records": len(ordered),
        "chain_intact": chain_ok,
        "content_intact": content_ok,
        "hash_format_valid": format_ok,
        "manifest_intact": manifest_ok,
        "manifest_hash": recorded_manifest,
        "result": result,
        "errors": errors,
    }
