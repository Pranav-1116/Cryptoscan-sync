"""Verify the committed contents, order and manifest of a persisted scan."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from evidence.hashing.chain_hasher import ChainHasher
from evidence.hashing.content_hasher import ContentHasher

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_EMPTY_MANIFEST = hashlib.sha256(b"").hexdigest()


def verify_stored_record(
    record: Any,
    *,
    previous_record: Any | None,
    expected_position: int,
    scan_id: str,
) -> dict[str, Any]:
    """Verify ONE persisted evidence record against its own commitments.

    Single source of truth for record-level verdicts — the scan verifier
    below calls this per row, so a single-record API answer can never
    disagree with the scan-level one. Honest scope: this proves the stored
    payload still matches its committed hashes and chain links; it is not
    a claim that the observation itself was true.
    """
    errors: list[str] = []

    if record.chain_position != expected_position:
        errors.append(
            f"chain position mismatch: stored {record.chain_position}, expected {expected_position}")
    previous_hash = previous_record.chain_hash if previous_record is not None else None
    if record.previous_hash != previous_hash:
        errors.append("predecessor hash mismatch")

    if not all(_HEX64.fullmatch(str(value or "")) for value in (record.content_hash, record.chain_hash)):
        errors.append("invalid hash format")

    try:
        if ContentHasher.compute_hash(record.finding_data) != record.content_hash:
            errors.append("content hash mismatch — stored finding_data no longer matches its commitment")
    except (TypeError, ValueError):
        errors.append("finding content unavailable")

    expected_chain = ChainHasher.compute_chain_hash(
        content_hash=record.content_hash or "",
        previous_chain_hash=previous_hash,
        scan_session_id=scan_id if expected_position == 0 else None,
    )
    if record.chain_hash != expected_chain:
        errors.append("chain hash mismatch")

    return {
        "evidence_id": record.id,
        "scan_id": getattr(record, "scan_id", None),
        "chain_position": record.chain_position,
        "content_intact": not any("content" in e or "unavailable" in e for e in errors),
        "chain_intact": not any("chain" in e or "predecessor" in e for e in errors),
        "hash_format_valid": not any("hash format" in e for e in errors),
        "result": "PASS" if not errors else "FAIL",
        "errors": errors,
        "notes": [
            "This verifies the stored payload against its committed content "
            "and chain hashes — it is not a claim that the observation was "
            "true, only that storage has not diverged from the commitment.",
        ],
    }


def verify_stored_scan(scan: Any, rows: list[Any]) -> dict[str, Any]:
    """Return an honest verdict; never use stored hashes as their own proof."""
    ordered = sorted(rows, key=lambda row: row.chain_position)
    errors: list[str] = []
    content_ok = True
    chain_ok = True
    format_ok = True

    for position, row in enumerate(ordered):
        record_verdict = verify_stored_record(
            row,
            previous_record=ordered[position - 1] if position > 0 else None,
            expected_position=position,
            scan_id=scan.id,
        )
        if record_verdict["result"] != "PASS":
            content_ok = content_ok and record_verdict["content_intact"]
            chain_ok = chain_ok and record_verdict["chain_intact"]
            format_ok = format_ok and record_verdict["hash_format_valid"]
            errors.extend(f"{e} at {position}" for e in record_verdict["errors"])


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
