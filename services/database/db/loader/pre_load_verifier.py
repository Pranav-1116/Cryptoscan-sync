"""Verify evidence hashes before DB load."""

from __future__ import annotations


def verify_records(records: list[dict]) -> tuple[bool, str | None]:
    if not records:
        return True, None
    positions = [r.get("chain_position") for r in records]
    if positions != list(range(len(records))):
        return False, "chain_position sequence is not contiguous"
    for rec in records:
        if not rec.get("content_hash") or len(str(rec["content_hash"])) != 64:
            return False, "invalid content_hash"
        if rec.get("chain_hash") and len(str(rec["chain_hash"])) != 64:
            return False, "invalid chain_hash"
    return True, None
