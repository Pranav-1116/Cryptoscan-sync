"""Operator-facing evidence chain verdict: VALID / INVALID / BROKEN_AT_SEQUENCE."""

from __future__ import annotations

from typing import Any, Iterable

from evidence.hashing.chain_hasher import ChainHasher


def verdict_for_records(records: Iterable[Any], scan_id: str) -> dict[str, Any]:
    rows = list(records)
    if not rows:
        return {
            "result": "VALID",
            "records": 0,
            "broken_at": None,
            "message": "No evidence records. Empty chain is intact.",
        }
    content = [getattr(row, "content_hash", None) or (row.get("content_hash") if isinstance(row, dict) else "") for row in rows]
    stored = [getattr(row, "chain_hash", None) or (row.get("chain_hash") if isinstance(row, dict) else "") for row in rows]
    if any(len(item or "") != 64 for item in content + stored):
        return {
            "result": "INVALID",
            "records": len(rows),
            "broken_at": None,
            "message": "A content or chain hash is missing or not SHA-256.",
        }
    computed = ChainHasher.compute_chain(content, scan_id)
    for index, (got, expected) in enumerate(zip(computed, stored)):
        if got != expected:
            return {
                "result": "BROKEN_AT_SEQUENCE",
                "records": len(rows),
                "broken_at": index,
                "message": f"Chain hash mismatch at sequence {index}.",
            }
    if len(computed) != len(stored):
        return {
            "result": "INVALID",
            "records": len(rows),
            "broken_at": None,
            "message": "Chain length mismatch.",
        }
    return {
        "result": "VALID",
        "records": len(rows),
        "broken_at": None,
        "message": f"{len(rows)} records, chain intact.",
    }
