"""Evidence layer for universal vendor observations (spec §1, §12).

Every normalized observation becomes an evidence record with a content hash
and a chained hash (SHA-256 over content_hash + previous chain hash), so the
vendor scan output is tamper-evident end to end. The chain can be verified.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Iterable, Optional

from universal_vendor.plugin import canonical_json


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def content_hash(record: dict[str, Any]) -> str:
    return _sha256(canonical_json(record))


def build_evidence_chain(
    observations: Iterable[dict[str, Any]],
    *,
    scan_id: str,
    start_index: int = 0,
    previous_hash: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Chain observations into tamper-evident evidence records.

    ``start_index`` and ``previous_hash`` let callers extend an existing
    chain incrementally (e.g. the 24/7 edge agent appending one event at a
    time): pass the current record count and the last chain hash to keep
    the linkage continuous. Defaults preserve the original behavior.
    """
    records: list[dict[str, Any]] = []
    previous = previous_hash
    for offset, obs in enumerate(observations):
        index = start_index + offset
        body = {"index": index, "observation": obs}
        chash = content_hash(body)
        chain_input = f"{chash}{previous or scan_id}"
        chain = _sha256(chain_input)
        records.append(
            {
                "evidence_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "chain_position": index,
                "content_hash": chash,
                "chain_hash": chain,
                "previous_hash": previous,
                "observation": obs,
            }
        )
        previous = chain
    return records


def verify_evidence_chain(records: Iterable[dict[str, Any]], *, scan_id: str) -> dict[str, Any]:
    rows = list(records)
    errors: list[str] = []
    previous: Optional[str] = None
    for index, record in enumerate(rows):
        # incremental chains store their own absolute position; use it when
        # present so per-record appends verify against their original bodies
        body = {"index": record.get("chain_position", index),
                "observation": record.get("observation")}
        expected_hash = content_hash(body)
        if record.get("content_hash") != expected_hash:
            errors.append(f"content_hash mismatch at position {index}")
        chain_input = f"{record.get('content_hash') or ''}{previous or scan_id}"
        expected_chain = _sha256(chain_input)
        if record.get("chain_hash") != expected_chain:
            errors.append(f"chain_hash mismatch at position {index}")
        previous = record.get("chain_hash")
    return {
        "valid": not errors,
        "errors": errors,
        "records": len(rows),
        "chain_intact": not errors,
    }
