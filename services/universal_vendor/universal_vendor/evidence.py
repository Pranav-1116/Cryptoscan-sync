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
                # UUID5 makes the evidence identifier reproducible for the
                # same scan, position, and observation. A UUID4 here made
                # otherwise identical vendor reports differ on every run.
                "evidence_id": str(uuid.uuid5(
                    uuid.NAMESPACE_URL, f"{scan_id}:{index}:{chash}")),
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


def verify_evidence_chain(
    records: Iterable[dict[str, Any]],
    *,
    scan_id: str,
    previous_hash: Optional[str] = None,
) -> dict[str, Any]:
    """Verify content, ordering, scan identity, and chain linkage.

    ``previous_hash`` is used when verifying an increment appended to an
    existing chain. Without it, the first record must be rooted at ``scan_id``
    (its stored ``previous_hash`` is therefore ``None``).
    """
    rows = list(records)
    errors: list[str] = []
    previous: Optional[str] = previous_hash
    seen_ids: set[str] = set()
    last_position: Optional[int] = None
    for index, record in enumerate(rows):
        position = record.get("chain_position", index)
        if not isinstance(position, int):
            errors.append(f"invalid chain position at record {index}")
            position = index
        if last_position is not None and position != last_position + 1:
            errors.append(f"chain position discontinuity at record {index}")
        last_position = position
        if record.get("scan_id") != scan_id:
            errors.append(f"scan_id mismatch at position {index}")
        evidence_id = record.get("evidence_id")
        if evidence_id in seen_ids:
            errors.append(f"duplicate evidence_id at position {index}")
        if evidence_id:
            seen_ids.add(evidence_id)
        if record.get("previous_hash") != previous:
            errors.append(f"previous_hash mismatch at position {index}")
        body = {"index": position, "observation": record.get("observation")}
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
