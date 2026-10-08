"""Generate a standalone Python script that re-checks a scan's hash chain."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _records_payload(records: list[Any]) -> list[dict[str, Any]]:
    payload = []
    for record in records:
        if hasattr(record, "to_dict"):
            data = record.to_dict()
        elif isinstance(record, dict):
            data = dict(record)
        else:
            data = {
                "id": getattr(record, "id", None),
                "content_hash": getattr(record, "content_hash", None),
                "chain_hash": getattr(record, "chain_hash", None),
                "file_path": getattr(record, "file_path", None),
                "line_number": getattr(record, "line_number", None),
                "algorithm": getattr(record, "algorithm", None),
            }
        payload.append(
            {
                "id": data.get("id") or data.get("evidence_id"),
                "content_hash": data.get("content_hash"),
                "chain_hash": data.get("chain_hash"),
                "file_path": data.get("file_path"),
                "line_number": data.get("line_number"),
                "algorithm": data.get("algorithm"),
            }
        )
    return payload


def generate_verification_script(
    *,
    scan_id: str,
    records: list[Any],
    output_path: str | Path | None = None,
) -> str:
    """
    Return a standalone verifier. When output_path is set the script is written
    there as well. The generated file has no CryptoScan imports.
    """
    payload = {
        "scan_id": scan_id,
        "records": _records_payload(records),
    }
    embedded = json.dumps(payload, indent=2)
    script = f'''#!/usr/bin/env python3
"""Standalone CryptoScan evidence-chain verifier. Generated, do not edit."""
from __future__ import annotations

import hashlib
import json
import sys

BUNDLE = json.loads(r"""{embedded}""")


def compute_chain(content_hashes: list[str], scan_id: str) -> list[str]:
    chain: list[str] = []
    previous = None
    for index, content_hash in enumerate(content_hashes):
        if index == 0:
            material = f"{{content_hash}}{{scan_id}}"
        else:
            material = f"{{content_hash}}{{previous}}"
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        chain.append(digest)
        previous = digest
    return chain


def main() -> int:
    scan_id = BUNDLE["scan_id"]
    records = BUNDLE["records"]
    if not records:
        print("UNVERIFIABLE no evidence records; use the authenticated scan verifier for manifest status")
        return 1
    content = [str(item.get("content_hash") or "") for item in records]
    stored = [str(item.get("chain_hash") or "") for item in records]
    if any(len(item) != 64 for item in content + stored):
        print("FAIL hash_format_invalid")
        return 1
    computed = compute_chain(content, scan_id)
    mismatches = [
        index for index, (left, right) in enumerate(zip(computed, stored)) if left != right
    ]
    if mismatches:
        print(f"FAIL chain_mismatch positions={{mismatches}}")
        return 1
    print(f"CHAIN_ONLY records={{len(records)}} scan_id={{scan_id}} (content and manifest not checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''
    if output_path is not None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(script, encoding="utf-8")
    return script
