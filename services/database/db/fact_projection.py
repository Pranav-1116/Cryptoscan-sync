"""Cryptographic fact identity — the one truth for what a fact IS.

Advanced/51 P0#1 (write-side step, round 35): facts become rows
(``cryptographic_facts``), so the identity function must live in the
database kernel where the fact repository uses it — and the API's live
projection imports the same function, so the read contract and the
stored rows can never disagree about identity.

Identity: what + why + where + parameters. Line number is deliberately
NOT part of the identity — the same algorithm/purpose/parameters in the
same file is one fact observed at several lines (lines stay on the
evidence rows).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional


def fact_key(row: Mapping[str, Any]) -> tuple:
    """Fact identity: (algorithm, purpose, file_path, key_size, mode)."""
    return (
        str(row.get("algorithm") or "UNKNOWN"),
        str(row.get("purpose") or ""),
        str(row.get("file_path") or ""),
        row.get("key_size"),
        str(row.get("mode") or ""),
    )


def identity_values(key: tuple) -> dict[str, Any]:
    """Spread a fact_key into column-name -> value for row construction.

    Values are stored VERBATIM (empty string for absent purpose/file/mode,
    never None): SQL NULLs are distinct under unique constraints in SQLite,
    so normalising to "" keeps fact identity exact-match everywhere.
    """
    algorithm, purpose, file_path, key_size, mode = key
    return {
        "algorithm": algorithm,
        "purpose": purpose,
        "file_path": file_path,
        "key_size": key_size,
        "mode": mode,
    }


def scanner_id(row: Mapping[str, Any]) -> Optional[str]:
    """Resolve the observing scanner from an evidence row's finding data."""
    finding = row.get("finding_data")
    if isinstance(finding, Mapping):
        value = finding.get("scanner_id") or (finding.get("metadata") or {}).get("scanner_id")
        return str(value) if value else None
    return None
