"""Stable identity key and SHA-256 fingerprint for a cryptographic asset."""

from __future__ import annotations

import hashlib
from typing import Any


def _get(finding: dict[str, Any], *path: str, default: Any = None) -> Any:
    current: Any = finding
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return default if current is None else current


def identity_tuple(finding: dict[str, Any]) -> tuple[str, str, str, int]:
    algorithm = str(
        _get(finding, "crypto", "algorithm") or finding.get("algorithm") or "UNKNOWN"
    ).upper()
    purpose = str(_get(finding, "crypto", "purpose") or finding.get("purpose") or "UNKNOWN").upper()
    file_path = str(_get(finding, "source", "file_path") or finding.get("file_path") or "")
    line = int(_get(finding, "source", "line_number") or finding.get("line_number") or 0)
    return algorithm, purpose, file_path, line


def identity_material(finding: dict[str, Any]) -> str:
    algorithm, purpose, file_path, line = identity_tuple(finding)
    return f"{algorithm}|{purpose}|{file_path}|{line}"


def dedup_key(finding: dict[str, Any]) -> str:
    return hashlib.sha256(identity_material(finding).encode("utf-8")).hexdigest()
