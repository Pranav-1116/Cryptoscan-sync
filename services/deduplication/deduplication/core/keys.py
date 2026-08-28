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


def _registry_canonical(algorithm: str) -> str:
    """Canonical name from the shared registry; honest upper-case fallback."""
    try:
        from shared_models.algorithm_registry import parse_algorithm

        info = parse_algorithm(algorithm or "")
        if info.recognized:
            return info.canonical
    except Exception:
        pass
    return str(algorithm or "").upper() or "UNKNOWN"


def _key_size(finding: dict[str, Any]) -> int | None:
    raw = _get(finding, "crypto", "key_size") or finding.get("key_size")
    if raw is None:
        # sizes embedded in the name (RSA-2048 / aes_128) count when the
        # finding itself did not carry an explicit field
        try:
            from shared_models.algorithm_registry import parse_algorithm

            info = parse_algorithm(_get(finding, "crypto", "algorithm") or finding.get("algorithm") or "")
            if info.recognized:
                return info.key_size
        except Exception:
            pass
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def canonical_identity_tuple(finding: dict[str, Any]) -> tuple[str, str, int | None, str, int]:
    """Registry-canonical identity: same crypto from two scanners merges.

    "RSA-2048" and "rsa_2048" collapse to (RSA, 2048, ...); genuinely
    different strengths stay distinct (AES-128 vs AES-256), and an
    unspecified size never merges with a specified one (RSA vs RSA-2048).
    """
    algorithm = str(
        _get(finding, "crypto", "algorithm") or finding.get("algorithm") or "UNKNOWN"
    )
    purpose = str(_get(finding, "crypto", "purpose") or finding.get("purpose") or "UNKNOWN").upper()
    file_path = str(_get(finding, "source", "file_path") or finding.get("file_path") or "")
    line = int(_get(finding, "source", "line_number") or finding.get("line_number") or 0)
    return _registry_canonical(algorithm), purpose, _key_size(finding), file_path, line


def canonical_identity_material(finding: dict[str, Any]) -> str:
    algorithm, purpose, key_size, file_path, line = canonical_identity_tuple(finding)
    return f"{algorithm}|{purpose}|{key_size}|{file_path}|{line}"


def canonical_dedup_key(finding: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_identity_material(finding).encode("utf-8")).hexdigest()


def identity_material(finding: dict[str, Any]) -> str:
    algorithm, purpose, file_path, line = identity_tuple(finding)
    return f"{algorithm}|{purpose}|{file_path}|{line}"


def dedup_key(finding: dict[str, Any]) -> str:
    return hashlib.sha256(identity_material(finding).encode("utf-8")).hexdigest()
