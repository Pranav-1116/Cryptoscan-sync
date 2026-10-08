"""Public, evidence-safe projection of detector observations.

Detectors may need raw source text while analysing a file. It must not cross the
scanner/output/evidence boundary: even an unrelated context line may be a secret.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_TOP_LEVEL = frozenset({
    "finding_id", "scan_timestamp", "scanner_id", "scanner_version",
    "algorithm", "api_type", "mode", "padding", "key_size", "purpose",
    "file_path", "line_number", "class_name", "method_name", "confidence",
    "severity", "is_hardcoded_key", "hardcoded_key_length", "code_origin",
    "protocol", "resource_id", "provider", "region", "finding_type",
})
_SOURCE = frozenset({
    "type", "language", "file_path", "line_number", "column_number",
    "method_name", "class_name", "variable_name", "is_in_try_catch",
    "src_ip", "dst_ip", "src_port", "dst_port",
})
_CRYPTO = frozenset({
    "api_type", "algorithm", "mode", "padding", "key_size", "purpose",
    "encryption", "authentication",
})
_HASH_FAMILIES = (
    ("SHA512", "SHA-512"), ("SHA384", "SHA-384"),
    ("SHA256", "SHA-256"), ("SHA224", "SHA-224"),
    ("SHA1", "SHA-1"), ("MD5", "MD5"),
)
_METADATA = frozenset({
    "confidence", "library", "is_hardcoded_key", "hardcoded_key_length",
    "code_origin",
})
_GIT = frozenset({"commit_hash", "commit_timestamp", "branch"})
_INVENTORY = frozenset({
    "key_label", "key_store", "object_class", "usage", "access", "state",
    "exportable", "exportability", "extractable", "weak_binding",
    "key_block_version", "last_used", "key_size", "algorithm", "subject", "issuer",
    "fingerprint", "fingerprint_sha256", "serial_number", "not_before",
    "not_after", "self_signed", "role", "entry_type", "signature_algorithm",
    "created_at", "last_rotated_at", "application",
})


def _select(data: Any, allowed: frozenset[str]) -> dict[str, Any]:
    if not isinstance(data, Mapping):
        return {}
    result = {}
    for key in allowed:
        if key not in data:
            continue
        value = data[key]
        if value is None or isinstance(value, (str, int, float, bool)):
            result[key] = value.replace("\x00", "") if isinstance(value, str) else value
    return result


def _hash_family(value: Any) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9/_:.+\-]{1,120}", value):
        return None
    normalized = value.upper().replace("-", "").replace("_", "")
    for token, family in _HASH_FAMILIES:
        if token in normalized:
            return family
    return None


def safe_finding(data: Mapping[str, Any]) -> dict[str, Any]:
    """Keep structured crypto facts, never snippets or arbitrary detector extras.

    Return a new object so a response projection cannot mutate a mapped JSON
    column or change an existing record's content commitment.
    """
    if not isinstance(data, Mapping):
        raise TypeError("evidence findings must be structured mappings")
    result = _select(data, _TOP_LEVEL)
    scopes = data.get("compliance_scopes")
    if isinstance(scopes, list):
        result["compliance_scopes"] = [scope for scope in scopes
                                       if isinstance(scope, str) and re.fullmatch(r"[A-Z0-9_.-]{1,64}", scope)]
    for key, fields in (("source", _SOURCE), ("crypto", _CRYPTO),
                        ("git_context", _GIT), ("inventory", _INVENTORY)):
        if key in data:
            result[key] = _select(data[key], fields)
    crypto = data.get("crypto")
    if isinstance(crypto, Mapping):
        family = _hash_family(crypto.get("hash_algorithm")) or _hash_family(crypto.get("raw_transformation"))
        if family:
            result.setdefault("crypto", {})["hash_algorithm"] = family
    if "metadata" in data:
        result["metadata"] = _select(data["metadata"], _METADATA)
        reason = data["metadata"].get("confidence_reason") if isinstance(data["metadata"], Mapping) else None
        if reason is not None:
            result["metadata"]["confidence_reason"] = (
                "algorithm resolved from cross-file constant"
                if isinstance(reason, str) and reason.startswith("algorithm resolved from cross-file constant")
                else "structured-observation"
            )
    return result
