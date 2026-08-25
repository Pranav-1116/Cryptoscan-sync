"""Build the sorted component list used by the spec dedup-key formula."""

from __future__ import annotations

from typing import Any

from deduplication.fingerprinting.location_normalizer import location_key


def build_components(finding: dict[str, Any], *, repo_root: str | None = None) -> list[str]:
    crypto = finding.get("crypto") if isinstance(finding.get("crypto"), dict) else {}
    algorithm = str(crypto.get("algorithm") or finding.get("algorithm") or "UNKNOWN")
    mode = str(crypto.get("mode") or finding.get("mode") or "DEFAULT")
    key_size = crypto.get("key_size") if crypto.get("key_size") is not None else finding.get("key_size")
    purpose = str(crypto.get("purpose") or finding.get("purpose") or "UNKNOWN")
    return [
        algorithm,
        mode or "DEFAULT",
        str(key_size or "UNKNOWN"),
        purpose,
        location_key(finding, repo_root=repo_root),
    ]


def canonical_components(finding: dict[str, Any], *, repo_root: str | None = None) -> str:
    return "|".join(build_components(finding, repo_root=repo_root))
