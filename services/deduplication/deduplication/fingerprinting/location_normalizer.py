"""Normalize file paths and container locations for dedup keys."""

from __future__ import annotations

from pathlib import Path
from typing import Any


CONTAINER_TYPES = {
    "CONTAINER",
    "CONTAINER_IMAGE",
    "CONTAINER_PACKAGE",
    "CONTAINER_BINARY",
    "CONTAINER_VULN",
}


def normalize_file_path(
    path: str | None,
    *,
    repo_root: str | Path | None = None,
    source_type: str | None = None,
) -> str:
    if source_type and str(source_type).upper() in CONTAINER_TYPES:
        return "CONTAINER"
    raw = str(path or "").replace("\\", "/").strip()
    if not raw:
        return ""
    if repo_root:
        root = str(Path(repo_root)).replace("\\", "/").rstrip("/")
        if raw.startswith(root + "/"):
            raw = raw[len(root) + 1 :]
        elif raw.startswith(root):
            raw = raw[len(root) :].lstrip("/")
    while raw.startswith("./"):
        raw = raw[2:]
    return raw.lstrip("/")


def location_key(finding: dict[str, Any], *, repo_root: str | Path | None = None) -> str:
    source = finding.get("source") if isinstance(finding.get("source"), dict) else {}
    source_type = source.get("type") or finding.get("source_type")
    path = source.get("file_path") or finding.get("file_path")
    return normalize_file_path(path, repo_root=repo_root, source_type=source_type)
