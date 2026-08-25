"""Detect BouncyCastle.Net usage."""

from __future__ import annotations

from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.csharp_parser import parse_csharp_file


def detect(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    return [
        finding
        for finding in parse_csharp_file(file_path, repo_root)
        if "bouncycastle" in (finding.metadata.library or "").lower()
        or "BouncyCastle" in (finding.source.code_snippet or "")
    ]
