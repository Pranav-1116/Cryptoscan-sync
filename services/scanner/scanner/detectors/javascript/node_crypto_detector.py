"""Detect Node.js crypto module usage."""

from __future__ import annotations

from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.javascript_parser import parse_javascript_file


def detect(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    return [
        finding
        for finding in parse_javascript_file(file_path, repo_root)
        if (finding.metadata.library or "").lower() in {"node-crypto", "crypto"}
        or "createCipher" in (finding.source.code_snippet or "")
        or "createHash" in (finding.source.code_snippet or "")
    ]
