"""Flag insecure PRNG / secrets misuse in Python source."""

from __future__ import annotations

from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.python_parser import parse_python_file


def detect(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    findings = parse_python_file(file_path, repo_root)
    return [
        finding
        for finding in findings
        if (finding.crypto.algorithm or "") == "PRNG"
        or (finding.metadata.library or "") == "random"
        or (finding.crypto.api_type or "") == "HARDCODED_KEY"
    ]
