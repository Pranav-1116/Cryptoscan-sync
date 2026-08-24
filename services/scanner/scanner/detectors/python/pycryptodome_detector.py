from __future__ import annotations

from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.python_parser import parse_python_file


def detect(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    return [
        finding
        for finding in parse_python_file(file_path, repo_root)
        if (finding.metadata.library or "").lower() in {"pycryptodome", "pycrypto"}
    ]
