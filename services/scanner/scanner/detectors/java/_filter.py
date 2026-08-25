"""Filter JavaParser findings by API type."""

from __future__ import annotations

from pathlib import Path

from scanner.parsers.java_parser import JavaParser


def detect_api(file_path, api_type: str, repo_root=None):
    path = Path(file_path)
    root = Path(repo_root) if repo_root else path.parent
    findings = JavaParser(root).parse_file(path)
    return [item for item in findings if getattr(getattr(item, "crypto", None), "api_type", None) == api_type]
