"""Language-specific scan runners used by the multi-language orchestrator."""

from __future__ import annotations

from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.csharp_parser import parse_csharp_file
from scanner.parsers.java_parser import parse_java_file
from scanner.parsers.javascript_parser import parse_javascript_file
from scanner.parsers.python_parser import parse_python_file

JAVA_EXT = {".java"}
PYTHON_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
CS_EXT = {".cs"}

PARSERS = (
    (JAVA_EXT, parse_java_file),
    (PYTHON_EXT, parse_python_file),
    (JS_EXT, parse_javascript_file),
    (CS_EXT, parse_csharp_file),
)


def scan_file(path: Path, repo_root: Path) -> list[RawFinding]:
    suffix = path.suffix.lower()
    for extensions, parser in PARSERS:
        if suffix in extensions:
            return parser(path, repo_root)
    return []
