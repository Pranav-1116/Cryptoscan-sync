"""Spec-named JavaScript/TypeScript parser entry (tree-sitter-free regex)."""

from __future__ import annotations

from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.javascript_parser import parse_javascript_file

SCANNER_ID = "static-js-scanner-v1.0"


def parse_js_ts_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    """Parse .js / .jsx / .ts / .tsx / .mjs / .cjs using the JavaScript detector."""
    return parse_javascript_file(file_path, repo_root)


def parse_javascript_or_typescript(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    return parse_js_ts_file(file_path, repo_root)


__all__ = ["parse_js_ts_file", "parse_javascript_or_typescript", "SCANNER_ID"]
