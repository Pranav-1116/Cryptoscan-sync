"""Run language-specific detectors over a discovered file set."""

from __future__ import annotations

from pathlib import Path

from scanner.core.file_discovery import FileDiscovery
from scanner.core.language_detector import detect_languages_in_repo
from scanner.models.raw_finding import RawFinding
from scanner.parsers.parse_error_handler import safe_parse
from scanner.parsers.csharp_parser import parse_csharp_file
from scanner.parsers.go_parser import parse_go_file
from scanner.parsers.java_parser import parse_java_file
from scanner.parsers.javascript_parser import parse_javascript_file
from scanner.parsers.php_parser import parse_php_file
from scanner.parsers.python_parser import parse_python_file
from scanner.parsers.ruby_parser import parse_ruby_file
from scanner.parsers.rust_parser import parse_rust_file

PARSERS = {
    ".java": parse_java_file,
    ".py": parse_python_file,
    ".js": parse_javascript_file,
    ".jsx": parse_javascript_file,
    ".mjs": parse_javascript_file,
    ".cjs": parse_javascript_file,
    ".ts": parse_javascript_file,
    ".tsx": parse_javascript_file,
    ".cs": parse_csharp_file,
    ".go": parse_go_file,
    ".php": parse_php_file,
    ".rb": parse_ruby_file,
    ".rs": parse_rust_file,
}


def run_language_detectors(root_path: str | Path) -> tuple[list[RawFinding], list[dict], list[str]]:
    root = Path(root_path)
    languages = detect_languages_in_repo(root)
    findings: list[RawFinding] = []
    errors: list[dict] = []
    for path in FileDiscovery().discover(root):
        parser = PARSERS.get(path.suffix.lower())
        if parser is None:
            continue
        parsed, error = safe_parse(parser, path, root)
        findings.extend(parsed)
        if error:
            errors.append(error)
    return findings, errors, languages
