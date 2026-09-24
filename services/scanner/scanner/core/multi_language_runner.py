"""Run language-specific detectors over a discovered file set."""

from __future__ import annotations

from pathlib import Path

from scanner.core.file_discovery import FileDiscovery
from scanner.core.language_detector import detect_languages_in_repo
from scanner.models.raw_finding import RawFinding
from scanner.parsers.parse_error_handler import safe_parse
from scanner.parsers.config_crypto_parser import parse_config_file
from scanner.parsers.c_parser import parse_c_file
from scanner.parsers.csharp_parser import parse_csharp_file
from scanner.parsers.go_parser import parse_go_file
from scanner.parsers.java_parser import parse_java_file
from scanner.parsers.javascript_parser import parse_javascript_file
from scanner.parsers.kotlin_parser import parse_kotlin_file
from scanner.parsers.php_parser import parse_php_file
from scanner.parsers.python_parser import parse_python_file
from scanner.parsers.ruby_parser import parse_ruby_file
from scanner.parsers.rust_parser import parse_rust_file

PARSERS = {
    ".java": parse_java_file,
    ".kt": parse_kotlin_file,
    ".kts": parse_kotlin_file,
    ".scala": parse_kotlin_file,
    ".conf": parse_config_file,
    ".yml": parse_config_file,
    ".yaml": parse_config_file,
    ".tf": parse_config_file,
    ".env": parse_config_file,
    ".properties": parse_config_file,
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
    ".c": parse_c_file,
    ".h": parse_c_file,
    ".cpp": parse_c_file,
    ".cc": parse_c_file,
    ".cxx": parse_c_file,
    ".hpp": parse_c_file,
    ".hh": parse_c_file,
    ".hxx": parse_c_file,
    ".m": parse_c_file,
    ".mm": parse_c_file,
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
