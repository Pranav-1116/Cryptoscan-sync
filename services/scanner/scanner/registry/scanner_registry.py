"""Map source language → parser callable."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from scanner.detectors.java.jar_string_scanner import scan_jar
from scanner.models.raw_finding import RawFinding
from scanner.parsers.config_crypto_parser import parse_config_file
from scanner.parsers.csharp_parser import parse_csharp_file
from scanner.parsers.go_parser import parse_go_file
from scanner.parsers.java_parser import parse_java_file
from scanner.parsers.javascript_parser import parse_javascript_file
from scanner.parsers.kotlin_parser import parse_kotlin_file
from scanner.parsers.php_parser import parse_php_file
from scanner.parsers.python_parser import parse_python_file
from scanner.parsers.ruby_parser import parse_ruby_file
from scanner.parsers.rust_parser import parse_rust_file

Parser = Callable[[Path, Path | None], list[RawFinding]]

LANGUAGE_PARSERS: dict[str, Parser] = {
    "JAVA": parse_java_file,
    "KOTLIN": parse_kotlin_file,
    "SCALA": parse_kotlin_file,
    "CONFIG": parse_config_file,
    "PYTHON": parse_python_file,
    "JAVASCRIPT": parse_javascript_file,
    "TYPESCRIPT": parse_javascript_file,
    "CSHARP": parse_csharp_file,
    "GO": parse_go_file,
    "PHP": parse_php_file,
    "RUBY": parse_ruby_file,
    "RUST": parse_rust_file,
    "JAR": scan_jar,
}

EXTENSION_LANGUAGE: dict[str, str] = {
    ".java": "JAVA",
    ".kt": "KOTLIN",
    ".kts": "KOTLIN",
    ".scala": "SCALA",
    ".conf": "CONFIG",
    ".cnf": "CONFIG",
    ".yml": "CONFIG",
    ".yaml": "CONFIG",
    ".properties": "CONFIG",
    ".env": "CONFIG",
    ".ini": "CONFIG",
    ".tf": "CONFIG",
    ".tfvars": "CONFIG",
    ".cfg": "CONFIG",
    ".py": "PYTHON",
    ".js": "JAVASCRIPT",
    ".jsx": "JAVASCRIPT",
    ".mjs": "JAVASCRIPT",
    ".cjs": "JAVASCRIPT",
    ".ts": "TYPESCRIPT",
    ".tsx": "TYPESCRIPT",
    ".cs": "CSHARP",
    ".go": "GO",
    ".php": "PHP",
    ".rb": "RUBY",
    ".rs": "RUST",
    ".jar": "JAR",
}


def language_for_path(path: Path) -> str | None:
    return EXTENSION_LANGUAGE.get(path.suffix.lower())


def get_scanner_for_language(language: str) -> Parser | None:
    return LANGUAGE_PARSERS.get((language or "").upper())


def parse_path(path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    language = language_for_path(path)
    parser = get_scanner_for_language(language or "")
    if parser is None:
        return []
    return parser(path, repo_root)
