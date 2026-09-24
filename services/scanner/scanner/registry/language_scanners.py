"""Language-specific scan runners used by the multi-language orchestrator."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.core.file_discovery import is_named_config_file

from scanner.detectors.java.jar_string_scanner import scan_jar
from scanner.models.raw_finding import RawFinding
from scanner.parsers.c_parser import parse_c_file
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
from scanner.parsers.tree_sitter_scanner import tree_sitter_enabled

JAVA_EXT = {".java"}
KOTLIN_EXT = {".kt", ".kts"}
SCALA_EXT = {".scala"}
PYTHON_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
CS_EXT = {".cs"}
GO_EXT = {".go"}
PHP_EXT = {".php"}
RUBY_EXT = {".rb"}
RUST_EXT = {".rs"}
C_EXT = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".m", ".mm"}
JAR_EXT = {".jar"}
CONFIG_EXT = {".conf", ".cnf", ".yml", ".yaml", ".properties", ".env", ".ini", ".tf", ".tfvars", ".cfg"}

PARSERS = (
    (JAVA_EXT, parse_java_file),
    (KOTLIN_EXT, parse_kotlin_file),
    (SCALA_EXT, parse_kotlin_file),
    (PYTHON_EXT, parse_python_file),
    (JS_EXT, parse_javascript_file),
    (CS_EXT, parse_csharp_file),
    (GO_EXT, parse_go_file),
    (PHP_EXT, parse_php_file),
    (RUBY_EXT, parse_ruby_file),
    (RUST_EXT, parse_rust_file),
    (C_EXT, parse_c_file),
    (JAR_EXT, scan_jar),
    (CONFIG_EXT, parse_config_file),
)


def scan_file(path: Path, repo_root: Path) -> list[RawFinding]:
    suffix = path.suffix.lower()
    findings: list[RawFinding] = []
    for extensions, parser in PARSERS:
        if suffix in extensions:
            findings = parser(path, repo_root)
            break
    else:
        if is_named_config_file(path.name):
            findings = parse_config_file(path, repo_root)
    # Deep-parser pass (tree-sitter CST walker) — opt-in via
    # CRYPTOSCAN_TREE_SITTER=1; adds findings, never replaces the
    # deterministic baseline parsers.
    if tree_sitter_enabled():
        from scanner.parsers.tree_sitter_scanner import scan_tree_sitter_file

        extra = scan_tree_sitter_file(path, repo_root)
        if extra:
            findings = findings + extra
    if findings:
        findings = findings + _expand_cipher_suites(path, repo_root, findings)
    return findings


_IANA_SUITE = re.compile(r"\b(?:TLS|SSL)_[A-Z0-9_]+_WITH_[A-Z0-9_]+|\bTLS_(?:AES_|CHACHA20_)")


def _expand_cipher_suites(path: Path, repo_root: Path | None, findings: list[RawFinding]) -> list[RawFinding]:
    """Turn cipher-suite strings (``TLS-CIPHERS``/suite constants) into per-algorithm findings.

    A parser that sees ``ssl_ciphers RC4-SHA:DES-CBC3-SHA`` reports a single
    TLS-CIPHERS finding with the raw string; the inventory must also know RC4,
    3DES and SHA-1 are in use. Done once here so every language benefits.
    """
    try:
        from scanner.extractors.cipher_suites import looks_like_cipher_string, suite_components
        from scanner.parsers.finding_factory import make_finding
    except Exception:  # pragma: no cover
        return []
    have = {(f.source.line_number, (f.crypto.algorithm or "").upper()) for f in findings}
    extra: list[RawFinding] = []
    for f in findings:
        algo = (f.crypto.algorithm or "").upper()
        raw = f.crypto.raw_transformation or ""
        if algo != "TLS-CIPHERS" and not _IANA_SUITE.search(raw):
            continue
        if not looks_like_cipher_string(raw):
            continue
        for family, api_type in suite_components(raw):
            key = (f.source.line_number, family.upper())
            if key in have:
                continue
            have.add(key)
            extra.append(
                make_finding(
                    file_path=path,
                    repo_root=repo_root,
                    line_number=f.source.line_number,
                    language=f.source.language or "UNKNOWN",
                    api_type=api_type,
                    algorithm=family,
                    purpose="NETWORK_ENCRYPTION",
                    library=f.metadata.library or "tls-config",
                    scanner_id=f.scanner_id,
                    confidence="MEDIUM",
                    confidence_reason="cipher-suite-component",
                    raw_transformation=raw[:80],
                )
            )
    return extra
