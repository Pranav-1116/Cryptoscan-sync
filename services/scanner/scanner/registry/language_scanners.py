"""Language-specific scan runners used by the multi-language orchestrator."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.core.file_discovery import SHELL_NAMED_FILES as _SHELL_NAMED_FILES, is_named_config_file

from scanner.detectors.dotnet.assembly_scanner import scan_assembly
from scanner.detectors.java.jar_string_scanner import scan_class_file, scan_jar
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
from scanner.parsers.shell_parser import parse_shell_file
from scanner.parsers.sql_parser import parse_sql_file
from scanner.parsers.cobol_parser import parse_cobol_file
from scanner.parsers.pli_parser import parse_pli_file
from scanner.parsers.rpg_parser import parse_rpg_file
from scanner.parsers.natural_parser import parse_natural_file
from scanner.parsers.legacy_4gl_parser import parse_legacy_4gl_file
from scanner.parsers.runtime_log_parser import RUNTIME_LOG_EXT, parse_runtime_log_file
from scanner.detectors.mobile.mobile_binary_scanner import MOBILE_PACKAGE_EXT, scan_mobile_package
from scanner.parsers.mainframe_defs_parser import parse_mainframe_defs_file, looks_like_attls_policy
from scanner.parsers.swift_parser import parse_swift_file
from scanner.parsers.xml_parser import parse_xml_file
from scanner.parsers.tree_sitter_scanner import tree_sitter_enabled

JAVA_EXT = {".java"}
KOTLIN_EXT = {".kt", ".kts", ".gradle", ".groovy"}
SCALA_EXT = {".scala"}
PYTHON_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"}
CS_EXT = {".cs"}
GO_EXT = {".go"}
PHP_EXT = {".php"}
RUBY_EXT = {".rb"}
RUST_EXT = {".rs"}
SHELL_EXT = {".sh", ".bash", ".zsh", ".ksh"}
SWIFT_EXT = {".swift"}
SQL_EXT = {".sql", ".pls", ".plsql", ".pks", ".pkb", ".prc", ".fnc", ".trg", ".tsql", ".ddl", ".psql", ".pgsql", ".spb", ".sps", ".tps", ".tpb", ".bdy", ".spc"}
ASSEMBLY_EXT = {".dll", ".exe", ".netmodule", ".winmd"}
PLI_EXT = {".pli", ".pl1", ".plx", ".pls1"}
NATURAL_EXT = {".nsp", ".nsn", ".nss", ".nsh", ".nsc", ".nsl", ".nsa", ".nsg", ".nsm", ".nat"}
LEGACY_4GL_EXT = {".4gl", ".per", ".sru", ".srw", ".srf", ".sra", ".srd", ".srs", ".srm", ".srq", ".p", ".w", ".i", ".cls", ".tal", ".tacl", ".ptal", ".sas", ".hsm"}
MAINFRAME_DEF_EXT = {".csd", ".rdo", ".sit", ".proclib", ".hwscfg", ".ttls", ".pagent"}
RPG_EXT = {".rpgle", ".sqlrpgle", ".rpg", ".rpg38", ".rpg36", ".rpgleinc", ".rpginc", ".sqlrpg", ".clle", ".clp", ".cllp", ".clle38", ".cl"}
COBOL_EXT = {".cbl", ".cob", ".cobol", ".cpy", ".cblle", ".sqlcblle", ".cbl38", ".pco", ".sqb", ".ccp", ".jcl", ".proc", ".rexx", ".rex", ".asm"}
PLIST_EXT = {".plist", ".entitlements"}
XML_EXT = {".xml", ".config", ".csproj", ".props", ".targets", ".wsdl", ".xaml"}
C_EXT = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".m", ".mm"}
JAR_EXT = {".jar", ".war", ".ear", ".aar"}
CLASS_EXT = {".class"}
CONFIG_EXT = {".conf", ".cnf", ".yml", ".yaml", ".properties", ".env", ".ini", ".tf", ".tfvars", ".cfg", ".tmpl", ".tpl", ".j2", ".toml", ".mqsc", ".security", ".policy", ".settings"}

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
    (SHELL_EXT, parse_shell_file),
    (SWIFT_EXT, parse_swift_file),
    (SQL_EXT, parse_sql_file),
    (COBOL_EXT, parse_cobol_file),
    (PLI_EXT, parse_pli_file),
    (RPG_EXT, parse_rpg_file),
    (NATURAL_EXT, parse_natural_file),
    (MAINFRAME_DEF_EXT, parse_mainframe_defs_file),
    (LEGACY_4GL_EXT, parse_legacy_4gl_file),
    (RUNTIME_LOG_EXT, parse_runtime_log_file),
    (MOBILE_PACKAGE_EXT, scan_mobile_package),
    (PLIST_EXT, parse_swift_file),
    (XML_EXT, parse_xml_file),
    (C_EXT, parse_c_file),
    (JAR_EXT, scan_jar),
    (CLASS_EXT, scan_class_file),
    (ASSEMBLY_EXT, scan_assembly),
    (CONFIG_EXT, parse_config_file),
)


def _dedupe_against(base: list[RawFinding], extra: list[RawFinding]) -> list[RawFinding]:
    seen = {(f.source.line_number, f.crypto.algorithm.upper()) for f in base}
    return [f for f in extra if (f.source.line_number, f.crypto.algorithm.upper()) not in seen]


def scan_file(path: Path, repo_root: Path) -> list[RawFinding]:
    suffix = path.suffix.lower()
    findings: list[RawFinding] = []
    if suffix == ".props":
        # MSBuild .props is XML; WebSphere ssl.client.props / sas.client.props are Java properties
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:512].lstrip()
        except OSError:
            head = ""
        if not head.startswith("<"):
            return parse_config_file(path, repo_root)
    for extensions, parser in PARSERS:
        if suffix in extensions:
            findings = parser(path, repo_root)
            if extensions is C_EXT:
                findings = findings + _ibm_i_c_pass(path, repo_root, findings)
            if extensions is CONFIG_EXT:
                findings = findings + _attls_pass(path, repo_root, findings)
            if extensions in (CS_EXT, PYTHON_EXT, GO_EXT, C_EXT, JS_EXT, PHP_EXT, RUBY_EXT, RUST_EXT, SWIFT_EXT):
                findings = findings + _payments_pass(path, repo_root, findings)
            break
    else:
        if is_named_config_file(path.name):
            findings = parse_config_file(path, repo_root)
            if path.name.lower().startswith(("dockerfile", "containerfile")) or path.name.lower().endswith(".dockerfile"):
                # RUN lines are shell: openssl/keytool/curl -k live there too.
                findings = findings + _dedupe_against(findings, parse_shell_file(path, repo_root))
        elif path.name.lower() in _SHELL_NAMED_FILES:
            findings = parse_shell_file(path, repo_root)
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
        _tag_origin(path, repo_root, findings)
    return findings


def _ibm_i_c_pass(path: Path, repo_root: Path | None, findings: list[RawFinding]) -> list[RawFinding]:
    """ILE C on IBM i: Qc3*/QC3xxxxx and GSKit calls share the RPG rule table."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if "Qc3" not in text and "QC3" not in text and "gsk_" not in text and "GSK_" not in text:
        return []
    from scanner.parsers.rpg_parser import scan_ibm_i_in_c

    seen = {(f.source.line_number, (f.crypto.algorithm or "").upper()) for f in findings}
    return scan_ibm_i_in_c(path, repo_root, text, seen=seen)


def _tag_origin(path: Path, repo_root: Path | None, findings: list[RawFinding]) -> None:
    """Stamp metadata.code_origin (source/test/generated/vendored/archive) on every finding."""
    try:
        from scanner.core.code_origin import classify_origin

        origin = classify_origin(path, repo_root)
    except Exception:  # pragma: no cover - classification must never break a scan
        return
    for f in findings:
        try:
            if not getattr(f.metadata, "code_origin", None):
                f.metadata.code_origin = origin
        except Exception:  # pragma: no cover
            continue


_IANA_SUITE = re.compile(r"\b(?:TLS|SSL)_[A-Z0-9_]+_WITH_[A-Z0-9_]+|\bTLS_(?:AES_|CHACHA20_)")


_LANGUAGE_BY_EXT = {".cs": "CSHARP", ".py": "PYTHON", ".go": "GO", ".php": "PHP", ".rb": "RUBY", ".rs": "RUST", ".swift": "SWIFT", ".ts": "TYPESCRIPT", ".tsx": "TYPESCRIPT"}


def _payments_pass(path: Path, repo_root: Path | None, findings: list[RawFinding]) -> list[RawFinding]:
    """Payments / HSM / PKCS#11 vocabulary (payShield commands, DUKPT, TR-31, KCV, CKM_*) is the same
    in every language; the Java rule table already has it, so run that subset for the others."""
    from scanner.parsers.java_rules import run_payments_rules

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    suffix = path.suffix.lower()
    language = _LANGUAGE_BY_EXT.get(suffix) or ("JAVASCRIPT" if suffix in JS_EXT else "C" if suffix in C_EXT else suffix.lstrip(".").upper())
    seen = {(f.source.line_number, (f.crypto.algorithm or "").upper()) for f in findings}
    extra = run_payments_rules(path, repo_root, text, language, f"static-{language.lower()}-scanner-v1.0", seen=seen)
    # a primary finding on the same line with a *known* algorithm already covers an UNKNOWN hint
    known_lines = {f.source.line_number for f in findings if f.crypto.algorithm not in (None, "UNKNOWN")}
    return [f for f in extra if not (f.crypto.algorithm == "UNKNOWN" and f.source.line_number in known_lines)]


def _attls_pass(path: Path, repo_root: Path | None, findings: list[RawFinding]) -> list[RawFinding]:
    """AT-TLS Policy Agent files are usually named ``*.conf`` / ``*.policy``; when the content is a
    TTLS policy, run the mainframe-definition rules as well (deduped against the config pass)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if not looks_like_attls_policy(text):
        return []
    return _dedupe_against(findings, parse_mainframe_defs_file(path, repo_root, text=text))


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
            child = make_finding(
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
            child.source.type = f.source.type  # runtime-log parents stay runtime evidence
            child.source.code_snippet = f.source.code_snippet
            extra.append(child)
    return extra
