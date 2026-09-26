"""
Java source code parser using regex-based AST analysis.

This module wraps the Eclipse JDT Java parser (called via subprocess)
or uses a pure-Python regex fallback for simpler cases.

Architecture:
  - Primary: Eclipse JDT via JAR subprocess call (production)
  - Fallback: Regex-based pattern matching (development/testing)

Regex matching is the built-in detector. JDT integration is additive when the helper JAR is on PATH.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import structlog

from scanner.extractors.algorithm_extractor import known_algorithm_or_unknown, parse_transformation
from scanner.extractors.confidence_calculator import calculate_confidence
from scanner.extractors.snippet_extractor import extract_snippet
from scanner.models.enums import ApiType, Purpose
from scanner.models.raw_finding import (
    RawFinding,
    SourceLocation,
    CryptoInfo,
    FindingMetadata,
)

logger = structlog.get_logger(__name__)


class JavaSyntaxError(ValueError):
    """Raised when a Java source file fails shallow syntax validation."""


def strip_java_strings_and_comments(source: str) -> str:
    """Blank out string/char literals and comments, preserving newlines.

    A tiny state machine — enough for brace balancing without counting
    braces that appear inside string literals (e.g. ``"{"``) or comments.
    """
    out: list[str] = []
    mode = "code"  # code | line_comment | block_comment | string | char
    i, n = 0, len(source)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if mode == "code":
            if ch == "/" and nxt == "/":
                mode = "line_comment"
                i += 2
            elif ch == "/" and nxt == "*":
                mode = "block_comment"
                i += 2
            elif ch == '"':
                mode = "string"
                i += 1
            elif ch == "'":
                mode = "char"
                i += 1
            else:
                out.append(ch)
                i += 1
        elif mode == "line_comment":
            if ch == "\n":
                out.append("\n")
                mode = "code"
            i += 1
        elif mode == "block_comment":
            if ch == "*" and nxt == "/":
                mode = "code"
                i += 2
            else:
                if ch == "\n":
                    out.append("\n")
                i += 1
        elif mode in ("string", "char"):
            quote = '"' if mode == "string" else "'"
            if ch == "\\":
                i += 2
            elif ch == quote or ch == "\n":
                # Unterminated literal ends at newline — treat as code again.
                mode = "code"
                i += 1
            else:
                i += 1
    return "".join(out)


def validate_java_syntax(source: str) -> None:
    """Shallow validation: brace balance over comment/string-stripped source."""
    stripped = strip_java_strings_and_comments(source)
    opens, closes = stripped.count("{"), stripped.count("}")
    if opens != closes:
        raise JavaSyntaxError(f"Unbalanced braces: {opens} '{{' vs {closes} '}}'")

# ============================================================
# Regex Patterns for Java Crypto API Detection
# ============================================================

# Pattern 1: Cipher.getInstance("AES/GCM/NoPadding")
CIPHER_GETINSTANCE = re.compile(
    r"""Cipher\.getInstance\s*\(\s*["']([^"']+)["']\s*[,)]""",
    re.MULTILINE
)
CIPHER_GETINSTANCE_VAR = re.compile(
    r"""Cipher\.getInstance\s*\(\s*(\w+)\s*[,)]""",
    re.MULTILINE
)

# Pattern 2: MessageDigest.getInstance("SHA-256")
MESSAGEDIGEST_GETINSTANCE = re.compile(
    r"""MessageDigest\.getInstance\s*\(\s*["']([^"']+)["']\s*[,)]""",
    re.MULTILINE
)
MESSAGEDIGEST_GETINSTANCE_VAR = re.compile(
    r"""MessageDigest\.getInstance\s*\(\s*(\w+)\s*[,)]""",
    re.MULTILINE
)

# Pattern 3: KeyGenerator.getInstance("AES")
KEYGENERATOR_GETINSTANCE = re.compile(
    r"""KeyGenerator\.getInstance\s*\(\s*["']([^"']+)["']\s*[,)]""",
    re.MULTILINE
)
KEYGENERATOR_GETINSTANCE_VAR = re.compile(
    r"""KeyGenerator\.getInstance\s*\(\s*(\w+)\s*[,)]""",
    re.MULTILINE
)

# Pattern 4: Signature.getInstance("SHA256withRSA")
SIGNATURE_GETINSTANCE = re.compile(
    r"""Signature\.getInstance\s*\(\s*["']([^"']+)["']\s*[,)]""",
    re.MULTILINE
)
SIGNATURE_GETINSTANCE_VAR = re.compile(
    r"""Signature\.getInstance\s*\(\s*(\w+)\s*[,)]""",
    re.MULTILINE
)

# Pattern 6: Mac.getInstance("HmacSHA256")
MAC_GETINSTANCE = re.compile(
    r"""Mac\.getInstance\s*\(\s*["']([^"']+)["']\s*[,)]""",
    re.MULTILINE,
)
MAC_GETINSTANCE_VAR = re.compile(
    r"""Mac\.getInstance\s*\(\s*(\w+)\s*[,)]""",
    re.MULTILINE,
)

# Pattern 5: SecretKeySpec(key, "AES") — potential hardcoded key
SECRETKEYSPEC_LITERAL = re.compile(
    r"""new\s+(?:[\w.]+\.)?SecretKeySpec\s*\(\s*(?:new\s+byte\[\]\s*\{[^}]+\}|"[^"]*"\.getBytes[^)]*\)|[^,]+)\s*,\s*["']([^"']+)["']\s*\)""",
    re.MULTILINE | re.DOTALL
)

# Detect hardcoded byte arrays: new byte[]{0x01, 0x02, ...}
HARDCODED_BYTE_ARRAY = re.compile(
    r"""new\s+(?:[\w.]+\.)?SecretKeySpec\s*\(\s*new\s+byte\[\]\s*\{([^}]+)\}""",
    re.MULTILINE | re.DOTALL
)

# Detect string-based keys: "mySecretKey".getBytes()
HARDCODED_STRING_KEY = re.compile(
    r"""new\s+(?:[\w.]+\.)?SecretKeySpec\s*\(\s*"([^"]+)"\.getBytes""",
    re.MULTILINE
)

# KeyGenerator init size: kg.init(256)
KEYGENERATOR_INIT = re.compile(
    r"""\.init\s*\(\s*(\d+)\s*[,)]""",
    re.MULTILINE
)

# KeyPairGenerator.getInstance("RSA") + initialize(2048)
KEYPAIRGENERATOR_GETINSTANCE = re.compile(
    r"""KeyPairGenerator\.getInstance\s*\(\s*["']([^"']+)["']\s*[,)]""",
    re.MULTILINE,
)
KEYPAIRGENERATOR_INIT = re.compile(
    r"""\.initialize\s*\(\s*(\d+)\s*[,)]""",
    re.MULTILINE,
)

# Method context detection
METHOD_DECLARATION = re.compile(
    r"""(?:public|private|protected|static|final|synchronized|\s)+\s+\w[\w<>,\s]*\s+(\w+)\s*\([^)]*\)\s*(?:throws[^{]*)?\s*\{""",
    re.MULTILINE
)

# Class declaration
CLASS_DECLARATION = re.compile(
    r"""(?:public|private|protected|abstract|final|static|\s)*\s+(?:class|interface|enum)\s+(\w+)""",
    re.MULTILINE
)

# Package declaration
PACKAGE_DECLARATION = re.compile(r"""^\s*package\s+([\w.]+)\s*;""", re.MULTILINE)

# Try-catch block detection (simple heuristic)
TRY_CATCH = re.compile(r"""\btry\s*\{""", re.MULTILINE)

# Pattern 7: SSLContext / KeyStore / KeyAgreement / SecureRandom / PBEKeySpec
SSLCONTEXT_GETINSTANCE = re.compile(
    r"""SSLContext\.getInstance\s*\(\s*[\"']([^\"']+)[\"']\s*[,)]""",
    re.MULTILINE,
)
KEYSTORE_GETINSTANCE = re.compile(
    r"""KeyStore\.getInstance\s*\(\s*[\"']([^\"']+)[\"']\s*[,)]""",
    re.MULTILINE,
)
# JEP 496: javax.crypto.KEM.getInstance("ML-KEM") is the FIPS 203 key-encapsulation entry point (also "DHKEM")
KEYAGREEMENT_GETINSTANCE = re.compile(
    r"""(?:KeyAgreement|KEM)\.getInstance\s*\(\s*[\"']([^\"']+)[\"']\s*[,)]""",
    re.MULTILINE,
)
SECURERANDOM_GETINSTANCE = re.compile(
    r"""SecureRandom\.getInstance\s*\(\s*[\"']([^\"']+)[\"']\s*[,)]""",
    re.MULTILINE,
)
PBEKEYSPEC = re.compile(r"""new\s+PBEKeySpec\s*\(""", re.MULTILINE)
BC_PROVIDER = re.compile(
    r"""(?:Cipher|MessageDigest|KeyGenerator|Signature|Mac)\.getInstance\s*\(\s*[\"'][^\"']+[\"']\s*,\s*[\"']BC[\"']""",
    re.MULTILINE,
)
HOSTNAME_VERIFIER = re.compile(
    r"""(?:setHostnameVerifier|setDefaultHostnameVerifier)\s*\(""",
    re.MULTILINE,
)
ALLOW_ALL_HOSTS = re.compile(
    r"""ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|TrustAll(?:Host|Trust)?""",
    re.MULTILINE,
)
EMPTY_TRUST_MANAGER = re.compile(
    r"""checkServerTrusted\s*\([^)]*\)\s*\{\s*\}""",
    re.MULTILINE,
)


@dataclass
class ParseContext:
    """Context extracted from a Java file for enriching findings."""
    file_path: Path
    package: Optional[str] = None
    class_name: Optional[str] = None
    source_lines: list[str] = field(default_factory=list)


class JavaParser:
    """
    Regex-based Java source code parser for crypto API detection.
    
    Implements the Java crypto detector patterns defined in the scanner spec.
    Uses line-by-line analysis for accurate line number extraction.
    """

    def __init__(self, repo_root: Optional[Path] = None):
        self._repo_root = repo_root

    def parse_file(self, file_path: Path, source: str | None = None) -> list[RawFinding]:
        """
        Parse a single Java file and return all crypto findings.

        Primary path is the token/AST walker. Regex detectors remain as
        fail-open fallback so a single unreadable construct cannot drop the file.
        """
        log = logger.bind(file=str(file_path))

        if source is None:
            try:
                source = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                log.error("cannot_read_file", error=str(e))
                raise

        source_lines = source.splitlines()
        context = self._extract_file_context(file_path, source, source_lines)
        try:
            validate_java_syntax(source)
        except JavaSyntaxError as exc:
            # Kotlin char literals / string templates and generated code trip the shallow
            # brace check. Never drop the file: the regex path still sees the API calls.
            log.warning("java_syntax_regex_fallback", error=str(exc))
            return self._parse_with_regex(file_path, source, source_lines, context, log)
        try:
            from scanner.parsers.java_ast import extract_crypto_events

            findings = [
                self._finding_from_event(event, source, source_lines, context) for event in extract_crypto_events(source)
            ]
            findings.extend(self._detect_insecure_tls(source, source_lines, context))
            self._mark_bouncycastle(source, findings)
            findings.extend(self._supplementary_rules(file_path, source, findings))
            log.debug("file_parsed_ast", findings_count=len(findings))
            return findings
        except Exception as exc:
            log.warning("java_ast_fallback", error=str(exc))
            return self._parse_with_regex(file_path, source, source_lines, context, log)

    def _finding_from_event(self, event, source: str, source_lines: list[str], context: ParseContext) -> RawFinding:
        return self._build_finding(
            file_path=context.file_path,
            source=source,
            source_lines=source_lines,
            match_start=event.start,
            context=context,
            api_type=event.api_type,
            algorithm=event.algorithm or "UNKNOWN",
            mode=event.mode,
            padding=event.padding,
            key_size=event.key_size,
            purpose=event.purpose,
            library=event.library,
            is_string_literal=event.is_string_literal,
            is_hardcoded_key=event.is_hardcoded_key,
            hardcoded_key_length=event.hardcoded_key_length,
            variable_name=event.variable_name,
            raw_transformation=event.raw_transformation,
            is_from_local_variable=event.is_from_local_variable,
        )

    def _parse_with_regex(
        self, file_path: Path, source: str, source_lines: list[str], context: ParseContext, log
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []
        findings.extend(self._detect_cipher(source, source_lines, context))
        findings.extend(self._detect_message_digest(source, source_lines, context))
        findings.extend(self._detect_key_generator(source, source_lines, context))
        findings.extend(self._detect_key_pair_generator(source, source_lines, context))
        findings.extend(self._detect_signature(source, source_lines, context))
        findings.extend(self._detect_mac(source, source_lines, context))
        findings.extend(self._detect_hardcoded_keys(source, source_lines, context))
        findings.extend(self._detect_tls_and_keystore(source, source_lines, context))
        findings.extend(self._detect_key_agreement(source, source_lines, context))
        findings.extend(self._detect_secure_random(source, source_lines, context))
        findings.extend(self._detect_pbe(source, source_lines, context))
        findings.extend(self._detect_insecure_tls(source, source_lines, context))
        self._mark_bouncycastle(source, findings)
        findings.extend(self._supplementary_rules(file_path, source, findings))
        log.debug("file_parsed", findings_count=len(findings))
        return findings

    def _supplementary_rules(self, file_path: Path, source: str, existing: list[RawFinding]) -> list[RawFinding]:
        """Library APIs that never pass through a JCA getInstance string."""
        try:
            from scanner.parsers.java_rules import run_java_rules

            seen = {(f.source.line_number, (f.crypto.algorithm or "").upper()) for f in existing}
            return run_java_rules(file_path, self._repo_root, source, "JAVA", "static-java-scanner-v0.1", seen=seen)
        except Exception as exc:  # pragma: no cover - never let the extra pass break the parser
            logger.warning("java_supplementary_rules_failed", file=str(file_path), error=str(exc))
            return []

    def _extract_file_context(
        self, file_path: Path, source: str, source_lines: list[str]
    ) -> ParseContext:
        """Extract package and class name from source."""
        context = ParseContext(file_path=file_path, source_lines=source_lines)

        package_match = PACKAGE_DECLARATION.search(source)
        if package_match:
            context.package = package_match.group(1)

        class_match = CLASS_DECLARATION.search(source)
        if class_match:
            class_name = class_match.group(1)
            context.class_name = (
                f"{context.package}.{class_name}" if context.package else class_name
            )

        return context

    def _get_line_number(self, source: str, match_start: int) -> int:
        """Get 1-indexed line number for a match position."""
        return source[:match_start].count("\n") + 1

    def _get_method_at_line(self, source: str, line_number: int) -> Optional[str]:
        """Find the method name containing the given line (best effort)."""
        # Find all method declarations before this line
        source_to_line = "\n".join(source.splitlines()[:line_number])
        matches = list(METHOD_DECLARATION.finditer(source_to_line))
        if matches:
            return matches[-1].group(1)
        return None

    def _is_in_try_catch(self, source: str, match_start: int) -> bool:
        """Check if position is inside a try block (heuristic)."""
        preceding = source[:match_start]
        try_count = len(TRY_CATCH.findall(preceding))
        close_brace_count = preceding.count("}")
        # Simple heuristic: more opens than closes suggests we're in a try
        return try_count > 0 and try_count > (close_brace_count // 3)

    def _make_relative_path(self, file_path: Path) -> str:
        """Return path relative to repo root if available."""
        if self._repo_root:
            try:
                return str(file_path.relative_to(self._repo_root))
            except ValueError:
                pass
        return str(file_path)

    def _build_finding(
        self,
        *,
        file_path: Path,
        source: str,
        source_lines: list[str],
        match_start: int,
        context: ParseContext,
        api_type: str,
        algorithm: Optional[str],
        mode: Optional[str] = None,
        padding: Optional[str] = None,
        key_size: Optional[int] = None,
        purpose: str,
        library: str,
        is_string_literal: bool,
        is_hardcoded_key: bool = False,
        hardcoded_key_length: Optional[int] = None,
        variable_name: Optional[str] = None,
        raw_transformation: Optional[str] = None,
        is_from_local_variable: bool = False,
    ) -> RawFinding:
        """Build a complete RawFinding from detection results."""
        line_number = self._get_line_number(source, match_start)
        method_name = self._get_method_at_line(source, line_number)
        in_try_catch = self._is_in_try_catch(source, match_start)
        snippet = extract_snippet(file_path, line_number)
        relative_path = self._make_relative_path(file_path)

        confidence_result = calculate_confidence(
            is_string_literal=is_string_literal,
            is_from_local_variable=is_from_local_variable,
            is_hardcoded=is_hardcoded_key,
        )

        return RawFinding(
            source=SourceLocation(
                file_path=relative_path,
                line_number=line_number,
                method_name=method_name,
                class_name=context.class_name,
                code_snippet=snippet,
                variable_name=variable_name,
                is_in_try_catch=in_try_catch,
            ),
            crypto=CryptoInfo(
                api_type=api_type,
                algorithm=algorithm,
                mode=mode,
                padding=padding,
                key_size=key_size,
                purpose=purpose,
                raw_transformation=raw_transformation,
            ),
            metadata=FindingMetadata(
                confidence=confidence_result.level.value,
                confidence_reason=confidence_result.reason,
                library=library,
                is_hardcoded_key=is_hardcoded_key,
                hardcoded_key_length=hardcoded_key_length,
            ),
        )

    # ============================================================
    # Pattern 1: javax.crypto.Cipher
    # ============================================================

    def _detect_cipher(
        self, source: str, source_lines: list[str], context: ParseContext
    ) -> list[RawFinding]:
        """Detect Cipher.getInstance() calls."""
        findings = []

        # String literal matches (HIGH confidence)
        for match in CIPHER_GETINSTANCE.finditer(source):
            transformation = match.group(1)
            parsed = parse_transformation(transformation)

            finding = self._build_finding(
                file_path=context.file_path,
                source=source,
                source_lines=source_lines,
                match_start=match.start(),
                context=context,
                api_type=ApiType.CIPHER_INSTANCE.value,
                algorithm=parsed.algorithm,
                mode=parsed.mode,
                padding=parsed.padding,
                purpose=Purpose.ENCRYPTION.value,
                library="javax.crypto",
                is_string_literal=True,
                raw_transformation=transformation,
            )
            findings.append(finding)

        # Variable matches (MEDIUM confidence) - avoid double-counting
        literal_positions = {m.start() for m in CIPHER_GETINSTANCE.finditer(source)}
        for match in CIPHER_GETINSTANCE_VAR.finditer(source):
            if match.start() in literal_positions:
                continue
            finding = self._build_finding(
                file_path=context.file_path,
                source=source,
                source_lines=source_lines,
                match_start=match.start(),
                context=context,
                api_type=ApiType.CIPHER_INSTANCE.value,
                algorithm=None,  # Cannot determine from variable
                purpose=Purpose.ENCRYPTION.value,
                library="javax.crypto",
                is_string_literal=False,
                is_from_local_variable=True,
                variable_name=match.group(1),
            )
            findings.append(finding)

        return findings

    # ============================================================
    # Pattern 2: java.security.MessageDigest
    # ============================================================

    def _detect_message_digest(
        self, source: str, source_lines: list[str], context: ParseContext
    ) -> list[RawFinding]:
        """Detect MessageDigest.getInstance() calls."""
        findings = []

        for match in MESSAGEDIGEST_GETINSTANCE.finditer(source):
            algorithm_str = match.group(1)
            parsed = parse_transformation(algorithm_str)

            finding = self._build_finding(
                file_path=context.file_path,
                source=source,
                source_lines=source_lines,
                match_start=match.start(),
                context=context,
                api_type=ApiType.MESSAGE_DIGEST.value,
                algorithm=parsed.algorithm,
                purpose=Purpose.HASHING.value,
                library="java.security",
                is_string_literal=True,
                raw_transformation=algorithm_str,
            )
            findings.append(finding)

        # Variable matches
        literal_positions = {m.start() for m in MESSAGEDIGEST_GETINSTANCE.finditer(source)}
        for match in MESSAGEDIGEST_GETINSTANCE_VAR.finditer(source):
            if match.start() in literal_positions:
                continue
            finding = self._build_finding(
                file_path=context.file_path,
                source=source,
                source_lines=source_lines,
                match_start=match.start(),
                context=context,
                api_type=ApiType.MESSAGE_DIGEST.value,
                algorithm=None,
                purpose=Purpose.HASHING.value,
                library="java.security",
                is_string_literal=False,
                is_from_local_variable=True,
            )
            findings.append(finding)

        return findings

    # ============================================================
    # Pattern 3: javax.crypto.KeyGenerator
    # ============================================================

    def _detect_key_generator(
        self, source: str, source_lines: list[str], context: ParseContext
    ) -> list[RawFinding]:
        """Detect KeyGenerator.getInstance() calls."""
        findings = []

        for match in KEYGENERATOR_GETINSTANCE.finditer(source):
            algorithm_str = match.group(1)
            parsed = parse_transformation(algorithm_str)

            # Try to find associated .init(keysize) call after this position
            subsequent_source = source[match.end():match.end() + 500]  # Look ahead 500 chars
            key_size = None
            init_match = KEYGENERATOR_INIT.search(subsequent_source)
            if init_match:
                try:
                    key_size = int(init_match.group(1))
                except ValueError:
                    pass

            finding = self._build_finding(
                file_path=context.file_path,
                source=source,
                source_lines=source_lines,
                match_start=match.start(),
                context=context,
                api_type=ApiType.KEY_GENERATOR.value,
                algorithm=parsed.algorithm,
                key_size=key_size,
                purpose=Purpose.KEY_GENERATION.value,
                library="javax.crypto",
                is_string_literal=True,
                raw_transformation=algorithm_str,
            )
            findings.append(finding)

        # Variable matches
        literal_positions = {m.start() for m in KEYGENERATOR_GETINSTANCE.finditer(source)}
        for match in KEYGENERATOR_GETINSTANCE_VAR.finditer(source):
            if match.start() in literal_positions:
                continue
            finding = self._build_finding(
                file_path=context.file_path,
                source=source,
                source_lines=source_lines,
                match_start=match.start(),
                context=context,
                api_type=ApiType.KEY_GENERATOR.value,
                algorithm=None,
                purpose=Purpose.KEY_GENERATION.value,
                library="javax.crypto",
                is_string_literal=False,
                is_from_local_variable=True,
            )
            findings.append(finding)

        return findings

    def _detect_key_pair_generator(
        self, source: str, source_lines: list[str], context: ParseContext
    ) -> list[RawFinding]:
        findings = []
        for match in KEYPAIRGENERATOR_GETINSTANCE.finditer(source):
            algorithm_str = match.group(1)
            parsed = parse_transformation(algorithm_str)
            subsequent = source[match.end() : match.end() + 400]
            key_size = None
            init_match = KEYPAIRGENERATOR_INIT.search(subsequent)
            if init_match:
                try:
                    key_size = int(init_match.group(1))
                except ValueError:
                    pass
            findings.append(
                self._build_finding(
                    file_path=context.file_path,
                    source=source,
                    source_lines=source_lines,
                    match_start=match.start(),
                    context=context,
                    api_type=ApiType.KEY_PAIR_GENERATOR.value,
                    algorithm=parsed.algorithm,
                    key_size=key_size,
                    purpose=Purpose.KEY_GENERATION.value,
                    library="java.security",
                    is_string_literal=True,
                    raw_transformation=algorithm_str,
                )
            )
        return findings

    # ============================================================
    # Pattern 4: java.security.Signature
    # ============================================================

    def _detect_signature(
        self, source: str, source_lines: list[str], context: ParseContext
    ) -> list[RawFinding]:
        """Detect Signature.getInstance() calls."""
        findings = []

        for match in SIGNATURE_GETINSTANCE.finditer(source):
            algorithm_str = match.group(1)
            parsed = parse_transformation(algorithm_str)

            finding = self._build_finding(
                file_path=context.file_path,
                source=source,
                source_lines=source_lines,
                match_start=match.start(),
                context=context,
                api_type=ApiType.SIGNATURE.value,
                algorithm=parsed.algorithm,
                purpose=Purpose.SIGNING.value,
                library="java.security",
                is_string_literal=True,
                raw_transformation=algorithm_str,
            )
            findings.append(finding)

        # Variable matches
        literal_positions = {m.start() for m in SIGNATURE_GETINSTANCE.finditer(source)}
        for match in SIGNATURE_GETINSTANCE_VAR.finditer(source):
            if match.start() in literal_positions:
                continue
            finding = self._build_finding(
                file_path=context.file_path,
                source=source,
                source_lines=source_lines,
                match_start=match.start(),
                context=context,
                api_type=ApiType.SIGNATURE.value,
                algorithm=None,
                purpose=Purpose.SIGNING.value,
                library="java.security",
                is_string_literal=False,
                is_from_local_variable=True,
            )
            findings.append(finding)

        return findings

    # ============================================================
    # Pattern 6: javax.crypto.Mac
    # ============================================================

    def _detect_mac(
        self, source: str, source_lines: list[str], context: ParseContext
    ) -> list[RawFinding]:
        """Detect Mac.getInstance() HMAC constructions."""
        findings = []
        for match in MAC_GETINSTANCE.finditer(source):
            algorithm_str = match.group(1)
            parsed = parse_transformation(algorithm_str)
            findings.append(
                self._build_finding(
                    file_path=context.file_path,
                    source=source,
                    source_lines=source_lines,
                    match_start=match.start(),
                    context=context,
                    api_type=ApiType.MAC.value,
                    algorithm=parsed.algorithm,
                    purpose=Purpose.MAC_GENERATION.value,
                    library="javax.crypto",
                    is_string_literal=True,
                    raw_transformation=algorithm_str,
                )
            )
        literal_positions = {m.start() for m in MAC_GETINSTANCE.finditer(source)}
        for match in MAC_GETINSTANCE_VAR.finditer(source):
            if match.start() in literal_positions:
                continue
            findings.append(
                self._build_finding(
                    file_path=context.file_path,
                    source=source,
                    source_lines=source_lines,
                    match_start=match.start(),
                    context=context,
                    api_type=ApiType.MAC.value,
                    algorithm=None,
                    purpose=Purpose.MAC_GENERATION.value,
                    library="javax.crypto",
                    is_string_literal=False,
                    is_from_local_variable=True,
                    variable_name=match.group(1),
                )
            )
        return findings

    # ============================================================
    # Pattern 5: Hardcoded Keys (SecretKeySpec)
    # ============================================================

    def _detect_hardcoded_keys(
        self, source: str, source_lines: list[str], context: ParseContext
    ) -> list[RawFinding]:
        """
        Detect hardcoded cryptographic keys in SecretKeySpec constructors.
        
        IMPORTANT: We detect the PRESENCE of hardcoded keys but do NOT
        extract the actual key value (security principle).
        """
        findings = []

        # Check for hardcoded byte arrays: new SecretKeySpec(new byte[]{...}, "AES")
        for match in HARDCODED_BYTE_ARRAY.finditer(source):
            # Count bytes to estimate key length
            byte_content = match.group(1)
            byte_count = len([b for b in byte_content.split(",") if b.strip()])
            key_length_bits = byte_count * 8

            # Find the algorithm - search for pattern around match
            surrounding = source[match.start():match.start() + 200]
            algo_match = SECRETKEYSPEC_LITERAL.search(surrounding)
            algorithm = algo_match.group(1) if algo_match else None
            parsed = parse_transformation(algorithm) if algorithm else None

            finding = self._build_finding(
                file_path=context.file_path,
                source=source,
                source_lines=source_lines,
                match_start=match.start(),
                context=context,
                api_type=ApiType.HARDCODED_KEY.value,
                algorithm=known_algorithm_or_unknown(parsed.algorithm if parsed else algorithm),
                purpose=Purpose.KEY_GENERATION.value,
                library="javax.crypto",
                is_string_literal=True,
                is_hardcoded_key=True,
                hardcoded_key_length=key_length_bits,
                raw_transformation=algorithm,
            )
            findings.append(finding)

        # Check for string-based keys: new SecretKeySpec("myKey".getBytes(), "AES")
        for match in HARDCODED_STRING_KEY.finditer(source):
            key_string_length = len(match.group(1))
            key_length_bits = key_string_length * 8  # ASCII approximation

            surrounding = source[match.start():match.start() + 200]
            algo_match = SECRETKEYSPEC_LITERAL.search(surrounding)
            algorithm = algo_match.group(1) if algo_match else None
            parsed = parse_transformation(algorithm) if algorithm else None

            finding = self._build_finding(
                file_path=context.file_path,
                source=source,
                source_lines=source_lines,
                match_start=match.start(),
                context=context,
                api_type=ApiType.HARDCODED_KEY.value,
                algorithm=known_algorithm_or_unknown(parsed.algorithm if parsed else algorithm),
                purpose=Purpose.KEY_GENERATION.value,
                library="javax.crypto",
                is_string_literal=True,
                is_hardcoded_key=True,
                hardcoded_key_length=key_length_bits,
                raw_transformation=algorithm,
            )
            findings.append(finding)

        return findings

    def _detect_tls_and_keystore(
        self, source: str, source_lines: list[str], context: ParseContext
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for match in SSLCONTEXT_GETINSTANCE.finditer(source):
            proto = match.group(1)
            algo = proto.upper().replace(" ", "")
            if algo in {"SSL", "SSLV3", "SSLV3.0"}:
                algo = "SSLv3"
            elif algo in {"TLSV1", "TLS1", "TLSV1.0"}:
                algo = "TLS1.0"
            elif algo in {"TLSV1.1", "TLS1.1"}:
                algo = "TLS1.1"
            elif algo in {"TLSV1.2", "TLS1.2"}:
                algo = "TLS1.2"
            elif algo in {"TLSV1.3", "TLS1.3"}:
                algo = "TLS1.3"
            else:
                algo = "TLS"
            findings.append(
                self._build_finding(
                    file_path=context.file_path,
                    source=source,
                    source_lines=source_lines,
                    match_start=match.start(),
                    context=context,
                    api_type=ApiType.KEY_AGREEMENT.value,
                    algorithm=algo,
                    purpose=Purpose.NETWORK_ENCRYPTION.value,
                    library="javax.net.ssl",
                    is_string_literal=True,
                    raw_transformation=proto,
                )
            )
        for match in KEYSTORE_GETINSTANCE.finditer(source):
            findings.append(
                self._build_finding(
                    file_path=context.file_path,
                    source=source,
                    source_lines=source_lines,
                    match_start=match.start(),
                    context=context,
                    api_type=ApiType.KEY_GENERATOR.value,
                    algorithm=match.group(1).upper(),
                    purpose="KEY_GENERATION",
                    library="java.security",
                    is_string_literal=True,
                    raw_transformation=match.group(1),
                )
            )
        return findings

    def _detect_key_agreement(
        self, source: str, source_lines: list[str], context: ParseContext
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for match in KEYAGREEMENT_GETINSTANCE.finditer(source):
            raw = match.group(1)
            upper = raw.upper()
            algo = "ECDH" if "ECDH" in upper else ("DH" if upper in {"DH", "DIFFIEHELLMAN"} else upper)
            if upper.startswith(("ML-KEM", "MLKEM", "KYBER")):
                algo = "ML-KEM"
            elif upper == "DHKEM":
                algo = "X25519"
            findings.append(
                self._build_finding(
                    file_path=context.file_path,
                    source=source,
                    source_lines=source_lines,
                    match_start=match.start(),
                    context=context,
                    api_type=ApiType.KEY_AGREEMENT.value,
                    algorithm=algo,
                    purpose="KEY_EXCHANGE",
                    library="javax.crypto",
                    is_string_literal=True,
                    raw_transformation=raw,
                )
            )
        return findings

    def _detect_secure_random(
        self, source: str, source_lines: list[str], context: ParseContext
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for match in SECURERANDOM_GETINSTANCE.finditer(source):
            raw = match.group(1)
            weak = raw.upper() in {"SHA1PRNG"}
            findings.append(
                self._build_finding(
                    file_path=context.file_path,
                    source=source,
                    source_lines=source_lines,
                    match_start=match.start(),
                    context=context,
                    api_type=ApiType.KEY_GENERATOR.value,
                    algorithm="SHA1PRNG" if weak else "CSPRNG",
                    purpose="KEY_GENERATION",
                    library="java.security",
                    is_string_literal=True,
                    raw_transformation=raw,
                )
            )
        return findings

    def _detect_pbe(
        self, source: str, source_lines: list[str], context: ParseContext
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for match in PBEKEYSPEC.finditer(source):
            findings.append(
                self._build_finding(
                    file_path=context.file_path,
                    source=source,
                    source_lines=source_lines,
                    match_start=match.start(),
                    context=context,
                    api_type=ApiType.KEY_GENERATOR.value,
                    algorithm="PBKDF2",
                    purpose="PASSWORD_HASHING",
                    library="javax.crypto",
                    is_string_literal=True,
                    raw_transformation="PBEKeySpec",
                )
            )
        return findings

    def _detect_insecure_tls(
        self, source: str, source_lines: list[str], context: ParseContext
    ) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for match in list(HOSTNAME_VERIFIER.finditer(source)) + list(ALLOW_ALL_HOSTS.finditer(source)):
            findings.append(
                self._build_finding(
                    file_path=context.file_path,
                    source=source,
                    source_lines=source_lines,
                    match_start=match.start(),
                    context=context,
                    api_type=ApiType.KEY_AGREEMENT.value,
                    algorithm="TLS",
                    purpose=Purpose.NETWORK_ENCRYPTION.value,
                    library="javax.net.ssl",
                    is_string_literal=True,
                    raw_transformation=match.group(0)[:80],
                )
            )
        for match in EMPTY_TRUST_MANAGER.finditer(source):
            findings.append(
                self._build_finding(
                    file_path=context.file_path,
                    source=source,
                    source_lines=source_lines,
                    match_start=match.start(),
                    context=context,
                    api_type=ApiType.KEY_AGREEMENT.value,
                    algorithm="TRUST-ALL",
                    purpose=Purpose.NETWORK_ENCRYPTION.value,
                    library="javax.net.ssl",
                    is_string_literal=True,
                    raw_transformation="checkServerTrusted{}",
                )
            )
        return findings

    def _mark_bouncycastle(self, source: str, findings: list[RawFinding]) -> None:
        bc_lines = {source[:match.start()].count("\n") + 1 for match in BC_PROVIDER.finditer(source)}
        if not bc_lines:
            return
        for finding in findings:
            if finding.source.line_number in bc_lines:
                finding.metadata.library = "BouncyCastle"


def parse_java_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    """Module-level helper used by the multi-language runner."""
    return JavaParser(repo_root=repo_root).parse_file(file_path)