"""Kotlin / Scala crypto detector — same JVM APIs as the Java parser."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.java_parser import JavaParser

_BUILD_STRING = re.compile(r"\b(?:val|var)\s+(\w+)\s*(?::\s*String)?\s*=\s*buildString\s*\{([^}]*)\}")
_APPEND = re.compile(r"append\s*\(\s*\"([^\"]*)\"\s*\)")
_STRING_CONST = re.compile(r"\b(?:const\s+)?(?:val|var)\s+(\w+)\s*(?::\s*String)?\s*=\s*\"([^\"$]{1,80})\"")
_CONCAT = re.compile(r"\b(?:const\s+)?(?:val|var)\s+(\w+)\s*(?::\s*String)?\s*=\s*((?:\"[^\"]*\"|\w+)(?:\s*\+\s*(?:\"[^\"]*\"|\w+))+)")
_TEMPLATE = re.compile(r"\$\{?(\w+)\}?")
_NUM_CONST = re.compile(r"\b(?:const\s+)?(?:val|var)\s+(\w+)\s*(?::\s*(?:Int|Long))?\s*=\s*(\d{1,4})\b")
_LISTOF_JOIN = re.compile(r"\b(?:val|var)\s+(\w+)\s*(?::\s*String)?\s*=\s*listOf\s*\(((?:\s*\"[^\"]*\"\s*,?)+)\)\s*\.\s*joinToString\s*\(\s*\"([^\"]*)\"\s*\)")


def desugar_kotlin(source: str) -> str:
    """Rewrite Kotlin-only string constructions into plain literals so the JVM
    token walker sees the real algorithm spec:

    * ``val alg = buildString { append("DES"); append("ede") }`` -> ``val alg = "DESede"``
    * ``val alg = listOf("AES", "GCM").joinToString("/")``         -> ``val alg = "AES/GCM"``
    * ``val alg = "AES" + "/" + mode``                              -> folded when every piece is known
    * ``"$alg/CBC/PKCS5Padding"`` / ``"${alg}/CBC"``                 -> ``"DESede/CBC/PKCS5Padding"``

    Only single-file, literal-only constructions are folded; anything dynamic is
    left untouched.  Line structure is preserved so line numbers stay correct.
    """
    consts: dict[str, str] = {}

    def _build(m: re.Match) -> str:
        value = "".join(_APPEND.findall(m.group(2)))
        if not value:
            return m.group(0)
        consts[m.group(1)] = value
        return f'val {m.group(1)} = "{value}"'

    source = _BUILD_STRING.sub(_build, source)

    def _join(m: re.Match) -> str:
        parts = re.findall(r"\"([^\"]*)\"", m.group(2))
        value = m.group(3).join(parts)
        consts[m.group(1)] = value
        return f'val {m.group(1)} = "{value}"'

    source = _LISTOF_JOIN.sub(_join, source)
    for m in _STRING_CONST.finditer(source):
        consts.setdefault(m.group(1), m.group(2))
    for m in _NUM_CONST.finditer(source):  # val bits = 512 → "SHA-$bits" → "SHA-512"
        consts.setdefault(m.group(1), m.group(2))

    def _concat(m: re.Match) -> str:
        pieces = []
        for piece in re.split(r"\s*\+\s*", m.group(2)):
            piece = piece.strip()
            if piece.startswith('"') and piece.endswith('"'):
                pieces.append(piece[1:-1])
            elif piece in consts:
                pieces.append(consts[piece])
            else:
                return m.group(0)
        value = "".join(pieces)
        consts[m.group(1)] = value
        return f'val {m.group(1)} = "{value}"'

    source = _CONCAT.sub(_concat, source)

    if not consts:
        return source

    def _template(m: re.Match) -> str:
        name = m.group(1)
        return consts.get(name, "$" + name)

    # only substitute inside string literals
    def _in_string(m: re.Match) -> str:
        body = m.group(0)
        if "$" not in body:
            return body
        return _TEMPLATE.sub(_template, body)

    return re.sub(r'"(?:[^"\\\n]|\\.)*"', _in_string, source)


def parse_kotlin_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings = JavaParser(repo_root=repo_root).parse_file(file_path, source=desugar_kotlin(raw))
    language = "SCALA" if file_path.suffix.lower() == ".scala" else "KOTLIN"
    scanner_id = f"static-{language.lower()}-scanner-v1.0"
    for finding in findings:
        finding.source.language = language
        finding.scanner_id = scanner_id
        finding.scanner_version = "1.0.0"
    return findings


parse_scala_file = parse_kotlin_file
