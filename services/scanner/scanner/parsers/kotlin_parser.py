"""Kotlin / Scala crypto detector — same JVM APIs as the Java parser."""

from __future__ import annotations

from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.java_parser import JavaParser


def parse_kotlin_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    findings = JavaParser(repo_root=repo_root).parse_file(file_path)
    language = "SCALA" if file_path.suffix.lower() == ".scala" else "KOTLIN"
    scanner_id = f"static-{language.lower()}-scanner-v1.0"
    for finding in findings:
        finding.source.language = language
        finding.scanner_id = scanner_id
        finding.scanner_version = "1.0.0"
    return findings


parse_scala_file = parse_kotlin_file
