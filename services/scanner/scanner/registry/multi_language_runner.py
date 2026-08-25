"""Run every applicable language scanner over a repository tree."""

from __future__ import annotations

from pathlib import Path

from scanner.core.file_discovery import FileDiscovery
from scanner.core.language_detector import detect_languages_in_repo
from scanner.models.raw_finding import RawFinding
from scanner.registry.scanner_registry import get_scanner_for_language, language_for_path, parse_path


def run_all_scanners(root: str | Path, *, languages: list[str] | None = None) -> list[RawFinding]:
    root_path = Path(root)
    wanted = {item.upper() for item in (languages or detect_languages_in_repo(root_path))}
    findings: list[RawFinding] = []
    for path in FileDiscovery().discover(root_path):
        language = language_for_path(path)
        if language is None:
            continue
        canonical = "JAVASCRIPT" if language == "TYPESCRIPT" else language
        if wanted and canonical not in wanted and language not in wanted:
            continue
        if get_scanner_for_language(language) is None:
            continue
        findings.extend(parse_path(path, root_path))
    return findings
