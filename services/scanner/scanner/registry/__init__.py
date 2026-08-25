"""Language scanner registry."""

from scanner.registry.language_scanners import scan_file
from scanner.registry.multi_language_runner import run_all_scanners
from scanner.registry.scanner_registry import get_scanner_for_language, language_for_path, parse_path

__all__ = [
    "get_scanner_for_language",
    "language_for_path",
    "parse_path",
    "run_all_scanners",
    "scan_file",
]
