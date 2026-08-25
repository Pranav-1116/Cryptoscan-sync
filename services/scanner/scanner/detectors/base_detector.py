"""Base detector interface used by named detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from scanner.models.raw_finding import RawFinding


class BaseDetector(ABC):
    api_type: str = "UNKNOWN"

    def __init__(self, repo_root: Path | None = None):
        self.repo_root = repo_root

    def detect(self, file_path: Path) -> list[RawFinding]:
        from scanner.registry.language_scanners import scan_file

        root = self.repo_root or file_path.parent
        return [finding for finding in scan_file(file_path, root) if self.matches(finding)]

    def matches(self, finding: RawFinding) -> bool:
        return finding.crypto.api_type == self.api_type

    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError
