"""Base detector interface used by the Java parser detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.java_parser import JavaParser


class BaseDetector(ABC):
    api_type: str = "UNKNOWN"

    def __init__(self, repo_root: Path | None = None):
        self.parser = JavaParser(repo_root=repo_root)

    def detect(self, file_path: Path) -> list[RawFinding]:
        return [f for f in self.parser.parse_file(file_path) if self.matches(f)]

    def matches(self, finding: RawFinding) -> bool:
        return finding.crypto.api_type == self.api_type

    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError
