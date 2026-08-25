"""Abstract OS package analyzer."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable


class BasePackageAnalyzer:
    manager: str = "unknown"

    def matches(self, path: Path) -> bool:
        raise NotImplementedError

    def parse(self, path: Path) -> list[dict[str, Any]]:
        raise NotImplementedError

    def discover(self, root: Path, files: Iterable[Path]) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for path in files:
            if self.matches(path):
                found.extend(self.parse(path))
        return found
