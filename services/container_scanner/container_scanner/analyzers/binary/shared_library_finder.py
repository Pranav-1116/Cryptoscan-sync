"""Walk a merged rootfs for shared libraries and JARs."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", "proc", "sys", "dev", "run"}
LIB_SUFFIXES = {".so", ".dll", ".dylib"}


def find_shared_libraries(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in _iter_files(root):
        name = path.name.lower()
        suffix = path.suffix.lower()
        if suffix in LIB_SUFFIXES or ".so." in name or name.endswith(".so"):
            found.append(path)
    return found


def find_jars(root: Path) -> list[Path]:
    return [path for path in _iter_files(root) if path.suffix.lower() == ".jar"]


def _iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path
