"""Apply Cypher schema files in version order."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

VERSIONS_DIR = Path(__file__).resolve().parent / "versions"


def _statements(text: str) -> list[str]:
    chunks: list[str] = []
    buf: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        buf.append(line)
        if line.endswith(";"):
            chunks.append(" ".join(buf).rstrip(";").strip())
            buf = []
    if buf:
        chunks.append(" ".join(buf).rstrip(";").strip())
    return [item for item in chunks if item]


def load_migration_files() -> list[Path]:
    return sorted(VERSIONS_DIR.glob("*.cypher"))


def apply_migrations(runner) -> dict[str, Any]:
    """Run every statement. `runner(cypher)` is session.run or FakeSession.run."""
    applied: list[str] = []
    for path in load_migration_files():
        for statement in _statements(path.read_text(encoding="utf-8")):
            runner(statement)
        applied.append(path.name)
        logger.info("neo4j_migration_applied", extra={"file": path.name})
    return {"applied": applied, "count": len(applied)}


def apply_statements(runner, statements: Iterable[str]) -> int:
    count = 0
    for statement in statements:
        runner(statement)
        count += 1
    return count
