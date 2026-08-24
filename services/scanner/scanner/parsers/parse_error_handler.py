"""Graceful parse-error handling used by the multi-language runner."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from scanner.models.raw_finding import RawFinding

logger = logging.getLogger(__name__)


def safe_parse(
    parser: Callable[[Path, Path | None], list[RawFinding]],
    file_path: Path,
    repo_root: Path | None = None,
) -> tuple[list[RawFinding], dict[str, Any] | None]:
    try:
        return parser(file_path, repo_root), None
    except Exception as exc:
        logger.warning("parse_error", extra={"file": str(file_path), "error": str(exc)})
        return [], {"file": str(file_path), "error": str(exc), "type": type(exc).__name__}
