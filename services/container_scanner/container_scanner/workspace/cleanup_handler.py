"""Guarantee workspace deletion after a container scan."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from container_scanner.workspace.workspace_manager import WorkspaceManager

logger = logging.getLogger(__name__)


class CleanupHandler:
    def __init__(self, workspace: WorkspaceManager, path: str | Path | None = None) -> None:
        self.workspace = workspace
        self.path = path

    def __enter__(self) -> WorkspaceManager:
        return self.workspace

    def __exit__(self, exc_type, exc, tb) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        try:
            self.workspace.cleanup(self.path)
        except Exception as exc:
            logger.info("workspace_cleanup_failed", extra={"error": str(exc)})


@contextmanager
def ensure_cleanup(
    workspace: WorkspaceManager | None,
    path: str | Path | None = None,
) -> Iterator[WorkspaceManager | None]:
    try:
        yield workspace
    finally:
        if workspace is not None:
            try:
                workspace.cleanup(path)
            except Exception as exc:
                logger.info("workspace_cleanup_failed", extra={"error": str(exc)})
