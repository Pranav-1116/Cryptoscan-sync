"""Workspace directories for scan jobs."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


class WorkspaceManager:
    def __init__(self, base_temp_dir: str = "./data/workspaces"):
        self.base_temp_dir = Path(base_temp_dir)
        self.base_temp_dir.mkdir(parents=True, exist_ok=True)

    def create(self, job_id: str) -> Path:
        path = self.base_temp_dir / f"job-{job_id}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def cleanup(self, workspace_path: str | Path) -> None:
        path = Path(workspace_path)
        if not path.exists():
            return
        # Resolve both sides: the default base is relative ("./data/workspaces")
        # and create() hands back a relative path, so comparing an unresolved
        # path against a resolved base rejected *every* cleanup. Found by the
        # Postgres soak: one leaked workspace per job, forever.
        try:
            path.resolve().relative_to(self.base_temp_dir.resolve())
        except ValueError:
            logger.error("refusing_to_delete_workspace_outside_base", extra={"path": str(path)})
            return
        shutil.rmtree(path, ignore_errors=True)
