"""Temporary workspaces for image extract / scan jobs."""

from __future__ import annotations

import logging
import shutil
import tempfile
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)


class WorkspaceManager:
    def __init__(self, base_temp_dir: str | Path | None = None, prefix: str = "cryptoscan-container-"):
        self.prefix = prefix
        self._owns_base = base_temp_dir is None
        if base_temp_dir is None:
            self.base_temp_dir = Path(tempfile.mkdtemp(prefix=f"{prefix}base-"))
        else:
            self.base_temp_dir = Path(base_temp_dir)
            self.base_temp_dir.mkdir(parents=True, exist_ok=True)
        self._impl = self._worker_impl()

    def _worker_impl(self):
        try:
            from worker.workspace.workspace_manager import WorkspaceManager as WorkerWorkspace

            return WorkerWorkspace(str(self.base_temp_dir))
        except Exception:
            return None

    def create(self, job_id: str | None = None) -> Path:
        ident = job_id or uuid.uuid4().hex
        if self._impl is not None:
            return Path(self._impl.create(ident))
        path = self.base_temp_dir / f"job-{ident}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def cleanup(self, workspace_path: str | Path | None = None) -> None:
        if workspace_path is None:
            if self._owns_base:
                shutil.rmtree(self.base_temp_dir, ignore_errors=True)
            return
        path = Path(workspace_path)
        if self._impl is not None:
            try:
                self._impl.cleanup(path)
                return
            except Exception as exc:
                logger.info("workspace_worker_cleanup_failed", extra={"error": str(exc)})
        if not path.exists():
            return
        try:
            path.resolve().relative_to(self.base_temp_dir.resolve())
        except ValueError:
            logger.error("refusing_to_delete_workspace_outside_base", extra={"path": str(path)})
            return
        shutil.rmtree(path, ignore_errors=True)
