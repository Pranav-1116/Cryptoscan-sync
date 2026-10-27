"""Clone or copy a scan target into the workspace."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class RepoCloner:
    def clone(
        self,
        repo_url: str,
        branch: str,
        target_path: str,
        commit: str | None = None,
        depth: int = 1,
    ) -> str:
        dest = Path(target_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        local = self._as_local_path(repo_url)
        if local is not None:
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(local, dest, ignore=shutil.ignore_patterns(".git", "node_modules", "__pycache__"))
            return commit or "local"

        cmd = ["git", "clone", "--depth", str(depth)]
        if branch:
            cmd.extend(["--branch", branch, "--single-branch"])
        cmd.extend([repo_url, str(dest)])
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed: {proc.stderr.strip()}")
        if commit:
            checkout = subprocess.run(
                ["git", "-C", str(dest), "checkout", commit],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if checkout.returncode != 0:
                raise RuntimeError(f"git checkout failed: {checkout.stderr.strip()}")
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return (head.stdout or commit or "unknown").strip()

    def _as_local_path(self, repo_url: str) -> Path | None:
        raw = repo_url
        if raw.startswith("local://"):
            raw = raw[len("local://") :]
        elif raw.startswith("file://"):
            raw = raw[len("file://") :]
        path = Path(raw)
        if not path.is_absolute():
            from shared_config.env_loader import repo_root

            path = repo_root() / raw
        if path.exists() and path.is_dir():
            return path
        return None
