"""
Repository cloner: clones Git repos safely with timeout and validation.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class RepoCloner:
    """
    Safely clones Git repositories with timeout and error handling.
    """

    CLONE_TIMEOUT = 300  # 5 minutes
    MAX_REPO_SIZE_MB = 500

    async def clone(
        self,
        repo_url: str,
        branch: str,
        target_path: str,
        depth: int = 1,
    ) -> str:
        """
        Clone repository to target path.

        Args:
            repo_url: Git repository URL
            branch: Branch to clone
            target_path: Local directory path
            depth: Shallow clone depth (1 = only latest commit)

        Returns: Commit hash of cloned HEAD

        Raises:
            CloneError: If clone fails or times out
        """
        logger.info(
            "repo_clone_start",
            extra={
                "repo": repo_url,
                "branch": branch,
                "target": target_path,
            },
        )

        try:
            Path(target_path).parent.mkdir(parents=True, exist_ok=True)

            # Clone with shallow history (faster, smaller)
            cmd = [
                "git",
                "clone",
                "--single-branch",
                "--branch", branch,
                "--depth", str(depth),
                repo_url,
                target_path,
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.CLONE_TIMEOUT,
                )
            except asyncio.TimeoutError:
                proc.kill()
                raise TimeoutError(
                    f"Clone timeout after {self.CLONE_TIMEOUT}s for {repo_url}"
                )

            if proc.returncode != 0:
                raise RuntimeError(
                    f"Clone failed: {stderr.decode() if stderr else 'unknown error'}"
                )

            # Verify clone
            repo_path = Path(target_path)
            if not (repo_path / ".git").exists():
                raise RuntimeError(f"Clone did not produce .git directory")

            # Get commit hash
            commit_hash = await self._get_head_commit(target_path)

            logger.info(
                "repo_clone_success",
                extra={
                    "repo": repo_url,
                    "commit": commit_hash,
                },
            )

            return commit_hash

        except Exception as exc:
            logger.exception(
                "repo_clone_failed",
                extra={"repo": repo_url, "error": str(exc)},
            )
            raise

    async def _get_head_commit(self, repo_path: str) -> str:
        """Get the commit hash of HEAD."""
        cmd = ["git", "-C", repo_path, "rev-parse", "HEAD"]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(f"Failed to get HEAD commit: {stderr.decode()}")

        return stdout.decode().strip()