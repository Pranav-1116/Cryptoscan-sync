"""Git repository client - clone and extract metadata."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Optional
from contextlib import contextmanager
from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class GitMetadata:
    """Metadata extracted from a Git repository."""
    commit_hash: str
    commit_author: str
    commit_timestamp: str  # ISO-8601
    commit_message: str
    branch: str
    repository_url: str


class GitClient:
    """
    Handles Git repository operations for the scanner.
    
    Clones repositories to temporary directories and extracts
    commit metadata for evidence records.
    """

    def clone(
        self,
        repo_url: str,
        target_dir: Path,
        branch: Optional[str] = None,
        commit_hash: Optional[str] = None,
        depth: int = 1,
    ) -> Path:
        """
        Clone a Git repository to target_dir.
        
        Args:
            repo_url: Repository URL (https or ssh)
            target_dir: Directory to clone into
            branch: Branch to checkout (default: default branch)
            commit_hash: Specific commit to checkout
            depth: Clone depth (1 = shallow clone for speed)
            
        Returns:
            Path to the cloned repository
        """
        import git  # GitPython

        log = logger.bind(repo=repo_url, branch=branch, commit=commit_hash)
        log.info("cloning_repository")

        try:
            clone_kwargs: dict = {
                "depth": depth,
                "no_single_branch": branch is None,
            }
            if branch:
                clone_kwargs["branch"] = branch

            repo = git.Repo.clone_from(
                repo_url,
                str(target_dir),
                **clone_kwargs,
            )

            # Checkout specific commit if requested
            if commit_hash:
                repo.git.checkout(commit_hash)
                log.info("checked_out_commit", commit=commit_hash)

            log.info("clone_complete")
            return target_dir

        except git.exc.GitCommandError as e:
            log.error("clone_failed", error=str(e))
            raise RuntimeError(f"Failed to clone {repo_url}: {e}") from e

    def get_metadata(self, repo_path: Path, repo_url: str) -> GitMetadata:
        """
        Extract Git metadata from a cloned repository.
        
        Args:
            repo_path: Path to the cloned repository
            repo_url: Original repository URL
            
        Returns:
            GitMetadata with commit information
        """
        import git

        try:
            repo = git.Repo(str(repo_path))
            commit = repo.head.commit

            # Get branch name
            try:
                branch = repo.active_branch.name
            except TypeError:
                branch = "detached-HEAD"

            return GitMetadata(
                commit_hash=commit.hexsha,
                commit_author=f"{commit.author.name} <{commit.author.email}>",
                commit_timestamp=commit.authored_datetime.isoformat(),
                commit_message=commit.message.strip(),
                branch=branch,
                repository_url=repo_url,
            )

        except Exception as e:
            logger.warning("cannot_extract_git_metadata", error=str(e))
            return GitMetadata(
                commit_hash="unknown",
                commit_author="unknown",
                commit_timestamp="unknown",
                commit_message="",
                branch="unknown",
                repository_url=repo_url,
            )

    @contextmanager
    def temp_clone(self, repo_url: str, branch: Optional[str] = None):
        """
        Context manager that clones a repo to a temp dir and cleans up on exit.
        
        Usage:
            with git_client.temp_clone(url, branch="main") as (path, metadata):
                scanner.scan(path)
        """
        tmp_dir = tempfile.mkdtemp(prefix="cryptoscan-clone-")
        try:
            clone_path = self.clone(repo_url, Path(tmp_dir), branch=branch)
            metadata = self.get_metadata(clone_path, repo_url)
            yield clone_path, metadata
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            logger.info("temp_clone_cleaned_up", path=tmp_dir)