"""Extract GitContext from a working tree."""

from __future__ import annotations

from pathlib import Path

from scanner.git.git_client import GitClient
from scanner.models.raw_finding import GitContext


def extract_git_context(repo_path: str | Path, repo_url: str = "") -> GitContext:
    meta = GitClient().get_metadata(Path(repo_path), repo_url or str(repo_path))
    return GitContext(
        commit_hash=meta.commit_hash,
        commit_author=meta.commit_author,
        commit_timestamp=meta.commit_timestamp,
        branch=meta.branch,
        repository_url=meta.repository_url,
        commit_message=meta.commit_message,
    )
