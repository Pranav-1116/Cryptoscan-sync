"""
GitHub webhook payload parser.
Extracts structured data from raw GitHub push/PR payloads.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ParsedPushEvent:
    """Structured representation of a GitHub push event."""

    repo_url: str
    repo_full_name: str
    repo_html_url: str
    commit_hash: str
    commit_message: str
    commit_author: str
    commit_timestamp: str
    branch: str
    pusher_name: str


class GitHubPayloadParser:
    """
    Parses raw GitHub webhook JSON payloads into structured objects.

    Design notes:
    - Returns None for events that should not trigger scans
      (e.g. branch deletions, pushes with no commits)
    - Never raises; logs and returns None on parse failures
    """

    def parse_push(self, payload: Dict[str, Any]) -> Optional[ParsedPushEvent]:
        """
        Parse a GitHub push event payload.

        Returns None if the event should not trigger a scan:
        - Deleted branch (ref deleted)
        - No head_commit present
        """
        try:
            ref: str = payload.get("ref", "")
            deleted: bool = payload.get("deleted", False)

            if deleted:
                logger.debug("push_event_is_branch_deletion", extra={"ref": ref})
                return None

            head_commit = payload.get("head_commit")
            if not head_commit:
                logger.debug("push_event_no_head_commit", extra={"ref": ref})
                return None

            repository = payload.get("repository", {})
            pusher = payload.get("pusher", {})

            branch = self._extract_branch(ref)
            if branch is None:
                logger.debug("push_event_non_branch_ref", extra={"ref": ref})
                return None

            return ParsedPushEvent(
                repo_url=repository.get("clone_url", ""),
                repo_full_name=repository.get("full_name", ""),
                repo_html_url=repository.get("html_url", ""),
                commit_hash=head_commit.get("id", ""),
                commit_message=head_commit.get("message", "")[:500],
                commit_author=head_commit.get("author", {}).get("name", "unknown"),
                commit_timestamp=head_commit.get("timestamp", ""),
                branch=branch,
                pusher_name=pusher.get("name", "github-webhook"),
            )

        except Exception as exc:
            logger.exception(
                "github_payload_parse_error",
                extra={"error": str(exc)},
            )
            return None

    def _extract_branch(self, ref: str) -> Optional[str]:
        """
        Extract branch name from Git ref string.

        Examples:
            'refs/heads/main'       -> 'main'
            'refs/heads/feature/x'  -> 'feature/x'
            'refs/tags/v1.0'        -> None (tags not scanned)
        """
        if ref.startswith("refs/heads/"):
            return ref[len("refs/heads/"):]
        return None