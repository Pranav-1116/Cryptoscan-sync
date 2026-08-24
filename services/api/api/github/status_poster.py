"""
GitHub Commit Status API poster.
Posts scan results back to GitHub as commit status checks.
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Optional

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class GitHubStatusState(str, Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"


class CommitStatusPayload(BaseModel):
    state: GitHubStatusState
    target_url: str
    description: str
    context: str = "cryptoscan/compliance"


class GitHubStatusPoster:
    """
    Posts commit status checks to GitHub via the Statuses API.

    Reference: https://docs.github.com/en/rest/commits/statuses
    """

    GITHUB_API_BASE = "https://api.github.com"
    CONTEXT_NAME = "cryptoscan/compliance"
    MAX_DESCRIPTION_LEN = 140  # GitHub API limit

    def __init__(self, token: str) -> None:
        self._token = token
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def post_pending(
        self,
        repo_full_name: str,
        commit_sha: str,
        scan_url: str,
    ) -> bool:
        """Post 'pending' status when scan starts."""
        return await self._post_status(
            repo_full_name=repo_full_name,
            commit_sha=commit_sha,
            payload=CommitStatusPayload(
                state=GitHubStatusState.PENDING,
                target_url=scan_url,
                description="CryptoScan analysis in progress...",
            ),
        )

    async def post_scan_result(
        self,
        repo_full_name: str,
        commit_sha: str,
        scan_url: str,
        total_findings: int,
        failed_findings: int,
        scan_id: str,
    ) -> bool:
        """Post final scan result status (success or failure)."""
        if failed_findings > 0:
            state = GitHubStatusState.FAILURE
            desc = f"{failed_findings} non-compliant crypto finding(s) detected"
        else:
            state = GitHubStatusState.SUCCESS
            desc = f"All {total_findings} crypto finding(s) are compliant"

        return await self._post_status(
            repo_full_name=repo_full_name,
            commit_sha=commit_sha,
            payload=CommitStatusPayload(
                state=state,
                target_url=scan_url,
                description=desc[:self.MAX_DESCRIPTION_LEN],
            ),
        )

    async def post_error(
        self,
        repo_full_name: str,
        commit_sha: str,
        scan_url: str,
        error_message: str,
    ) -> bool:
        """Post error status when scan pipeline fails."""
        return await self._post_status(
            repo_full_name=repo_full_name,
            commit_sha=commit_sha,
            payload=CommitStatusPayload(
                state=GitHubStatusState.ERROR,
                target_url=scan_url,
                description=f"Scan error: {error_message}"[:self.MAX_DESCRIPTION_LEN],
            ),
        )

    async def _post_status(
        self,
        repo_full_name: str,
        commit_sha: str,
        payload: CommitStatusPayload,
    ) -> bool:
        """
        POST to GitHub Statuses API.

        Returns True on success, False on failure (non-raising).
        Failures are logged but do not propagate — status posting
        is best-effort and must not break the scan pipeline.
        """
        url = f"{self.GITHUB_API_BASE}/repos/{repo_full_name}/statuses/{commit_sha}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    url,
                    headers=self._headers,
                    json={
                        "state": payload.state.value,
                        "target_url": payload.target_url,
                        "description": payload.description,
                        "context": payload.context,
                    },
                )

            if response.status_code in (200, 201):
                logger.info(
                    "github_status_posted",
                    extra={
                        "repo": repo_full_name,
                        "commit": commit_sha[:8],
                        "state": payload.state.value,
                    },
                )
                return True
            else:
                logger.warning(
                    "github_status_post_failed",
                    extra={
                        "repo": repo_full_name,
                        "commit": commit_sha[:8],
                        "http_status": response.status_code,
                        "response": response.text[:500],
                    },
                )
                return False

        except Exception as exc:
            logger.exception(
                "github_status_post_error",
                extra={
                    "repo": repo_full_name,
                    "commit": commit_sha[:8],
                    "error": str(exc),
                },
            )
            return False