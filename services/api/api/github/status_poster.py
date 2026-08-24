"""Post commit status back to GitHub (optional)."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


def post_status(
    *,
    token: str,
    owner: str,
    repo: str,
    commit: str,
    state: str,
    description: str,
    target_url: str,
    context: str = "cryptoscan/compliance",
) -> None:
    if not token:
        return
    url = f"https://api.github.com/repos/{owner}/{repo}/statuses/{commit}"
    try:
        httpx.post(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={"state": state, "description": description, "target_url": target_url, "context": context},
            timeout=15,
        )
    except Exception:
        logger.exception("github_status_post_failed")
