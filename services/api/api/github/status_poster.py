"""Post commit status back to GitHub (optional)."""

from __future__ import annotations

import logging
import re

import httpx

logger = logging.getLogger(__name__)

GITHUB_HTTPS = re.compile(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/#?]+)", re.IGNORECASE)


def parse_github_repo(repo_url: str | None) -> tuple[str, str] | None:
    if not repo_url:
        return None
    match = GITHUB_HTTPS.search(repo_url)
    if not match:
        return None
    repo = match.group("repo")
    if repo.endswith(".git"):
        repo = repo[:-4]
    return match.group("owner"), repo


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
) -> bool:
    if not token or not commit:
        return False
    url = f"https://api.github.com/repos/{owner}/{repo}/statuses/{commit}"
    try:
        response = httpx.post(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={"state": state, "description": description[:140], "target_url": target_url, "context": context},
            timeout=15,
        )
        if response.status_code >= 300:
            logger.warning("github_status_rejected", extra={"status": response.status_code})
            return False
        return True
    except Exception:
        logger.exception("github_status_post_failed")
        return False


def post_pipeline_status(
    *,
    token: str,
    repo_url: str,
    commit: str | None,
    state: str,
    description: str,
    target_url: str = "",
    context: str = "cryptoscan/compliance",
) -> bool:
    parsed = parse_github_repo(repo_url)
    if not parsed or not token or not commit:
        return False
    owner, repo = parsed
    return post_status(
        token=token,
        owner=owner,
        repo=repo,
        commit=commit,
        state=state,
        description=description,
        target_url=target_url,
        context=context,
    )
