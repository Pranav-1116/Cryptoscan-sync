"""Parse GitHub webhook payloads."""

from __future__ import annotations


def parse_pull_request_event(payload: dict) -> dict:
    repo = payload.get("repository") or {}
    pull = payload.get("pull_request") or {}
    head = pull.get("head") or {}
    user = pull.get("user") or {}
    return {
        "repo_url": repo.get("clone_url") or repo.get("html_url") or "",
        "repo_name": repo.get("full_name") or repo.get("name") or "",
        "commit": (head.get("sha") or "")[:40] or None,
        "branch": head.get("ref") or "main",
        "author": user.get("login") or user.get("name"),
        "message": pull.get("title"),
        "pr_number": pull.get("number"),
        "action": payload.get("action"),
    }


def parse_push_event(payload: dict) -> dict:
    repo = payload.get("repository") or {}
    head = payload.get("head_commit") or {}
    ref = payload.get("ref") or ""
    branch = ref.split("/")[-1] if ref.startswith("refs/heads/") else ref
    return {
        "repo_url": repo.get("clone_url") or repo.get("html_url") or "",
        "repo_name": repo.get("full_name") or repo.get("name") or "",
        "commit": (head.get("id") or payload.get("after") or "")[:40] or None,
        "branch": branch or "main",
        "author": (head.get("author") or {}).get("name") or (payload.get("pusher") or {}).get("name"),
        "message": head.get("message"),
    }
