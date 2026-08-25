"""AWS ECR EventBridge / SNS image-push payloads."""

from __future__ import annotations

from typing import Any

from container_scanner.registry.registry_webhook_handler import parse_registry_event


def parse_ecr_event(payload: dict[str, Any] | None) -> dict[str, Any]:
    body = dict(payload or {})
    detail = body.get("detail") if isinstance(body.get("detail"), dict) else {}
    if detail and not body.get("image"):
        repo = detail.get("repository-name") or detail.get("repositoryName")
        tag = detail.get("image-tag") or detail.get("imageTag")
        account = detail.get("repository-account") or body.get("account")
        region = body.get("region") or detail.get("region")
        if repo and account and region:
            body["image"] = f"{account}.dkr.ecr.{region}.amazonaws.com/{repo}"
        elif repo:
            body["image"] = repo
        if tag:
            body["tag"] = tag
    event = parse_registry_event(body, source="ecr")
    event["registry"] = "ecr"
    return event
