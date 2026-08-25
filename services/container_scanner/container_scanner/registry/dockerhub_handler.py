"""Docker Hub webhook payloads."""

from __future__ import annotations

from typing import Any

from container_scanner.registry.registry_webhook_handler import parse_registry_event


def parse_dockerhub_event(payload: dict[str, Any] | None) -> dict[str, Any]:
    body = dict(payload or {})
    repository = body.get("repository") if isinstance(body.get("repository"), dict) else {}
    push = body.get("push_data") if isinstance(body.get("push_data"), dict) else {}
    if repository.get("repo_name"):
        body["image"] = repository.get("repo_name")
    if push.get("tag"):
        body["tag"] = push.get("tag")
    event = parse_registry_event(body, source="dockerhub")
    event["registry"] = "dockerhub"
    event["pusher"] = push.get("pusher")
    return event
